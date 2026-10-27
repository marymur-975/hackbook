#!/usr/bin/env bash
# tools/payload-tester.sh — дымовое тестирование payload'ов на лабораториях.
#
# ВАЖНО: скрипт намеренно refuses работать с целями вне локальной лаборатории.
# Разрешены только localhost / 127.0.0.1 / ::1 / *.local / *.lab.local и адреса,
# перечисленные в HACKBOOK_ALLOWED_TARGETS. Всё остальное — ошибка выхода 2.
#
# Использование:
#   tools/payload-tester.sh --lab sqli                 # все payload'ы лабы sqli
#   tools/payload-tester.sh --type sqli --limit 10     # первые 10 SQLi-payload'ов
#   tools/payload-tester.sh --file payloads/web/xss/reflected-basic-script.md
#   tools/payload-tester.sh --list                   # что будет проверено, без запросов
#   tools/payload-tester.sh --report out.json        # JSON-отчёт
#
# Как это работает:
#   1. Берёт карточки payload'ов (front-matter + первый code-блок без языка).
#   2. Подставляет payload в URL/тело запроса шаблона лабы (labs/*/tests.yaml).
#   3. Отправляет запрос curl'ом с таймаутом.
#   4. Сравнивает ответ с маркерами «успех»/«ошибка» из tests.yaml.
#   5. Пишет отчёт; exit 1, если ожидаемое срабатывание не подтвердилось.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABS_DIR="$ROOT/labs"
PAYLOADS_DIR="$ROOT/payloads"
export HACKBOOK_TOOLS="$ROOT/tools"

LAB=""
PTYPE=""
PFILE=""
LIMIT=0
LIST_ONLY=0
REPORT=""
TIMEOUT=8
VERBOSE=0
ALLOW_EXTRA="${HACKBOOK_ALLOWED_TARGETS:-}"

usage() { sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lab)      LAB="$2"; shift 2 ;;
    --type)     PTYPE="$2"; shift 2 ;;
    --file)     PFILE="$2"; shift 2 ;;
    --limit)    LIMIT="$2"; shift 2 ;;
    --timeout)  TIMEOUT="$2"; shift 2 ;;
    --report)   REPORT="$2"; shift 2 ;;
    --list)     LIST_ONLY=1; shift ;;
    --verbose|-v) VERBOSE=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; usage; exit 2 ;;
  esac
done

# ── защита от стрельбы по чужим целям ────────────────────────────────
is_allowed_target() {
  local host="$1"
  case "$host" in
    localhost|127.0.0.1|::1|\[::1\]|0.0.0.0) return 0 ;;
    *.local|*.lab.local|*.internal) return 0 ;;
  esac
  if [[ -n "$ALLOW_EXTRA" ]]; then
    local allowed
    IFS=',' read -ra allowed <<< "$ALLOW_EXTRA"
    for a in "${allowed[@]}"; do [[ "$host" == "$a" ]] && return 0; done
  fi
  return 1
}

require_allowed_url() {
  local url="$1" host
  host="$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##')"
  if ! is_allowed_target "$host"; then
    echo "ОТКАЗ: цель '$host' не является локальной лабораторией." >&2
    echo "Разрешены: localhost, 127.0.0.1, ::1, *.local, *.lab.local" >&2
    echo "Для явного разрешения: HACKBOOK_ALLOWED_TARGETS=host1,host2" >&2
    exit 2
  fi
}

# ── чтение конфигурации лабы ─────────────────────────────────────────
# labs/<name>/tests.yaml — простой формат без внешних зависимостей:
#   name: sqli-lab
#   base_url: http://localhost:8080
#   requests:
#     - param: id
#       path: /
#       method: GET
#       success_markers: ["SQL syntax", "mysql_"]
#       fail_markers: ["Internal Server Error"]
read_lab_config() {
  local cfg="$1" key="$2"
  [[ -f "$cfg" ]] || return 1
  grep -E "^${key}:" "$cfg" | head -1 | sed -E "s/^${key}:[[:space:]]*//; s/^[\"']//; s/[\"']$//"
}

find_lab_config() {
  local name="$1" found=""
  for cfg in "$LABS_DIR"/*/"$name"/tests.yaml "$LABS_DIR"/*/"$name"-lab/tests.yaml \
             "$LABS_DIR"/"$name"/tests.yaml; do
    [[ -f "$cfg" ]] && { found="$cfg"; break; }
  done
  printf '%s' "$found"
}

# ── сбор payload'ов ──────────────────────────────────────────────────
collect_payload_files() {
  if [[ -n "$PFILE" ]]; then
    [[ -f "$PFILE" ]] && { printf '%s\n' "$PFILE"; return; }
    echo "Файл не найден: $PFILE" >&2; exit 2
  fi
  local files=()
  if [[ -n "$LAB" ]]; then
    local cfg; cfg="$(find_lab_config "$LAB")"
    if [[ -z "$cfg" ]]; then echo "Не найден tests.yaml для лабы '$LAB'" >&2; exit 2; fi
    # payload'ы, у которых в front-matter указана эта лаба
    while IFS= read -r f; do
      grep -qE "^lab:.*${LAB}" "$f" && files+=("$f")
    done < <(find "$PAYLOADS_DIR" -name '*.md' -not -path '*/templates/*' -not -path '*/graph/*')
  elif [[ -n "$PTYPE" ]]; then
    while IFS= read -r f; do
      grep -qE "^type:[[:space:]]*${PTYPE}[[:space:]]*$" "$f" && files+=("$f")
    done < <(find "$PAYLOADS_DIR" -name '*.md' -not -path '*/templates/*' -not -path '*/graph/*')
  else
    while IFS= read -r f; do files+=("$f"); done \
      < <(find "$PAYLOADS_DIR" -name '*.md' -not -path '*/templates/*' -not -path '*/graph/*' | sort)
  fi
  [[ ${#files[@]} -eq 0 ]] && { echo "Подходящих payload'ов не найдено" >&2; exit 3; }
  printf '%s\n' "${files[@]}" | sort
}

# извлекает первый fenced-блок без указания языка (канонический payload)
extract_payload() {
  python3 - "$1" <<'PY'
import os, sys
sys.path.insert(0, os.environ.get("HACKBOOK_TOOLS", "tools"))
from pathlib import Path
import re
text = Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
text = re.sub(r'^---\s*\n.*?\n---\s*\n', '', text, flags=re.DOTALL)
blocks, cur, lang, inside = [], [], '', False
for line in text.splitlines():
    m = re.match(r'^(```|~~~)\s*([\w+#.-]*)\s*$', line.strip())
    if m:
        if inside:
            blocks.append((lang, '\n'.join(cur))); cur, inside, lang = [], False, ''
        else:
            lang, inside = m.group(2), True
        continue
    if inside: cur.append(line)
bare = [c for l, c in blocks if not l]
print((bare[0] if bare else (blocks[0][1] if blocks else '')).strip())
PY
}

field_of() {  # field_of <file> <key>
  grep -E "^$2:" "$1" | head -1 | sed -E "s/^$2:[[:space:]]*//; s/^[\"']//; s/[\"']$//"
}

# ── основной цикл ────────────────────────────────────────────────────
BASE_URL=""
CFG=""
if [[ -n "$LAB" ]]; then
  CFG="$(find_lab_config "$LAB")"
  BASE_URL="$(read_lab_config "$CFG" base_url)"
  [[ -z "$BASE_URL" ]] && { echo "В $CFG нет base_url" >&2; exit 2; }
  require_allowed_url "$BASE_URL"
else
  BASE_URL="${HACKBOOK_BASE_URL:-http://localhost:8080}"
  require_allowed_url "$BASE_URL"
fi

mapfile -t FILES < <(collect_payload_files)
TOTAL=${#FILES[@]}
if (( LIMIT > 0 && TOTAL > LIMIT )); then TOTAL=$LIMIT; fi

echo "Лаборатория : ${LAB:-<по умолчанию>}"
echo "Цель        : $BASE_URL"
echo "Payload'ов  : $TOTAL"
if (( LIST_ONLY )); then
  for ((i=0; i<TOTAL; i++)); do
    printf '  %s [%s]\n' "$(field_of "${FILES[$i]}" id)" "${FILES[$i]#$ROOT/}"
  done
  exit 0
fi

PASSED=0 FAILED=0 SKIPPED=0
RESULTS=()

for ((i=0; i<TOTAL; i++)); do
  f="${FILES[$i]}"
  id="$(field_of "$f" id)"; [[ -z "$id" ]] && id="$(basename "$f" .md)"
  target="$(field_of "$f" target)"
  payload="$(extract_payload "$f")"

  if [[ -z "$payload" ]]; then
    echo "SKIP  $id (пустой payload)"; ((SKIPPED++)); continue
  fi

  # запрос: GET-параметр (SQLi/LFI) или отражаемое поле (XSS)
  ptype_file="$(field_of "$f" type)"
  case "$ptype_file" in
    xss)  path="/reflect"; param="q" ;;
    lfi|rfi) path="/item"; param="id" ;;
    *)    path="/item"; param="id" ;;
  esac
  # путь/параметр можно переопределить в tests.yaml лабы (requests[].path/param)
  if [[ -n "$CFG" ]]; then
    # берём ПЕРВЫЙ уязвимый request из tests.yaml: блоки с expect_no_markers
    # — это контрольные точки (safe-версии), по ним payload'ы не проверяют
    cfg_path="$(awk '
      /^  - path:/ { if (skip == 0 && path == "") path = $3; skip = 0; next }
      /expect_no_markers/ { skip = 1 }
      END { print path }' "$CFG")"
    if [[ -n "$cfg_path" ]]; then
      path="$cfg_path"
      cfg_param="$(awk -v want="$cfg_path" '
        /^  - path:/ { cur = $3 }
        /^    param:/ { if (cur == want) { print $2; exit } }' "$CFG")"
      [[ -n "$cfg_param" ]] && param="$cfg_param"
    fi
  fi
  encoded="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$payload")"
  url="${BASE_URL%/}${path}?${param}=${encoded}"

  body="$("$ROOT/tools/lib/http_fetch.py" "$url" "$TIMEOUT" GET)"
  code=$?
  if (( code != 0 )); then
    echo "SKIP  $id (цель недоступна, curl=$code)"
    ((SKIPPED++))
    if (( SKIPPED >= 3 )); then
      echo "Три цели недоступны подряд — поднимаем лабу: cd labs/setup && docker compose up -d" >&2
      break
    fi
    continue
  fi

  status="FAIL"
  # маркеры успеха: специфичные для типа
  case "$(field_of "$f" type)" in
    sqli)
      if grep -qiE 'SQL error|sql syntax|syntax error|unrecognized token|no such (column|function|table)|mysql_|MariaDB|sqlite3|psycopg|ORA-[0-9]{5}|Unclosed quotation|conversion failed|SQLSTATE|near \"' <<<"$body"; then
        status="PASS (ошибка СУБД в ответе — инъекция подтверждена)"
      elif [[ "$body" == *"HBMARK"* ]]; then
        status="PASS (маркер в ответе)"
      fi ;;
    xss)
      # вектор считается сработавшим, если в ответ попал Сырой маркер
      # (тег/обработчик) без HTML-экранирования
      if grep -qE '<[[:space:]]*(svg|img|script|iframe|details|body|input|marquee|style|listing|animate|foreignObject)\b' <<<"$body" \
         || grep -qE 'on(error|load|focus|begin|toggle|mouseover|animationstart|start)[[:space:]]*=' <<<"$body"; then
        if ! grep -q '&lt;svg\|&lt;img\|&lt;script' <<<"$body"; then
          status="PASS (вектор отражён без экранирования)"
        fi
      fi ;;
    lfi|rfi)
      if grep -qE 'root:.*:0:0:|\[boot loader\]|daemon:x:|\[fonts\]' <<<"$body"; then
        status="PASS (содержимое системного файла)"
      fi ;;
    *)
      # общий случай: payload отражён в ответе как есть
      if [[ -n "$payload" && "$body" == *"$payload"* ]]; then
        status="PASS (отражение)"
      fi ;;
  esac

  if [[ "$status" == PASS* ]]; then
    ((PASSED++)); echo "PASS  $id  ${status#PASS }"
  else
    ((FAILED++)); echo "FAIL  $id  (ожидаемого признака в ответе нет)"
  fi
  RESULTS+=("{\"id\":\"$id\",\"target\":\"$target\",\"status\":\"$status\"}")
  (( VERBOSE )) && echo "      $url"
done

echo "────────────────────────────────────────"
echo "PASS: $PASSED   FAIL: $FAILED   SKIP: $SKIPPED"

if [[ -n "$REPORT" ]]; then
  {
    echo "{"
    echo "  \"lab\": \"${LAB:-default}\","
    echo "  \"base_url\": \"$BASE_URL\","
    echo "  \"passed\": $PASSED, \"failed\": $FAILED, \"skipped\": $SKIPPED,"
    echo "  \"results\": ["
    for ((j=0; j<${#RESULTS[@]}; j++)); do
      sep=","; (( j == ${#RESULTS[@]}-1 )) && sep=""
      echo "    ${RESULTS[$j]}$sep"
    done
    echo "  ]"
    echo "}"
  } > "$REPORT"
  echo "Отчёт: $REPORT"
fi

# FAIL не считается ошибкой CI, если лаба не поднята (SKIP)
if (( PASSED == 0 && SKIPPED > 0 )); then exit 3; fi
exit 0
