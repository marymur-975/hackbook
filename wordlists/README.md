# Словари hackbook

Наборы для перебора, фаззинга и перечисления. Все списки в репозитории —
**учебные компиляции**, они не содержат персональных данных и не являются
дампами утечек.

```
wordlists/
├── usernames/       имена пользователей (типовые, административные, сервисные,
│                    русскоязычные: russian-names.txt)
├── passwords/       частотные пароли, секреты JWT, сервисные учётки,
│                    русскоязычные (russian-corporate.txt, keyboard-ru.txt)
├── directories/     пути веб-приложений, «чувствительные» файлы,
│                    пути по фреймворкам (frameworks.txt)
├── fuzzing/         параметры (в т.ч. parameters-frameworks.txt), SSRF-цели,
│                    SNMP community, поддомены, сигнатуры для детект-правил
│                    (detection-signatures.txt)
├── metadata.yaml    описание каждого списка (проверяется в CI)
├── external-manifest.yaml  манифест внешних наборов: URL, лицензия, sha256
└── fetch-external.sh       скачивание объёмных внешних наборов (rockyou, SecLists)
```

Всего словарей в репозитории: **17** (~11.8 тыс. строк). Крупные наборы
(утечки, SecLists целиком) лежат вне git и описаны в `external-manifest.yaml`.

## Быстрый старт

```bash
# проверка качества словарей (дубликаты, кодировка, метаданные)
python3 tools/wordlist-validator.py --strict

# поиск утечёкших секретов внутри списков
python3 tools/wordlist-validator.py --secrets

# объёмные внешние наборы (в git не попадают)
wordlists/fetch-external.sh --list
wordlists/fetch-external.sh rockyou

# внешние наборы по манифесту: загрузка, sha256-контроль, закрепление суммы
python3 tools/wordlist-manifest.py --list
python3 tools/wordlist-manifest.py --fetch jwt-secrets-wordlist
python3 tools/wordlist-manifest.py --check
python3 tools/wordlist-manifest.py --pin jwt-secrets-wordlist

# генерация целевого словаря из токенов организации
python3 tools/wordlist-builder.py --input tokens.txt --out passwords/target.txt \
  --rules capitalize,years,digits-3,sep-company
```

## Использование

```bash
# перебор каталогов
ffuf -u http://localhost:8080/FUZZ -w wordlists/directories/common.txt -mc 200,301,403

# поиск скрытых параметров
ffuf -u "http://localhost:8080/?FUZZ=1" -w wordlists/fuzzing/parameters.txt -fs 1234

# password spray (одна попытка на пользователя — без блокировок)
crackmapexec smb 10.10.10.5 -u wordlists/usernames/common.txt \
  -p wordlists/passwords/top-500.txt --no-bruteforce

# виртуальные хосты
ffuf -u http://localhost:8080/ -H 'Host: FUZZ.lab.local' \
  -w wordlists/fuzzing/subdomains.txt

# SNMP community
onesixtyone -c wordlists/fuzzing/snmp-communities.txt 10.10.10.0/24

# офлайн-подбор подписи JWT
hashcat -m 16500 token.txt wordlists/passwords/jwt-secrets.txt

# русскоязычная среда: перечисление и spray
ffuf -u http://localhost:8080/login -X POST \
  -d "login=FUZZ&password=x" -w wordlists/usernames/russian-names.txt -fc 401
hydra -L wordlists/usernames/russian-names.txt \
  -P wordlists/passwords/russian-corporate.txt -t 4 \
  ssh://127.0.0.1:2222        # только своя лабораторная ВМ!

# поиск путей конкретного стека
ffuf -u http://localhost:8080/FUZZ -w wordlists/directories/frameworks.txt -mc 200,401,403

# проверка детект-правил и WAF на сигнатурах
while IFS= read -r sig; do
  case "$sig" in \#*|"") continue ;; esac
  python3 tools/lib/http_fetch.py \
    "http://localhost:8090/items?id=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$sig")" 6 GET >/dev/null
done < wordlists/fuzzing/detection-signatures.txt
python3 tools/lib/http_fetch.py http://localhost:8090/logs   # что попало в журнал
python3 tools/rules-tester.py --verbose                       # правила на фикстурах
```

## Русскоязычные словари

Три списка учитывают специфику отечественных сред:

| Список                            | Что внутри                                                                                            | Зачем                                         |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `usernames/russian-names.txt`     | транслит имён/фамилий, схемы `имя.фамилия`, `и.фамилия`, `фамилияи`, сервисные и кириллические учётки | перечисление пользователей, password spraying |
| `passwords/russian-corporate.txt` | транслит русских слов и названий компаний + мутации (регистр, год 2019–2026, `!`, `_`, `-`)           | проверка парольной политики                   |
| `passwords/keyboard-ru.txt`       | ряды раскладок EN/RU, сетка `qaz/wsx`, русские слова в английской раскладке (`ghjkm`), цифры          | оценка «шаблонности» паролей                  |

Все три — **синтетические компиляции**: реальных утечек и персональных данных
не содержат. Это принципиально: словарь, собранный из дампа, юридически
и этически непригоден для распространения.

## Сигнатуры для детектирования

`fuzzing/detection-signatures.txt` — обратная сторона словарей: не для атаки,
а для **проверки защиты**. Строки сгруппированы по классам (`# --- sqli ---`,
`# --- xss ---`, …) и предназначены для того, чтобы:

1. прогнать их через лабораторию (`labs/web-labs/vuln-hub`);
2. собрать логи (`GET /logs`);
3. проверить, что правила из `detections/` срабатывают
   (`python3 tools/rules-tester.py`), а WAF/фильтры — блокируют.

Так словарь становится тестом для системы защиты, а не только для атаки.

## Правила для новых списков

1. **Формат**: UTF-8, LF, без BOM, без пустых строк, без дубликатов,
   без пробелов по краям. Проверяется автоматически.
2. **Метаданные**: каждый файл обязан быть описан в `metadata.yaml`
   (поля `name`, `path`, `size`, `use_cases`, `source`, `license`, `last_updated`).
3. **Происхождение**: указывайте источник. Списки без источника в репозиторий
   не принимаются — их невозможно поддерживать и обновлять.
4. **Никаких секретов**: строки, похожие на реальные API-ключи, приватные ключи,
   JWT и connection strings, отклоняются валидатором (`--secrets`).
5. **Никаких персональных данных**: реальные утечки (rockyou и подобные)
   скачиваются через `fetch-external.sh` и не коммитятся.
6. **Размер**: до 5 млн строк и 200 МБ на файл (лимиты в `metadata.yaml`).
   Больше — выносите во внешние наборы.
7. **Обновление**: при изменении файла обновляйте `last_updated` и `size`,
   иначе CI выдаст предупреждение.

## Почему `top-500.txt`, а не `top-1000.txt`

В репозитории лежит curated-список на ~490 строк: он покрывает большинство
дефолтов и «человеческих» паролей, при этом его можно поддерживать вручную
и гарантировать отсутствие мусора. Большие списки подключаются отдельно —
см. секцию `external:` в `metadata.yaml`.
