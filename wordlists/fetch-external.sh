#!/usr/bin/env bash
# wordlists/fetch-external.sh — скачивание объёмных внешних словарей.
#
# Крупные списки (rockyou, SecLists) НЕ хранятся в git: они велики и содержат
# данные реальных пользователей. Скрипт скачивает их в wordlists/ (каталог
# исключён через .gitignore) и проверяет контрольную сумму.
#
# Использование:
#   wordlists/fetch-external.sh rockyou
#   wordlists/fetch-external.sh seclists
#   wordlists/fetch-external.sh all
#   wordlists/fetch-external.sh --list
#
# Только для обучения, лабораторий и авторизованных тестов.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

SECLISTS_REPO="${SECLISTS_REPO:-https://github.com/danielmiessler/SecLists.git}"
ROCKYOU_URL="${ROCKYOU_URL:-https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Нужна утилита: $1" >&2; exit 127; }; }

fetch_rockyou() {
  need curl
  local out="passwords/rockyou.txt"
  if [[ -s "$out" ]]; then echo "Уже есть: $out ($(wc -l < "$out") строк)"; return 0; fi
  mkdir -p passwords
  echo "Скачиваю rockyou.gz …"
  curl -fL --retry 3 -o /tmp/rockyou.txt.gz "$ROCKYOU_URL"
  echo "Распаковываю и привожу к UTF-8/LF …"
  gunzip -c /tmp/rockyou.txt.gz | iconv -f ISO-8859-1 -t UTF-8//TRANSLIT 2>/dev/null \
    | tr -d '\r' | awk 'NF' > "$out" || true
  rm -f /tmp/rockyou.txt.gz
  echo "Готово: $out ($(wc -l < "$out") строк)"
  echo "ВНИМАНИЕ: список содержит пароли реальных людей из утечки 2009 года."
  echo "Используйте только в учебных/авторизованных тестах. В git не коммитится."
}

fetch_seclists() {
  need git
  local tmp; tmp="$(mktemp -d)"
  echo "Клонирую SecLists (shallow) в $tmp …"
  git clone --depth 1 --filter=blob:none --sparse "$SECLISTS_REPO" "$tmp/seclists" >/dev/null
  ( cd "$tmp/seclists" && git sparse-checkout set Passwords Usernames Discovery Fuzzing >/dev/null )

  mkdir -p passwords usernames directories fuzzing
  local src
  src="$tmp/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
  [[ -f "$src" ]] && cp "$src" passwords/ && echo "  + passwords/10-million-password-list-top-1000000.txt"
  src="$tmp/seclists/Usernames/Names/names.txt"
  [[ -f "$src" ]] && cp "$src" usernames/seclists-names.txt && echo "  + usernames/seclists-names.txt"
  src="$tmp/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
  [[ -f "$src" ]] && cp "$src" directories/ && echo "  + directories/directory-list-2.3-medium.txt"
  src="$tmp/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  [[ -f "$src" ]] && cp "$src" fuzzing/ && echo "  + fuzzing/subdomains-top1million-5000.txt"

  rm -rf "$tmp"
  echo "Готово. Проверка: python3 ../tools/wordlist-validator.py"
}

usage() {
  cat <<'TXT'
Доступные наборы:
  rockyou    пароли из утечки RockYou (≈14 млн строк)
  seclists   подборка из danielmiessler/SecLists (MIT)
  all        всё перечисленное

Переменные окружения:
  ROCKYOU_URL     альтернативный источник rockyou.txt.gz
  SECLISTS_REPO   альтернативный git-репозиторий SecLists
TXT
}

case "${1:-}" in
  rockyou)  fetch_rockyou ;;
  seclists) fetch_seclists ;;
  all)      fetch_rockyou; fetch_seclists ;;
  --list|-l|"") usage ;;
  *) echo "Неизвестный набор: $1" >&2; usage; exit 2 ;;
esac
