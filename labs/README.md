# Лаборатории hackbook

Практическая часть книги: изолированные контейнеры с **намеренно уязвимыми**
приложениями. Каждая лаба привязана к главе книги и к карточкам payload'ов.

!!! danger "Правила" * Поднимайте лаборатории только на своей машине / в своей виртуальной сети. * Порты опубликованы исключительно на `127.0.0.1` — не меняйте это. * Не направляйте инструменты из лабораторий на внешние системы. * Данные в контейнерах учебные; не загружайте туда реальные сведения.

## Быстрый старт

```bash
cd labs/setup

docker compose up -d                 # веб-лабы (sqli + xss)
docker compose up -d --profile network   # + сетевые сервисы (redis, ldap, ftp)

docker compose ps
docker compose logs -f sqli-lab
docker compose down                  # остановить
docker compose down -v               # остановить и удалить данные
```

| Лаба                 | URL                   | Что изучаем                                                               | Глава   |
| -------------------- | --------------------- | ------------------------------------------------------------------------- | ------- |
| `sqli-lab`           | http://localhost:8080 | SQL-инъекции: error/boolean/UNION, обход входа                            | 1       |
| `xss-lab`            | http://localhost:8081 | XSS: три контекста, blacklist-обход, stored                               | 1       |
| `upload-lab`         | http://localhost:8082 | Загрузка файлов: blacklist, MIME, полиглоты, XSS через имя                | 1       |
| `vuln-hub`           | http://localhost:8090 | 9 классов: SQLi, IDOR, XSS, SSRF, XXE, CMDi, LFI, JWT, 2FA (+ safe-ветки) | 1, 6, 7 |
| `redis-noauth`       | localhost:6379        | Сервисы без аутентификации, путь к RCE                                    | 2       |
| `openldap-anonymous` | localhost:1389        | Anonymous bind, перечисление каталога                                     | 2, 3    |
| `ftp-anonymous`      | localhost:2121        | Анонимный доступ, запись файлов                                           | 2       |

## Автоматические тесты payload'ов

```bash
# прогнать карточки, привязанные к лабе, против поднятого стенда
tools/payload-tester.sh --lab sqli-lab
tools/payload-tester.sh --lab xss-lab
tools/payload-tester.sh --lab upload-lab
tools/payload-tester.sh --lab vuln-hub
python3 labs/web-labs/vuln-hub/selftest.py   # контракт поведения стенда

# посмотреть, что будет проверено, без запросов
tools/payload-tester.sh --lab sqli-lab --list

# JSON-отчёт (прикладывается к артефактам CI)
tools/payload-tester.sh --lab sqli-lab --report reports/sqli.json
```

Скрипт **отказывается** работать с целями вне локальной лаборатории: разрешены
`localhost`, `127.0.0.1`, `::1`, `*.local`, `*.lab.local`. Чтобы явно разрешить
другой адрес (например, Docker-сеть на отдельном хосте), экспортируйте
`HACKBOOK_ALLOWED_TARGETS=10.10.10.5,lab.local`.

## Как устроена веб-лаба

Оба приложения написаны на **стандартной библиотеке Python** (http.server + sqlite3):
образ собирается без сети и без pip, запуск занимает секунды.

```
web-labs/<имя>-lab/
├── app.py        # намеренно уязвимое приложение (маркеры "УЯЗВИМО" в коде)
├── Dockerfile    # python:3.12-alpine, non-root, healthcheck
├── tests.yaml    # точки входа и маркеры успеха для payload-tester
└── README.md     # задания
```

Лаборатории: `sqli-lab` (SQL-инъекции, SQLite), `xss-lab` (три контекста вывода,
stored XSS, CSP), `upload-lab` (загрузка файлов: blacklist, MIME, полиглоты,
имена файлов).

В коде уязвимые места помечены комментарием `# УЯЗВИМО:` — рядом всегда лежит
безопасная версия (`/item_safe`, `/search_safe`, `/login_safe`). Это сделано
специально: задание «починить» проверяется сравнением двух эндпоинтов.

Контейнеры запускаются с `read_only: true`, `cap_drop: [ALL]` и
`no-new-privileges`: даже уязвимое приложение не должно давать доступ к хосту.

## Задания

- [sqli-lab](web-labs/sqli-lab/README.md) — 8 заданий от подтверждения инъекции
  до починки кода.
- [xss-lab](web-labs/xss-lab/README.md) — 5 заданий по контекстам вывода и CSP.
- [upload-lab](web-labs/upload-lab/README.md) — 7 заданий по загрузке файлов
  и сравнению с безопасной реализацией.
- [vuln-hub](web-labs/vuln-hub/README.md) — 11 сквозных заданий «эксплуатируй →
  задетектируй → почини» и регрессионный контракт `selftest.py` (30 проверок).
- [network-labs](network-labs/README.md) — разведка сетевых сервисов без
  аутентификации и их hardening.

## Добавление своей лаборатории

1. Создайте каталог `labs/<категория>/<имя>-lab/`.
2. Добавьте `app.py` (или Dockerfile с нужным образом), `Dockerfile`,
   `tests.yaml` и `README.md` с заданиями.
3. Подключите сервис в `labs/setup/docker-compose.yml`:
   порт только на `127.0.0.1`, `cap_drop: [ALL]`, `read_only`, non-root.
4. Убедитесь, что `tools/payload-tester.sh --lab <имя>` находит `tests.yaml`.
5. Свяжите лабу с карточками payload'ов через поле `lab:` в front-matter —
   граф знаний подхватит связь автоматически.

Требования к безопасности самой лабы — в `docs/STYLE-GUIDE.md` (раздел «Лаборатории»).
