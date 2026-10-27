# 🔐 hackbook

**Учебник + база payload'ов + словари + лаборатории по практической кибербезопасности
в одном репозитории.** Всё связано между собой: глава ссылается на карточки атак,
карточка — на лабораторию, где её можно воспроизвести, а граф знаний показывает,
куда ведёт каждая техника.

Единый источник контента — Markdown с YAML-метаданными. Из него автоматически
собираются **HTML-сайт, PDF, EPUB и интерактивный граф**. Никаких ручных копий.

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────────┐
│  book/src/*.md  │    │ payloads/**/*.md │    │ wordlists/metadata.yaml│
│  главы + meta   │    │ карточки атак    │    │ словари + описание     │
└────────┬────────┘    └────────┬─────────┘    └───────────┬────────────┘
         │                      │                          │
         └──────────┬───────────┴──────────────────────────┘
                    │  tools/graph-generator.py · tools/pdf-builder.py
        ┌───────────┴────────────┬─────────────────────┬──────────────┐
        ▼                        ▼                     ▼              ▼
   сайт (MkDocs)         graph.json + graph.html   hackbook.pdf   hackbook.epub
```

> ⚠️ **Ответственное использование.** Материалы предназначены для обучения,
> лабораторий этого репозитория, CTF и систем, на тестирование которых у вас есть
> **письменное разрешение** владельца. Атака на чужие системы без разрешения —
> преступление. У каждой карточки есть секции `Detection` и `Remediation`:
> половина профессии защитника живёт именно там.

---

## Содержание репозитория

| Раздел | Что внутри |
|--------|-----------|
| 📚 [`book/src/`](book/src/) | 6 глав учебника (Markdown + `meta.yaml`) |
| 🎯 [`payloads/`](payloads/) | 84 карточки атак в едином формате |
| 🕸️ [`payloads/graph/index.html`](payloads/graph/index.html) | интерактивный граф знаний (129 узлов, 283 связи) |
| 📝 [`wordlists/`](wordlists/) | 11 словарей + `metadata.yaml` с описанием каждого |
| 🔬 [`labs/`](labs/) | docker-compose лаборатории (SQLi, XSS, сетевые сервисы) |
| 🛠️ [`tools/`](tools/) | сборка PDF/EPUB, генерация графа, валидаторы, тестер |
| 📖 [`docs/`](docs/) | CONTRIBUTING, STYLE-GUIDE, ROADMAP, SECURITY |
| ⚙️ [`.github/workflows/`](.github/workflows/) | CI: сборка, валидация контента, смоук-тесты лаб, деплой |

### Payload'ы по типам

| Тип | Кол-во | Тип | Кол-во |
|-----|-------:|-----|-------:|
| `sqli` | 22 | `xxe` | 6 |
| `xss` | 10 | `cmdi` | 5 |
| `cloud` | 7 | `header` | 5 |
| `network` | 7 | `ssti` | 4 |
| `auth-bypass` | 6 | `lfi` | 6 |
| `ssrf` | 6 | | |

По сложности: 23 beginner · 39 intermediate · 21 advanced · 1 expert.

---

## Быстрый старт

### Практика (лаборатории)

```bash
cd labs/setup
docker compose up -d                       # SQLi + XSS лабы на 127.0.0.1:8080/8081
docker compose up -d --profile network     # + redis, ldap, ftp без аутентификации

# открыть в браузере
#   http://localhost:8080   — SQLi: /item?id=, /search?q=, /login
#   http://localhost:8081   — XSS: /reflect?q=, /attribute?v=, /guestbook
```

Проверить, что карточки payload'ов реально работают на лабе:

```bash
tools/payload-tester.sh --lab sqli-lab      # 7/7 PASS на «сломанной» лабе
tools/payload-tester.sh --lab xss-lab       # 4/4 PASS
tools/payload-tester.sh --lab sqli-lab --list   # что будет проверено
```

Скрипт **отказывается** работать с целями вне локальной лаборатории
(`localhost`, `127.0.0.1`, `*.local`) — это защита от случайного выстрела
по чужой инфраструктуре.

### Чтение

```bash
pip install -r requirements.txt

# сайт книги
python tools/mkdocs-site.py --clean        # book/src -> book/docs
mkdocs serve --config-file book/mkdocs.yml

# единый HTML + PDF + EPUB (без зависимостей, кроме шрифтов)
python tools/pdf-builder.py --format all
# -> book/build/hackbook.{html,pdf,epub}

# граф знаний
python tools/graph-generator.py --pretty
xdg-open payloads/graph/index.html
```

Инструменты работают на «чистом» Python 3.10+: парсер Markdown/YAML, конвертер
в HTML, генератор EPUB и PDF-fallback написаны без внешних библиотек.
WeasyPrint и PyYAML используются, если установлены.

---

## Формат контента

### Карточка payload'а

```markdown
---
id: sqli-mysql-tautology-auth-bypass
title: "MySQL: обход аутентификации тавтологией"
type: sqli            # sqli | xss | ssrf | lfi | xxe | cmdi | ssti | auth-bypass | header | network | cloud
target: mysql
difficulty: beginner  # beginner | intermediate | advanced | expert
bypass: none          # none | waf | filter | encoding | auth
risk: low
cwe: "CWE-89"
tested_on: ["MySQL 8.0", "SQLite 3.40 (sqli-lab)"]
success_rate: 0.9
lab: "labs/web-labs/sqli-lab"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
graph:
  - target: auth-bypass
    type: leads_to
    description: "SQLi в форме логина даёт обход аутентификации"
---

# MySQL: обход аутентификации тавтологией

## Payload      <- первый code-блок без языка = каноническая нагрузка
## Explanation  <- почему работает
## Detection    <- как найти (признаки в ответе и логах)
## Remediation  <- как чинить
```

Шаблон: [`payloads/templates/payload-template.md`](payloads/templates/payload-template.md).
Формат проверяется в CI (`tools/validate-payloads.py --strict`).

### Глава книги

```markdown
---
title: "SQL Injection: Полное руководство"
chapter: 1
difficulty: intermediate
tags: [sqli, web, injection]
prerequisites: ["HTTP Basics", "SQL Fundamentals"]
related_payloads: ["payloads/web/sqli/mysql-tautology-auth-bypass.md"]
lab: "labs/web-labs/sqli-lab"
---

# SQL Injection

## Теория
...

## Payload'ы
{{ include "payloads/web/sqli/mysql-tautology-auth-bypass.md" }}
```

Директива `{{ include }}` раскрывается при сборке и одновременно создаёт связь
«глава → payload» в графе знаний.

---

## Граф знаний

`payloads/graph/index.html` — самодостаточный файл (данные встроены), работает
офлайн. Умеет:

* поиск по названию, тегам, CWE, пути;
* фильтры по типу узла (глава / техника / payload / лаба), категории, сложности;
* фильтры по типу связи (`leads_to`, `instance_of`, `covered_in`, …);
* две раскладки: force и radial-по-категориям;
* панель узла с метаданными, ссылками на файл и списком связей (кликабельно).

Рендер: D3 v7 с CDN; если CDN недоступен, автоматически включается встроенный
canvas-рендерер со своей force-симуляцией — то есть граф работает и без сети.

Граф **не правится руками**: он генерируется из метаданных Markdown.
CI проверяет, что закоммиченный `graph.json` не расходится с контентом.

---

## Инструменты

| Скрипт | Назначение | Зависимости |
|--------|-----------|-------------|
| [`tools/pdf-builder.py`](tools/pdf-builder.py) | HTML-бандл, PDF, EPUB из глав | stdlib (+WeasyPrint/fpdf2 для PDF) |
| [`tools/graph-generator.py`](tools/graph-generator.py) | Markdown → `graph.json` + интерактивная карта | stdlib |
| [`tools/mkdocs-site.py`](tools/mkdocs-site.py) | `book/src` → дерево `book/docs` для MkDocs | stdlib |
| [`tools/validate-payloads.py`](tools/validate-payloads.py) | формат карточек и глав, ссылки, рёбра графа | stdlib |
| [`tools/wordlist-validator.py`](tools/wordlist-validator.py) | кодировка, дубликаты, метаданные, поиск секретов | stdlib |
| [`tools/link-checker.py`](tools/link-checker.py) | битые ссылки и якоря (опц. внешние URL) | stdlib |
| [`tools/payload-tester.sh`](tools/payload-tester.sh) | дымовые тесты карточек на лабораториях | bash, python3 |
| [`tools/lib/`](tools/lib/) | общий парсер Markdown/YAML, конвертер в HTML, модель репозитория | stdlib |

Каждый скрипт имеет `--help` и режим `--check`/`--json` для CI.

---

## Проверки качества

```bash
python tools/validate-payloads.py --strict      # формат карточек и глав
python tools/wordlist-validator.py --secrets --strict
python tools/link-checker.py                    # битые ссылки
python tools/graph-generator.py --check         # целостность графа
tools/payload-tester.sh --lab sqli-lab          # payload'ы против лабы
```

Все проверки продублированы в GitHub Actions:
[`validate-payloads.yml`](.github/workflows/validate-payloads.yml) (контент),
[`build-pdf.yml`](.github/workflows/build-pdf.yml) (сборка книг и сайта),
[`lab-tests.yml`](.github/workflows/lab-tests.yml) (смоук-тесты лаб),
[`deploy-graph.yml`](.github/workflows/deploy-graph.yml) (публикация на Pages).

---

## Структура каталогов

```
hackbook/
├── book/
│   ├── src/                     # главы (единственный источник контента)
│   │   ├── 00-introduction/     #   chapter.md + meta.yaml
│   │   ├── 01-web-security/
│   │   ├── 02-network/
│   │   ├── 03-active-directory/
│   │   ├── 04-cloud/
│   │   └── 05-privilege-escalation/
│   ├── assets/                  # стили, схемы
│   ├── theme/                   # переопределения темы Material
│   ├── docs/                    # генерируется tools/mkdocs-site.py (не править)
│   ├── build/                   # результат сборки (в .gitignore)
│   └── mkdocs.yml
├── payloads/
│   ├── web/{sqli,xss,ssrf,lfi-rfi,xxe,cmdi,ssti,auth-bypass,headers}/
│   ├── network/
│   ├── cloud/
│   ├── graph/                   # graph.json + index.html (генерируется)
│   └── templates/               # шаблоны карточек
├── wordlists/
│   ├── usernames/ passwords/ directories/ fuzzing/
│   ├── metadata.yaml
│   └── fetch-external.sh        # rockyou / SecLists (в git не хранятся)
├── labs/
│   ├── setup/docker-compose.yml # единая точка входа
│   ├── web-labs/{sqli-lab,xss-lab}/
│   ├── network-labs/
│   └── db-init/                 # LDIF для лабораторного каталога
├── tools/                       # скрипты сборки и валидации
├── docs/                        # CONTRIBUTING, ROADMAP, STYLE-GUIDE, SECURITY
└── .github/workflows/           # CI/CD
```

---

## Вклад в проект

Проще всего начать с карточки payload'а по технике, которую вы **реально
проверяли**:

```bash
cp payloads/templates/payload-template.md payloads/web/sqli/my-technique.md
# заполнить front-matter и четыре обязательные секции
python tools/validate-payloads.py --strict     # должно быть 0 ошибок
python tools/graph-generator.py --pretty       # обновить граф
```

Подробности — в [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md), правила
оформления — в [`docs/STYLE-GUIDE.md`](docs/STYLE-GUIDE.md).

## Дорожная карта

Текущая фаза — **Фаза 1 (фундамент)**: структура, 6 глав, 84 карточки, 11 словарей,
2 веб-лабораторы, граф знаний и полный CI. План и статус — в
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## Лицензия

* Код и инструментарий — [MIT](LICENSE).
* Текст книги и карточки payload'ов — [CC BY-SA 4.0](LICENSE-content)
  (copyleft: производные работы распространяются на тех же условиях с указанием
  авторства).

## Благодарности

Формат и подходы вдохновлены открытыми проектами: OWASP Testing Guide,
PortSwigger Web Security Academy, HackTricks, PayloadsAllTheThings, GTFOBins,
MITRE ATT&CK и Hack The Box Academy.
