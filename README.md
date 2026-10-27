# 🔐 hackbook

**Учебник + база payload'ов + словари + лаборатории по практической кибербезопасности в одном репозитории.** Всё связано между собой: глава ссылается на карточки атак, карточка — на лабораторию, где её можно воспроизвести, а граф знаний показывает, куда ведёт каждая техника.

Единый источник контента — Markdown с YAML-метаданными. Из него автоматически собираются **HTML-сайт, PDF, EPUB и интерактивный граф**. Никаких ручных копий.

> ⚠️ **Ответственное использование.** Материалы предназначены для обучения, лабораторий этого репозитория, CTF и систем, на тестирование которых у вас есть **письменное разрешение** владельца. Атака на чужие системы без разрешения — преступление. У каждой карточки есть секции `Detection` и `Remediation`: половина профессии защитника живёт именно там.

**Сайт книги:** [https://marymur-975.github.io/hackbook/](https://marymur-975.github.io/hackbook/)

---

## Что внутри

| Раздел                         | Что внутри                                                       |
| ------------------------------ | ---------------------------------------------------------------- |
| 📚 `book/src/`                 | **23 главы** (12 основных + 11 подглав) в Markdown + YAML        |
| 🎯 `payloads/`                 | **180 карточек** атак (SQLi, XSS, SSRF, Cloud, AD, Mobile и др.) |
| 🕸️ `payloads/graph/index.html` | интерактивный граф знаний (**252 узла, 601 связь**)              |
| 📝 `wordlists/`                | 11+ словарей + `metadata.yaml` и `external-manifest.yaml`        |
| 🔬 `labs/`                     | docker-compose лаборатории (SQLi, XSS, Upload, Vuln-Hub)         |
| 🛠️ `tools/`                    | сборка PDF/EPUB, генерация графа, валидаторы                     |
| 📖 `docs/`                     | CONTRIBUTING, STYLE-GUIDE, ROADMAP, SECURITY                     |
| ⚙️ `.github/workflows/`        | CI: автоматическая сборка и деплой на GitHub Pages               |

### Payload'ы по типам (топ)

| Тип           | Кол-во | Тип               | Кол-во |
| ------------- | -----: | ----------------- | -----: |
| `sqli`        |     22 | `cloud`           |     18 |
| `xss`         |     10 | `ad`              |     10 |
| `auth-bypass` |      9 | `deserialization` |     10 |
| `lfi`         |      6 | `ssrf`            |      6 |
| `xxe`         |      6 | `cmdi`            |      5 |

По сложности: 29 beginner · 69 intermediate · 47 advanced · 4 expert.

---

## Быстрый старт (локально)

```bash
pip install -r requirements.txt

# 1. Сгенерировать граф знаний
python tools/graph-generator.py --pretty

# 2. Собрать дерево для MkDocs (копирует главы и карточки)
python tools/mkdocs-site.py --clean

# 3. Запустить локальный сайт
mkdocs serve --config-file book/mkdocs.yml

# 4. (Опционально) Собрать PDF и EPUB
python tools/pdf-builder.py --format all
```

Или просто запусти `build.bat` (Windows) — он сделает всё сразу.

### Лаборатории (Docker)

```bash
cd labs/setup
docker compose up -d                       # SQLi + XSS + Upload
docker compose up -d --profile network     # + redis, ldap, ftp
```

---

## Визуал и интерактив

- **Киберпанк-стиль** (неоновая сетка, свечение, шрифты Inter / JetBrains Mono).
- **Чек-боксы прогресса** — отмечай изученные главы, галочки сохраняются в браузере.
- **Интерактивный граф** — фильтры по типу, категории, сложности и связям.

---

## Технологии

- **MkDocs + Material for MkDocs** — генерация сайта.
- **D3.js v7** — интерактивный граф знаний.
- **Python 3.10+** — сборка (PDF, EPUB, граф).
- **GitHub Actions** — CI/CD и деплой на GitHub Pages.

## Лицензия

- Код и инструментарий — [MIT](LICENSE).
- Текст книги и карточки payload'ов — [CC BY-SA 4.0](LICENSE-content).

```

```
