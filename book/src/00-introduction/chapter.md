---
title: "Введение: как устроен hackbook"
chapter: 0
difficulty: beginner
category: general
tags: [введение, методология, структура, этика]
prerequisites: []
related_payloads: []
lab: null
---

# Введение: как устроен hackbook

**hackbook** — это учебник, база payload'ов, словарь и набор лабораторий в одном
репозитории. Всё связано между собой: глава ссылается на payload'ы, payload — на
лабораторию, где его можно воспроизвести, а граф знаний показывает, куда ведёт
каждая техника.

!!! danger "Правила использования"
    Материалы репозитория предназначены для:

    * учебных лабораторий этого репозитория (`labs/`);
    * систем, на тестирование которых у вас есть **письменное разрешение** владельца;
    * CTF-площадок и учебных стендов.

    Атака на чужие системы без разрешения — преступление в большинстве юрисдикций
    (в РФ — ст. 272–274 УК, в ЕС/США — CFAA, Computer Misuse Act и аналоги).
    Ответственность за применение знаний несёте вы.

## Зачем ещё одна книга

Существуют отличные открытые ресурсы: HackTricks, PayloadsAllTheThings, PortSwigger
Web Security Academy, OWASP Testing Guide. Проблемы у них две:

1. **Материал разорван.** Теория живёт в одном месте, payload'ы — в другом, лаборатории —
   в третьем. Читателю приходится самому склеивать картину.
2. **Нет связей.** Понимание приходит не от списка техник, а от понимания, *куда техника
   ведёт*: SQLi → чтение конфигурации → учётные данные → перемещение по сети → домен.
   Здесь эти связи формализованы в графе и генерируются автоматически из метаданных.

hackbook отвечает на оба пункта: единый формат контента, автоматическая сборка графа
и лаборатории, которые поднимаются одной командой.

## Структура репозитория

| Каталог | Что внутри | Как используется |
|---------|-----------|------------------|
| `book/src/` | Главы учебника в Markdown + `meta.yaml` | Собирается в HTML/PDF/EPUB |
| `payloads/` | Карточки payload'ов в едином формате | Подключаются в главы через `include`, питают граф |
| `wordlists/` | Словари + `metadata.yaml` с описанием | Перебор, фаззинг; валидируются в CI |
| `labs/` | Docker-compose лаборатории | `docker compose up` — и можно практиковаться |
| `tools/` | Скрипты сборки и валидации | PDF, граф, проверка словарей и ссылок |
| `docs/` | Документация проекта | CONTRIBUTING, STYLE-GUIDE, ROADMAP |
| `.github/workflows/` | CI/CD | Сборка, валидация payload'ов, деплой графа |

### Единый источник правды

Ни одна связь не описывается дважды. Граф знаний, оглавление книги, поиск и
статистика в README генерируются из одного и того же набора Markdown-файлов
с YAML-заголовком. Изменили метаданные payload'а — граф обновился сам.

```
payloads/**/*.md  ─┐
book/src/**/*.md  ─┼──> tools/graph-generator.py ──> payloads/graph/graph.json
wordlists/*.yaml  ─┘                              └──> payloads/graph/index.html
```

## Формат главы

Глава — это каталог `book/src/NN-название/` с файлами `chapter.md` и `meta.yaml`.
В начале `chapter.md` идёт YAML front-matter:

```yaml
---
title: "SQL Injection: Полное руководство"
chapter: 1
difficulty: intermediate
tags: [sqli, web, injection]
prerequisites: ["HTTP Basics", "SQL Fundamentals"]
related_payloads: ["payloads/web/sqli/mysql-tautology-auth-bypass.md"]
lab: "labs/web-labs/sqli-lab"
---
```

| Поле | Обязательно | Смысл |
|------|-------------|-------|
| `title` | да | Заголовок главы |
| `chapter` | да | Номер (влияет на порядок в книге) |
| `difficulty` | да | `beginner` / `intermediate` / `advanced` |
| `tags` | нет | Теги для поиска и графа |
| `prerequisites` | нет | Что нужно знать заранее (станет рёбрами `requires`) |
| `related_payloads` | нет | Карточки payload'ов для этой главы |
| `lab` | нет | Каталог лаборатории для практики |

Внутри главы можно подключать payload'ы целиком:

```markdown
{{ include "payloads/web/sqli/mysql-tautology-auth-bypass.md" }}
```

Директива раскрывается при сборке (`tools/pdf-builder.py`) и одновременно
регистрирует связь «глава → payload» в графе.

## Формат payload'а

Каждый payload — отдельный `.md`-файл. Полный шаблон лежит в
`payloads/templates/payload-template.md`. Обязательные секции:

```markdown
---
id: sqli-mysql-tautology-auth-bypass
title: "MySQL: обход аутентификации тавтологией"
type: sqli
target: mysql
difficulty: beginner
bypass: none
risk: low
cwe: "CWE-89"
tested_on: ["MySQL 8.0"]
success_rate: 0.9
lab: "labs/web-labs/sqli-lab"
graph:
  - target: auth-bypass
    type: leads_to
    description: "SQLi в форме логина даёт обход аутентификации"
---

# Заголовок

## Payload      <- первый блок без указания языка = канонический payload
## Explanation  <- почему работает
## Detection    <- как найти
## Remediation  <- как чинить
```

Поле `graph` — единственный способ добавить связь в граф знаний вручную.
Типы рёбер фиксированы (`leads_to`, `instance_of`, `related_to`, `technique_of`,
`covered_in`, `practiced_in`, `requires`, `category_of`, `uses`) — их проверяет CI.

## Методология работы с материалом

Рекомендуемый цикл для каждой темы:

1. **Теория.** Прочитать главу: как уязвимость возникает, какие бывают варианты.
2. **Payload'ы.** Разобрать карточки: не копировать, а понять, *почему* строка работает.
3. **Лаборатория.** Поднять лабу (`docker compose up -d`) и воспроизвести вручную.
4. **Детект.** Проверить, что видно в логах: это половина профессии защитника.
5. **Исправление.** Починить код в лабе и убедиться, что payload больше не работает.
6. **Граф.** Посмотреть в `payloads/graph/index.html`, куда техника ведёт дальше.

Пункты 4–5 отличают учебник от списка эксплойтов: у каждой карточки есть секции
`Detection` и `Remediation`, и именно они чаще всего нужны на работе.

## Как собирать проект локально

```bash
# HTML/PDF/EPUB из глав
python tools/pdf-builder.py --format all

# граф знаний
python tools/graph-generator.py --pretty

# проверки качества
python tools/wordlist-validator.py
python tools/link-checker.py
python tools/validate-payloads.py --strict

# лаборатория
cd labs/setup && docker compose up -d
```

Все скрипты работают на «чистом» Python 3.10+ без обязательных зависимостей:
PDF собирается через WeasyPrint, если он установлен, иначе через fpdf2,
а HTML-бандл и EPUB не требуют ничего.

## Дорожная карта и вклад в проект

* `docs/ROADMAP.md` — план по фазам и текущий статус;
* `docs/CONTRIBUTING.md` — как добавить главу, payload или лабу;
* `docs/STYLE-GUIDE.md` — правила оформления текста и кода.

Начинать проще всего с payload'ов: возьмите технику, которую вы реально проверяли,
опишите её по шаблону и укажите, где и на чём тестировали (`tested_on`).
Карточка без подтверждения воспроизводимости в книгу не попадёт.
