# Вклад в hackbook

Спасибо, что хотите участвовать. Ниже — всё, что нужно, чтобы ваш pull request
прошёл ревью с первого раза.

## Правила игры

1. **Только авторизованное тестирование.** Карточки описывают техники для
   лабораторий и систем с письменным разрешением. Мы не принимаем:
   - готовые вредоносные инструменты (шифровальщики, стиллеры, руткиты,
     C2-фреймворки, обфусцированные дропперы);
   - payload'ы, нацеленные на отказ инфраструктуры третьих лиц (DDoS-усиление
     против конкретных целей, массовые рассылки);
   - реальные учётные данные, ключи, токены и персональные данные из утечек;
   - инструкции по атаке на конкретные живые сервисы и организации.
2. **Воспроизводимость.** Указывайте `tested_on`: где и на чём вы проверяли
   карточку. «Работает в теории» — это гипотеза, а не payload.
3. **Защита обязательна.** Карточка без секций `Detection` и `Remediation`
   не принимается: проект учебный, а не оружейный.
4. **Один PR = одна тема.** 30 карточек SQLi и редизайн графа в одном PR —
   гарантированно долгий ревью.

## Быстрый старт

```bash
git clone https://github.com/hackbook/hackbook.git
cd hackbook
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# проверки, которые должен пройти ваш PR
python tools/validate-payloads.py --strict
python tools/wordlist-validator.py --secrets --strict
python tools/detections-extract.py --check  # Sigma-правила в карточках
python tools/rules-tester.py                # правила на фикстурах
python tools/tests/test_lib.py              # юнит-тесты инструментов
python tools/link-checker.py
python tools/graph-generator.py --check
```

## Добавить карточку payload'а

```bash
cp payloads/templates/payload-template.md payloads/web/sqli/my-technique.md
```

Заполните front-matter:

| Поле            | Обязательно | Комментарий                                                                                  |
| --------------- | :---------: | -------------------------------------------------------------------------------------------- |
| `id`            |     ✅      | kebab-case, уникален во всём репозитории; соглашение `<тип>-<имя файла>`                     |
| `title`         |     ✅      | человекочитаемый, с указанием цели: «MySQL: …»                                               |
| `type`          |     ✅      | `sqli` `xss` `ssrf` `lfi` `rfi` `xxe` `cmdi` `ssti` `auth-bypass` `header` `network` `cloud` |
| `target`        |     ✅      | СУБД / ОС / сервис / `generic`                                                               |
| `category`      |     ✅      | `web` `network` `active-directory` `cloud` `privilege-escalation` `general`                  |
| `difficulty`    |     ✅      | `beginner` `intermediate` `advanced` `expert`                                                |
| `bypass`        |     ✅      | `none` `waf` `filter` `encoding` `auth` `sandbox`                                            |
| `tags`          |     ✅      | 2–6 тегов, kebab-case, только строчные                                                       |
| `tested_on`     |     ✅      | конкретные версии: `["MySQL 8.0", "SQLite 3.40 (sqli-lab)"]`                                 |
| `success_rate`  |     ✅      | 0.0–1.0, ваша честная оценка воспроизводимости                                               |
| `risk`          |     ✅      | `low` `medium` `high` `critical` — насколько разрушителен payload                            |
| `cwe`           |     ✅      | `CWE-89` и т.п. (или `null`, если неприменимо)                                               |
| `references`    |     ➖      | OWASP/PortSwigger/вендорская документация                                                    |
| `lab`           |     ➖      | путь к лаборатории, где техника воспроизводится                                              |
| `graph`         |     ➖      | рёбра графа знаний (см. ниже)                                                                |
| `last_verified` |     ✅      | ISO-дата последней проверки                                                                  |

Секции тела — в этом порядке:

```markdown
# <title>

!!! warning "Этика"
Только лаборатории `hackbook` или системы с письменным разрешением.

## Payload <- первый code-блок БЕЗ указания языка

## Explanation <- почему работает: синтаксис, логика, ограничения

## Detection <- признаки в ответе, логах, SIEM; как безопасно проверить

## Remediation <- конкретные настройки/код, а не «используйте параметры»

## Variants <- необязательно: варианты и обходы

## Notes <- необязательно: оговорки, ложные срабатывания
```

### Рёбра графа

```yaml
graph:
  - target: auth-bypass # узел: payload, техника или понятие
    type: leads_to # тип связи (см. список ниже)
    description: "SQLi в форме логина даёт обход авторизации"
```

Допустимые типы: `leads_to`, `instance_of`, `related_to`, `technique_of`,
`covered_in`, `practiced_in`, `requires`, `category_of`, `uses`.

Узел `instance_of` на технику добавляется автоматически по полю `type`,
поэтому вручную его указывать не нужно.

После добавления карточек **обязательно** перегенерируйте граф:

```bash
python tools/graph-generator.py --pretty
git add payloads/graph/graph.json payloads/graph/index.html
```

CI падает, если закоммиченный `graph.json` расходится с контентом.

## Добавить главу

```bash
mkdir -p book/src/06-mobile
```

- `chapter.md` — текст с YAML front-matter (`title`, `chapter`, `difficulty`,
  `category`, `tags`, `prerequisites`, `related_payloads`, `lab`);
- `meta.yaml` — те же метаданные в отдельном файле (front-matter приоритетнее),
  удобно для `estimated_minutes`, `status`, `authors` и рёбер графа.

Подключение карточек в текст главы:

```markdown
{{ include "payloads/web/sqli/mysql-tautology-auth-bypass.md" }}
```

Директива раскрывается при сборке PDF/EPUB и при генерации сайта, а связь
«глава → payload» автоматически попадает в граф.

Структура главы (рекомендуется):

```
# Заголовок
вступление: почему тема важна, какое место занимает в реальной атаке
## Как возникает      — уязвимый паттерн кода
## Классификация      — таблица вариантов
## Диагностика        — безопасные проверки, команды
## Payload'ы          — ссылки/include на карточки
## Практика           — лаборатория + задания по возрастанию сложности
## Чек-лист           — что проверить в коде/конфигурации
## Связи в графе       — куда техника ведёт дальше
```

## Добавить лабораторию

1. `labs/<категория>/<имя>-lab/` с `app.py` (или Dockerfile), `Dockerfile`,
   `tests.yaml`, `README.md`.
2. Подключите сервис в `labs/setup/docker-compose.yml`:
   - порт **только** на `127.0.0.1`;
   - `cap_drop: [ALL]`, `read_only: true`, `no-new-privileges`;
   - non-root пользователь в образе;
   - `healthcheck`.
3. `tests.yaml` — точки входа и маркеры успеха для `tools/payload-tester.sh`
   (блоки с `expect_no_markers` считаются контрольными точками и не тестируются).
4. `README.md` — задания по возрастанию сложности, последнее задание всегда
   «починить и перепроверить».
5. Свяжите карточки с lab'ой через поле `lab:` в front-matter.

## Добавить словарь

1. Файл в `wordlists/<категория>/<имя>.txt`: UTF-8, LF, без BOM, без пустых
   строк и дубликатов, без пробелов по краям.
2. Описание в `wordlists/metadata.yaml`: `name`, `path`, `size`, `use_cases`,
   `source`, `license`, `last_updated`.
3. Проверка: `python tools/wordlist-validator.py --secrets --strict`.

**Не коммитьте**: реальные дампы утечек, персональные данные, ключи и токены.
Объёмные списки (rockyou, SecLists) подключаются через
`wordlists/fetch-external.sh` и перечислены в секции `external:` метаданных.

## Стиль

Полные правила — в [`STYLE-GUIDE.md`](STYLE-GUIDE.md). Кратко:

- русский язык для текста, английский — для кода, метаданных и идентификаторов;
- заголовки — ATX (`##`), до трёх уровней вложенности;
- код — fenced-блоки с указанием языка (кроме канонического payload'а);
- таблицы — для сравнений и справочников; списки — для перечислений;
- одна мысль = один абзац; строки в Markdown переносите по смыслу;
- `!!! warning`/`!!! danger` — для предупреждений об этике и разрушительных
  техниках.

## Процесс ревью

1. CI должен быть зелёным: `validate-payloads`, `wordlist-validator`,
   `link-checker`, `graph-generator --check`, сборка PDF/EPUB и сайта.
2. Рецензент смотрит: корректность техники, наличие `Detection`/`Remediation`,
   соответствие формату, отсутствие запрещённого контента (см. «Правила игры»).
3. Замечания исправляются в той же ветке (squash при мерже).
4. Мерж — после одного approve и зелёного CI.

Мелкие правки (опечатки, битые ссылки) мержатся без длительного обсуждения.

## Идеи, с которых удобно начать

- карточки по техникам, которые вы проверяли в CTF или на работе;
- секции `Detection` для существующих карточек (правила Sigma/Suricata/YARA);
- перевод и адаптация заданий лабораторий;
- новые словари с указанием источника и лицензии;
- тесты для `tools/` (сейчас их нет — это известная слабость проекта);
- улучшения графа: группировка, экспорт PNG/SVG, режим «путь между узлами».

Актуальный список — в issue с меткой `good first issue`.

## Кодекс поведения

Взаимоуважение, критика работы (а не человека), отсутствие оскорблений
и дискриминации. Нарушения — к мейнтейнерам (см. [`SECURITY.md`](SECURITY.md)).

## Карточка детектирования и правила

Если вы добавляете технику — добавьте и правило детектирования: секция
`## Detection rules` с блоком ```yaml в конце карточки. Правило без теста
деградирует молча, поэтому:

1. опишите правило (обязательные поля: `title`, `id`-UUID, `status`,
   `description`, `logsource`, `detection` + `condition`, `level`,
   `falsepositives`);
2. добавьте синтетические события в `detections/tests/generate_fixtures.py`
   (и положительные, и отрицательные — иначе правило «ловит всё»);
3. пропишите ожидаемое число совпадений в `detections/tests/manifest.json`;
4. пересоберите:

   ```bash
   python detections/tests/generate_fixtures.py
   python tools/detections-extract.py
   python tools/rules-tester.py --verbose
   ```

Каталог `detections/**/*.yml` генерируется из карточек — правьте карточку,
а не файл правила. CI проверяет, что каталог не расходится с контентом.

Подробности: [`detections/index.md`](../detections/index.md).
