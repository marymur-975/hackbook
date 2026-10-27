# xss-lab — лаборатория Cross-Site Scripting

Намеренно уязвимое приложение на Python stdlib. Соответствует главе 1
(«Web Security») и карточкам `payloads/web/xss/`.

```bash
cd labs/setup && docker compose up -d xss-lab
# или без Docker:
DB_PATH=/tmp/xss.db PORT=8081 python3 labs/web-labs/xss-lab/app.py
```

URL: http://localhost:8081

## Контексты вывода

Главная идея лабы: **одна и та же нагрузка работает не во всех контекстах**,
а защита обязана быть контекстно-зависимой.

| Эндпоинт | Контекст | Экранируется? | Рабочий вектор |
|----------|----------|---------------|----------------|
| `/reflect?q=` | тело HTML | нет | `<svg onload=alert(document.domain)>` |
| `/attribute?v=` | значение атрибута в `"` | нет | `" autofocus onfocus=alert(document.domain) x="` |
| `/js?name=` | строка в JavaScript | нет | `';alert(document.domain);//` |
| `/filtered?q=` | тело HTML + blacklist | только `<script` | `<img src=x onerror=alert(document.domain)>` |
| `/guestbook` | stored (SQLite) | нет | `<details open ontoggle=alert(document.domain)>` |
| `/guestbook.json` | JSON-экспорт | нет | та же нагрузка, исполнение при рендере |
| `/safe?q=` | тело HTML | `html.escape` | — (контрольная точка) |
| `/csp?q=` | тело HTML + CSP | `html.escape` + политика | — (контрольная точка) |

## Задания

### 1. Три контекста — три вектора

Для каждого эндпоинта подберите работающую нагрузку и объясните, почему
HTML-экранирование (`&lt;`) **не** защищает в `/attribute` и `/js`.

```bash
curl -s "localhost:8081/reflect?q=%3Csvg%20onload%3Dalert(document.domain)%3E" | grep -o "<svg.*"
curl -s "localhost:8081/attribute?v=%22%20autofocus%20onfocus%3Dalert(1)%20x%3D%22" | grep -o "value=.*size"
curl -s "localhost:8081/js?name=%27%3Balert(document.domain)%3B%2F%2F" | grep -o "const name.*"
```

### 2. Обойти blacklist тремя способами

Фильтр в `/filtered` вырезает только `<script`. Найдите минимум три обхода:

1. тег без `script` (`<img onerror>`, `<svg onload>`, `<body onload>`);
2. изменение регистра / разбиение (`<ScRiPt`, `<scr<script>ipt>`);
3. HTML-сущности и JS-экранирование (`&#97;lert`, `\u0061lert`).

Объясните, почему whitelist-санитизация (DOMPurify/bleach) решает задачу,
а blacklist — нет.

### 3. Stored XSS и blind-вектор

```bash
curl -s -X POST localhost:8081/guestbook \
  --data-urlencode "author=<b>student</b>" \
  --data-urlencode "body=<details open ontoggle=alert(document.domain)>hb</details>"
curl -s localhost:8081/guestbook | grep -c "ontoggle"
```

Найдите все места, где сообщение отображается (`/guestbook`, `/guestbook.json`)
и объясните, чем stored-XSS опаснее reflected. Отдельно обсудите blind XSS:
что произойдёт, если сообщения попадут во внутреннюю панель модерации?

### 4. CSP: что остаётся рабочим

Страница `/csp` отдаёт `default-src 'self'; script-src 'self'; object-src 'none'`.
Проверьте на ней векторы из заданий 1–3 и зафиксируйте, что CSP блокирует,
а что нет:

* inline-обработчики (`onload=`, `onerror=`) — блокируются;
* `javascript:` в `href` — **не блокируется** CSP (нужна валидация URL на сервере);
* внешний скрипт с разрешённого CDN (JSONP-gadget) — обход, см.
  `payloads/web/xss/csp-bypass-jsonp.md`.

### 5. Починить приложение

Примените контекстно-зависимое экранирование:

```python
# тело HTML
value = html.escape(raw, quote=True)

# атрибут
f"<input value=\"{html.escape(raw, quote=True)}\">"

# JavaScript-контекст — только JSON-кодирование
f"const name = {json.dumps(raw)};"

# пользовательская разметка — санитайзер с whitelist, не blacklist
import bleach  # вне этой лабы; в stdlib аналога нет
bleach.clean(raw, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
```

После починки прогоните тесты — маркеры отражения должны исчезнуть:

```bash
tools/payload-tester.sh --lab xss-lab
```

## Автоматические тесты

```bash
tools/payload-tester.sh --lab xss-lab --report reports/xss.json
```

Критерий «PASS»: в ответе присутствует сырой тег или обработчик события
без HTML-экранирования. На `/safe` и `/csp` те же векторы отражаются как
`&lt;svg …` и считаются непрошедшими — так и задумано.

## Артефакты для разбора

* `payloads/web/xss/reflected-basic-script.md`
* `payloads/web/xss/attribute-breakout-double-quote.md`
* `payloads/web/xss/img-onerror-no-script-tag.md`
* `payloads/web/xss/html-entity-encoding-bypass.md`
* `payloads/web/xss/stored-in-profile.md`
* `payloads/web/xss/csp-bypass-jsonp.md`
* `payloads/web/xss/mutation-xss.md`
