---
title: "Web Security: инъекции, XSS и всё, что между ними"
chapter: 1
difficulty: intermediate
category: web
tags: [web, sqli, xss, ssrf, lfi, xxe, cmdi, ssti, http]
prerequisites: ["HTTP Basics", "Основы SQL", "Как работает браузер"]
related_payloads:
  - "payloads/web/sqli/mysql-tautology-auth-bypass.md"
  - "payloads/web/sqli/mysql-union-select-enumeration.md"
  - "payloads/web/xss/reflected-basic-script.md"
  - "payloads/web/ssrf/cloud-metadata-169254.md"
  - "payloads/web/lfi-rfi/traversal-etc-passwd.md"
  - "payloads/web/cmdi/basic-chained-commands.md"
lab: "labs/web-labs/sqli-lab"
---

# Web Security: инъекции, XSS и всё, что между ними

Подавляющая часть веб-уязвимостей — это одна и та же ошибка в разных декорациях:
**данные пользователя попадают туда, где исполняется код**. SQL-запрос, shell-команда,
HTML-разметка, XML-парсер, шаблонизатор, HTTP-заголовок. Отличаются только синтаксис
«склеивания» и способ экранирования.

Эта глава разбирает семейство инъекций по единой схеме:

1. где возникает (источник данных);
2. как выглядит в коде (уязвимый паттерн);
3. как проверяется (безопасная диагностика);
4. как эксплуатируется (карточки payload'ов);
5. как чинится (единственно верный способ + защитные слои).

## Модель: источник → приёмник

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  ИСТОЧНИК    │ --> │  ОБРАБОТКА       │ --> │  ПРИЁМНИК (sink) │
│ query/body/  │     │ конкатенация     │     │ SQL / shell /    │
│ header/cookie│     │ без параметризации│    │ HTML / XML /     │
│ file/URL     │     │                  │     │ template / path  │
└──────────────┘     └──────────────────┘     └──────────────────┘
```

Уязвимость существует, если между источником и приёмником нет **контекстно-правильного**
преобразования. Ключевое слово — контекстного: экранирование кавычек для SQL бесполезно
в HTML, а HTML-экранирование не спасает внутри атрибута, обёрнутого в одинарные кавычки.

| Приёмник | Правильная защита | Типичная ошибка |
|----------|-------------------|-----------------|
| SQL | prepared statements | конкатенация строк, `format()` |
| Shell | `execve` с массивом аргументов | `os.system`, `shell=True` |
| HTML | автоэкранирование шаблонизатора | `\|safe`, `innerHTML`, `dangerouslySetInnerHTML` |
| XML-парсер | запрет DTD и внешних сущностей | настройки «по умолчанию» |
| Шаблонизатор | данные в контекст, не в шаблон | `render(user_string)` |
| Файловый путь | whitelist алиасов | `open(base + request.param)` |
| HTTP-заголовок | валидация charset, запрет CRLF | `Location: " + user_url` |

## SQL Injection

### Как возникает

```python
# УЯЗВИМО
query = f"SELECT * FROM users WHERE login='{login}' AND password='{password}'"
cursor.execute(query)

# БЕЗОПАСНО
cursor.execute(
    "SELECT * FROM users WHERE login=%s AND password_hash=%s",
    (login, password_hash),
)
```

Во втором случае драйвер передаёт значения отдельно от текста запроса: СУБД никогда
не интерпретирует их как синтаксис. Именно поэтому параметризация лечит **все**
варианты SQLi сразу — тавтологии, UNION, blind, second-order, stacked queries.

### Классификация по каналу получения данных

| Класс | Как проявляется | Сложность | Payload'ы |
|-------|-----------------|-----------|-----------|
| In-band (union/error) | Данные видны в ответе | низкая | `mysql-union-select-enumeration`, `mysql-error-based-extractvalue` |
| Boolean blind | Различается «есть результат / нет» | средняя | `mysql-boolean-blind`, `postgresql-boolean-sleep` |
| Time blind | Различается только время ответа | средняя | `mysql-time-based-sleep` |
| Out-of-band | Данные уходят по DNS/HTTP наружу | высокая | `generic-out-of-band-dns` |
| Second-order | Срабатывает позже, из сохранённых данных | высокая | `mysql-second-order` |

### Диагностика

Минимальный безопасный набор проверок (ничего не ломает, данные не читает):

```bash
# 1. синтаксическая ошибка на одинарной кавычке
curl -s "http://lab.local:8080/item?id=1'" | grep -i "sql\|syntax\|error"

# 2. логическое различие: истина против лжи
curl -s "http://lab.local:8080/item?id=1 AND 1=1" -o /tmp/a.html
curl -s "http://lab.local:8080/item?id=1 AND 1=2" -o /tmp/b.html
diff <(wc -c </tmp/a.html) <(wc -c </tmp/b.html)

# 3. временной канал
time curl -s "http://lab.local:8080/item?id=1;SELECT SLEEP(5)-- -" -o /dev/null
```

Автоматизация — `sqlmap`, но сначала поймите, что именно он подбирает:
число колонок, тип данных, точку вывода, технику чтения.

### Карточка payload'а (пример формата)

Ниже — живая карточка из базы, подключённая директивой `include`. Обратите внимание
на структуру: `Payload` → `Explanation` → `Detection` → `Remediation`.

{{ include "payloads/web/sqli/mysql-tautology-auth-bypass.md" }}

### Что читать дальше по SQLi

* `payloads/web/sqli/mysql-union-select-enumeration.md` — перечисление схемы;
* `payloads/web/sqli/mysql-time-based-sleep.md` — слепая инъекция по времени;
* `payloads/web/sqli/mssql-xp-cmdshell.md` — переход от инъекции к командам ОС;
* `payloads/web/sqli/postgresql-copy-program.md` — то же для PostgreSQL.

## Cross-Site Scripting

XSS — это выполнение вашего JavaScript в контексте чужого сайта. Последствия:
кража сессии, действия от имени пользователя, кейлоггинг в рамках страницы,
подмена контента, атаки на админ-панели (blind XSS).

### Три контекста — три разных защиты

```html
<!-- 1. тело HTML: экранируем < > & -->
<p>Привет, <?= escape($name) ?></p>

<!-- 2. атрибут: экранируем ещё и кавычки -->
<input value="<?= escape_attr($value) ?>">

<!-- 3. JavaScript: JSON-кодирование, никакого "просто экранировать" -->
<script>const data = <?= json_encode($value, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) ?>;</script>
```

Ошибка №1 — применять HTML-экранирование «ко всему подряд»: в JS-контексте
`&#39;` не спасает, а в URL-контексте нужен percent-encoding.

### Классификация

| Тип | Где живёт | Как доставляется | Карточки |
|-----|-----------|------------------|----------|
| Reflected | В ответе на текущий запрос | Ссылка/запрос жертве | `reflected-basic-script` |
| Stored | В БД (комментарий, профиль) | Само собой, всем посетителям | `stored-in-profile` |
| DOM-based | В клиентском JS | Любой источник (`location.hash`, `postMessage`) | `dom-location-hash` |
| Blind | В логах/админке | Исполняется у оператора | `stored-in-profile`, `user-agent-log-injection` |
| mXSS | В санитайзере | Пересборка DOM браузером | `mutation-xss` |

### CSP — не замена экранированию

Content-Security-Policy резко снижает цену успешного XSS, но:

* `script-src 'self'` + разрешённый CDN с JSONP-эндпоинтом = обход
  (`payloads/web/xss/csp-bypass-jsonp.md`);
* `unsafe-inline` или `unsafe-eval` обесценивают политику почти полностью;
* `javascript:` в `href` политикой не блокируется.

Рабочая конфигурация: точный список источников + nonce/hash для inline-скриптов,
`object-src 'none'`, `base-uri 'none'`, `frame-ancestors`, `report-to` и
Trusted Types там, где поддерживается.

{{ include "payloads/web/xss/img-onerror-no-script-tag.md" }}

## Path Traversal и LFI/RFI

```python
# УЯЗВИМО
path = os.path.join(UPLOADS, request.args["file"])
return send_file(path)

# БЕЗОПАСНО
ALLOWED = {"invoice": "invoice.pdf", "terms": "terms.pdf"}
name = ALLOWED.get(request.args["file"])          # whitelist алиасов
if not name:
    abort(404)
return send_file(os.path.join(UPLOADS, name))
```

Если whitelist невозможен — нормализуйте путь и проверяйте префикс:

```python
base = Path(UPLOADS).resolve()
target = (base / user_input).resolve()
if not target.is_relative_to(base):
    abort(400)
```

В PHP-контексте добавляются stream wrappers (`php://filter`, `php://input`, `data://`)
и двухшаговые техники вроде отравления логов. Разбор — в
`payloads/web/lfi-rfi/`.

## SSRF

SSRF опасен не сам по себе, а тем, что открывает доступ к **внутренним** ресурсам:
метаданным облака, админ-панелям, Redis/Memcached, внутренним API без аутентификации.

Правильная защита — не blacklist адресов, а:

1. whitelist доменов и схем (только `https`);
2. резолв DNS до проверки и проверка **всех** полученных IP (включая IPv6);
3. запрет или повторная валидация редиректов;
4. исходящий прокси для всех fetch-запросов приложения;
5. IMDSv2 (`HttpTokens: required`) и `HttpPutResponseHopLimit: 1` в AWS.

Подробнее: `payloads/web/ssrf/`.

## XXE

XML-парсеры по-прежнему опасны, потому что «безопасные настройки» в разных языках
задаются по-разному и почти нигде не включены по умолчанию:

```java
// Java — безопасная фабрика
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

```python
# Python — defusedxml вместо lxml/xml.etree
from defusedxml import ElementTree as ET
ET.fromstring(untrusted_xml)
```

Не забывайте про неочевидные точки входа: загрузка SVG/DOCX/XLSX — это тоже XML
(`payloads/web/xxe/svg-upload-vector.md`).

## Command Injection и SSTI

Оба класса дают выполнение кода, оба лечатся отказом от интерпретации
пользовательских данных:

```python
# УЯЗВИМО
os.system(f"convert {filename} out.png")

# БЕЗОПАСНО
subprocess.run(["convert", filename, "out.png"], shell=False, check=True, timeout=30)
```

```python
# УЯЗВИМО (шаблон собирается из ввода)
Template("Hello " + user_name).render()

# БЕЗОПАСНО (шаблон фиксирован, ввод — данные)
Template("Hello {{ name }}").render(name=user_name)
```

Отдельно стоит помнить про **argument injection**: даже вызов без shell опасен,
если пользовательское значение может начинаться с `-` (`--upload-pack=`, `-oProxyCommand=`,
`--checkpoint-action=exec=`). Спасает разделитель `--` и валидация.

## Практика

### Лаборатория

```bash
cd labs/setup
docker compose up -d sqli-lab xss-lab
# SQLi:  http://localhost:8080/?id=1
# XSS:   http://localhost:8081/?q=test
```

Задания по возрастанию сложности:

1. Подтвердите SQLi в `?id=` тремя способами: ошибка, логическое различие, задержка.
2. Определите число колонок и выведите версию СУБД через UNION.
3. Прочитайте таблицу `users` и объясните, почему хранение паролей в MD5 — отдельная находка.
4. Почините приложение (переведите запросы на параметры) и убедитесь, что payload'ы
   из пунктов 1–3 перестали работать.
5. В `xss-lab` найдите три контекста отражения (тело, атрибут, JS) и подберите
   вектор для каждого.
6. Включите CSP `default-src 'self'; script-src 'self'` и проверьте, какие векторы
   остались рабочими. Объясните результат.

### Чек-лист ревью веб-кода

- [ ] Нет конкатенации пользовательских данных в SQL/shell/XML/шаблон/путь.
- [ ] Все выводимые значения экранированы в правильном контексте.
- [ ] Заголовки ответов не собираются из ввода; CRLF отклоняется.
- [ ] Исходящие URL валидируются по whitelist, редиректы контролируются.
- [ ] XML-парсеры с отключёнными DTD/внешними сущностями.
- [ ] Загрузки проверяются по содержимому, хранятся вне веб-корня, отдаются
      как `attachment`.
- [ ] CSP, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`,
      `Referrer-Policy`, cookie с `HttpOnly`/`Secure`/`SameSite`.
- [ ] Ошибки не раскрывают стектрейсы, версии и тексты СУБД.
- [ ] Rate limiting на аутентификации и «дорогих» эндпоинтах.
- [ ] Авторизация проверяется для каждого объекта (защита от IDOR).

## Связи в графе

Откройте `payloads/graph/index.html` и выберите узел `sqli`: вы увидите рёбра
`leads_to` к `auth-bypass`, `data-exfiltration`, `rce` и `active-directory`.
Это не декорация — это маршрут типового вторжения: инъекция в веб-приложении
заканчивается в домене Windows через учётную запись службы СУБД.
