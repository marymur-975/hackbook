---
id: logic-graphql-introspection-batching
title: "GraphQL: introspection, батчинг и отсутствие лимитов"
type: logic
target: graphql
category: web
difficulty: intermediate
bypass: none
tags: [graphql, introspection, dos, idor, batching]
tested_on: ["Apollo Server", "graphql-yoga", "Hasura", "PostGraphile"]
success_rate: 0.6
risk: high
cwe: "CWE-200"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "business-logic"
    type: related_to
  - target: "info-disclosure"
    type: leads_to
  - target: "dos"
    type: leads_to
  - target: "auth-bypass"
    type: related_to
  - target: "bruteforce"
    type: related_to
---

# GraphQL: introspection, батчинг и отсутствие лимитов

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
query IntrospectionQuery {
  __schema { types { name fields { name type { name kind ofType { name } } } } }
}
```

## Explanation

GraphQL концентрирует несколько классов проблем в одной точке:

1. **Introspection** включён в production -> полная карта схемы: типы, поля,
    мутации, аргументы, включая служебные (`deleteUser`, `setRole`).
    Это не уязвимость сама по себе, но она сокращает разведку до одного запроса.
2. **Батчинг**: массив запросов в одном HTTP-вызове
    (`[{query:…},{query:…},…]`) обходит rate limiting, который считает HTTP-запросы.
3. **Вложенность и алиасы** -> DoS: `{a: user { friends { friends { … }}}}`
    или 100 алиасов тяжёлого поля = экспоненциальная нагрузка.
4. **Авторизация на резолверах**: проверка есть на `Query.viewer`, но её нет
    на `User.email`, доступном через другую связь (классический GraphQL-IDOR).
5. **Мутации без идемпотентности**: повторный вызов создаёт дубли заказов.
6. **Утечка ошибок**: стектрейсы резолверов раскрывают SQL/внутренние пути.
7. Запросы в GET (кэшируются CDN/прокси), отсутствие depth/complexity-лимитов.

## Detection

1. `POST /graphql {"query":"{__schema{types{name}}}"}` — схема открыта?
2. Проверьте `__typename`, `__type(name:"User")` и поля `Mutation`.
3. Батчинг: отправьте массив из 50 копий одного запроса — все ли выполнились
   (и как сработал rate limit).
4. Глубина: запрос с 20 уровнями вложенности и 50 алиасами — время ответа.
5. IDOR: запросите объект по чужому id через разные связи схемы.
6. Инструменты: `graphql-voyager`, `InQL` (Burp), `graphw00f`, `clairvoyix`.

## Remediation

- Отключить introspection в production (`introspection: false`), оставить
  только для внутренней среды; не полагаться на это как на защиту.
- Авторизация **на каждом резолвере** (не только на корневом), проверка
  владения объектом; единая policy-библиотека.
- Лимиты: query depth (≤ 8), complexity/стоимость запроса, число алиасов,
  размер запроса, таймаут резолверов.
- Запрет батчинга или отдельный лимит на число операций в батче;
  rate limiting по операциям, а не по HTTP-запросам.
- Мутации идемпотентны (idempotency key), транзакционны.
- Ошибки: общий текст клиенту, детали в лог; `persisted queries`
  (allowlist запросов) для публичных API.
- WAF/API-gateway: запрет `__schema`/`__type` наружу, мониторинг тяжёлых запросов.

## Variants

```
[{"query":"{me{id}}"},{"query":"{me{id}}"}] (батчинг)
```

```
query { a1: user(id:1){email} a2: user(id:2){email} … a50: … }
```

```
GET /graphql?query={me{id}} (кеш прокси)
```

## Detection rules

```yaml
title: GraphQL-злоупотребление — глубина, алиасы и батчинг запросов
id: e5f6a7b8-0079-4e5f-9a7b-000000000079
status: experimental
description: >-
  Аномалии по метрикам GraphQL-запросов: глубина вложенности >= 10,
  >= 5 алиасов (alias-бомба для обхода rate-limit), батч из >= 5 операций,
  а также IntrospectionQuery в продуктивном контуре.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://graphql.org/learn/introspection/
logsource:
  category: application
  definition: 'логи API-шлюза GraphQL с метриками запроса (depth, aliases, batch)'
detection:
  depth_bomb:
    query_depth|gte: 10
  alias_bomb:
    alias_count|gte: 5
  batch_bomb:
    batch_size|gte: 5
  introspection_prod:
    operation_name: IntrospectionQuery
  condition: depth_bomb or alias_bomb or batch_bomb or introspection_prod
fields:
  - source_ip
  - operation_name
  - query_depth
  - alias_count
  - batch_size
  - duration_ms
falsepositives:
  - легитимные агрегирующие запросы мобильных клиентов (глубина 5-7) —
    пороги подбирайте по профилю своей нагрузки
level: medium
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.400
```
