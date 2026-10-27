---
id: detection-graphql-abuse-logs
title: "Детект злоупотреблений GraphQL: introspection, батчинг, тяжёлые запросы"
type: logic
target: graphql
category: web
difficulty: intermediate
bypass: none
tags: [detection, sigma, graphql, dos, idor, api-logs]
tested_on: ["Apollo Server access logs", "API gateway logs"]
success_rate: 0.6
risk: low
cwe: "CWE-770"
lab: null
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
---

# Детект злоупотреблений GraphQL: introspection, батчинг, тяжёлые запросы

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# воспроизведение (свой стенд!)
curl -s -X POST http://localhost:4000/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'
```

## Explanation

GraphQL концентрирует трафик в одной точке (`POST /graphql`), поэтому
классические правила «путь + параметр» не работают: анализировать нужно
**содержимое запроса**. Что детектируется:

1. **Introspection в production**: `__schema`, `__type`, `__typename`
    в запросе от внешнего клиента.
2. **Батчинг**: тело запроса — JSON-массив операций; число операций
    в одном HTTP-запросе.
3. **Тяжёлые запросы**: глубина вложенности, число алиасов одного поля,
    `query` с десятками полей; признак — резкий рост времени ответа
    и нагрузки на БД.
4. **Перебор идентификаторов**: серия запросов с инкрементными `id`
    в аргументах (GraphQL-вариант IDOR/BOLA).
5. **Мутации без идемпотентности**: повторяющиеся `createX` от одной сессии.
6. **Ошибки резолверов**: стектрейсы в ответе (утечка внутренних имён и SQL).

Для детекта включите логирование тела запроса (или хотя бы хеша операции
и имени операции) и persisted queries — тогда аномалии видны по именам
операций, а не по «сырому» тексту.

## Detection

Минимальный набор полей в логе API-шлюза: `operation_name`, `query_depth`,
`alias_count`, `batch_size`, `variables` (без значений секретов),
`duration_ms`, `status`, `user_id`, `source_ip`.

Практические эвристики:

* `query_depth > 8` или `alias_count > 20` — аномалия;
* `batch_size > 1` при отсутствии явной поддержки батчинга;
* `__schema`/`__type` от внешнего IP;
* рост `duration_ms` в 5+ раз для одной операции;
* > 20 запросов к одной операции с разными `id` от одной сессии за минуту.

## Remediation

- Отключить introspection в production; не полагаться на это как на защиту.
- Лимиты: глубина, сложность (стоимость) запроса, число алиасов, размер тела,
  таймаут резолверов.
- Запрет батчинга или отдельный лимит на операции в батче; rate limiting
  по операциям, а не по HTTP-запросам.
- Авторизация на каждом резолвере + проверка владения объектом (BOLA).
- Persisted queries (allowlist операций) для публичных клиентов.
- Ошибки: общий текст клиенту, детали в лог.
- Мониторинг: аномалии глубины/алиасов, перебор `id`, всплеск ошибок
  авторизации.


## Detection rules

```yaml
title: "Злоупотребление GraphQL: introspection, батчинг или аномально тяжёлый запрос"
id: b2c3d4e5-0008-4b2c-8d3e-000000000108
status: experimental
description: >-
  Признаки разведки схемы и ресурсных атак через GraphQL-эндпоинт. Поля
  специфичны для логов API-шлюза: замените имена на фактические.
references:
  - https://attack.mitre.org/techniques/T1595/002/
  - payloads/web/logic/graphql-introspection-batching.md
logsource:
  category: application
  product: graphql
  definition: 'логи API-шлюза с полями operation_name, query_depth, batch_size'
detection:
  introspection:
    request_path|endswith: '/graphql'
    query_text|contains:
      - '__schema'
      - '__type('
      - '__typename'
  batching:
    request_path|endswith: '/graphql'
    batch_size|gt: 5
  heavy:
    request_path|endswith: '/graphql'
    query_depth|gt: 8
  aliases:
    request_path|endswith: '/graphql'
    alias_count|gt: 20
  condition: introspection or batching or heavy or aliases
fields:
  - source_ip
  - user_id
  - operation_name
  - query_depth
  - batch_size
  - duration_ms
falsepositives:
  - внутренняя разработка и инструменты типа GraphQL Playground (выносите по user_id/IP)
level: medium
tags:
  - attack.reconnaissance
  - attack.t1595.002
  - attack.impact
```
