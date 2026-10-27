---
id: nosql-mongodb-where-js
title: "MongoDB: выполнение JS через $where / $function / $accumulator"
type: nosql
target: mongodb
category: web
difficulty: advanced
bypass: none
tags: [nosql, mongodb, javascript, rce-adjacent]
tested_on: ["MongoDB 4.4 (javascriptEnabled)", "MongoDB 6.0"]
success_rate: 0.35
risk: critical
cwe: "CWE-943"
lab: null
last_verified: "2026-10-23"
references:
  - "https://www.mongodb.com/docs/manual/reference/operator/query/where/"
graph:
  - target: "nosql"
    type: instance_of
  - target: "dos"
    type: leads_to
  - target: "info-disclosure"
    type: leads_to
---

# MongoDB: выполнение JS через $where / $function / $accumulator

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"$where": "sleep(3000)"}
```

## Explanation

`$where` принимает строку JavaScript и выполняет её на сервере для каждого
документа; `$function`/`$accumulator` (aggregation, MongoDB ≥ 4.4) позволяют
передать произвольное JS-тело функции. Если пользовательское значение попадает
в позицию, где допустим оператор, атакующий получает:

- временной канал (`sleep(N)`) — подтверждение инъекции;
- чтение полей документа (`this.password`) и их сравнение посимвольно;
- высокую нагрузку на сервер (JS выполняется без индексов) — фактически DoS.

Полноценного RCE это не даёт: серверный JS-движок MongoDB изолирован
и не имеет доступа к ФС/сети (в отличие от `$function` в старых сборках
с включённым `--noscripting=false`).

## Detection

1. Отправьте `{"$where": "sleep(3000)"}` и измерьте время ответа.
2. В логах MongoDB: `command` с `$where`, `Slow query` на JS-фильтрах.
3. В коде приложения ищите конкатенацию строк в `$where` и `mapReduce`.

## Remediation

- Запретить серверный JS, если он не нужен: `security.javascriptEnabled: false`
  (или запуск mongod с `--noscripting`).
- Никогда не строить `$where`/`mapReduce`/`$function` из пользовательских данных.
- Валидация типа входных значений (строка/число, без объектов).
- Лимиты времени запросов и пула соединений; алерты на медленные JS-запросы.

## Variants

```
{"$where": "this.username == \"admin\" && this.role == \"admin\""}
```

```
{"$function": {"body": "function(){ return true }", "args": [], "lang": "js"}}
```

## Detection rules

```yaml
title: NoSQL — JavaScript-инъекция через $where (time-based и логические бомбы)
id: e5f6a7b8-0076-4e5f-9a7b-000000000076
status: experimental
description: >-
  Оператор $where выполняет произвольный JavaScript на стороне MongoDB:
  sleep(3000) для слепой проверки, this.password для перебора. Видно и в
  query-строке (%24where), и в теле запроса.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: application
  definition: 'логи приложения с телом запроса + access-лог'
detection:
  selection_body:
    request_body|contains:
      - '$where'
      - 'function()'
      - 'this.password'
      - 'sleep(3000)'
  selection_query:
    cs-uri-query|contains:
      - '$where'
      - '%24where'
      - 'sleep(3000)'
  condition: selection_body or selection_query
fields:
  - source_ip
  - request_path
  - request_body
  - duration_ms
falsepositives:
  - легитимные map-reduce с $where практически не встречаются из внешних запросов
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.943
```
