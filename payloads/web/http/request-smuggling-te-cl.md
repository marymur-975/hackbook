---
id: http-request-smuggling-te-cl
title: "HTTP request smuggling: TE.CL"
type: http
target: http
category: web
difficulty: advanced
bypass: waf
tags: [http, smuggling, te-cl, desync]
tested_on: ["backend с chunked-парсером + прокси на CL"]
success_rate: 0.25
risk: critical
cwe: "CWE-444"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/request-smuggling"
graph:
  - target: "http-request-smuggling"
    type: instance_of
  - target: "headers"
    type: related_to
  - target: "waf-bypass"
    type: technique_of
---

# HTTP request smuggling: TE.CL

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
POST / HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

12
GPOST / HTTP/1.1

0

```

## Explanation

Обратный случай: frontend понимает `Transfer-Encoding` (читает chunked до `0`),
а backend игнорирует TE и берёт `Content-Length`. Тогда frontend передаёт весь
кусковый поток, а backend считывает только первые N байт, оставляя «хвост»
в соединении — он становится следующим запросом.
В примере тело объявлено как chunk размером 0x12 (18 байт), внутри которого
лежит целый поддельный запрос `GPOST / HTTP/1.1...`.

TE.CL встречается реже CL.TE (большинство прокси нормализуют TE), но именно он
часто остаётся рабочим после «починки» CL.TE.

## Detection

1. Тайминг-тест: запрос с `Content-Length: 4` и chunked-телом большего размера —
   если ответ приходит мгновенно, backend прочитал только CL.
2. Desync-проба: поддельный второй запрос внутри чанка; сдвиг ответов = уязвимость.
3. Автоматика: Burp «Request Smuggler» (перебор CL.TE / TE.CL / TE.TE / H2-вариантов).

## Remediation

- Те же меры, что и для CL.TE: запрет комбинации CL+TE, единая нормализация,
  отключение reuse соединений между слоями, обновления прокси.
- Проверять ВСЕ пары frontend/backend, включая CDN и внутренние шлюзы:
  desync возникает на стыке, а не в одном компоненте.
- Если применяется HTTP/2 — следить за downgrading в HTTP/1.1 к backend
  (класс CVE-2023-44487 и H2.CL/H2.TE-варианты).

## Detection rules

```yaml
title: Request smuggling TE.CL и аномалии chunked-тела с 4xx/5xx
id: e5f6a7b8-0093-4e5f-9a7b-000000000093
status: experimental
description: >-
  Запросы chunked, которые фронтенд принял, а бэкенд отверг (4xx/5xx) —
  признак расхождения в разборе TE (TE.CL и TE-обфускации). Дополняет
  правило CL.TE со стороны «странных» ответов.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/request-smuggling
logsource:
  category: proxy
  definition: 'журнал HTTP-шлюза: TE, статусы фронтенда и бэкенда'
detection:
  http1:
    scheme: http/1.1
  chunked:
    transfer_encoding|contains: 'chunked'
  backend_reject:
    status|gte: 400
  condition: http1 and chunked and backend_reject
fields:
  - source_ip
  - method
  - path
  - transfer_encoding
  - status
falsepositives:
  - обрывы соединений мобильных клиентов (единичны; серия от одного IP — атака)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.444
```
