---
id: http-request-smuggling-cl-te
title: "HTTP request smuggling: CL.TE"
type: http
target: http
category: web
difficulty: advanced
bypass: waf
tags: [http, smuggling, cl-te, desync]
tested_on: [" HAProxy + backend с chunked", "классический пример PortSwigger"]
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
  - target: "cache-poisoning"
    type: leads_to
  - target: "waf-bypass"
    type: technique_of
  - target: "auth-bypass"
    type: leads_to
---

# HTTP request smuggling: CL.TE

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
POST / HTTP/1.1
Host: target
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

## Explanation

Frontend (прокси/балансировщик) и backend по-разному решают, где конец тела
запроса: один использует `Content-Length`, другой — `Transfer-Encoding: chunked`.
В CL.TE frontend смотрит на CL и пересылает N байт, а backend читает chunked
и останавливается на терминаторе `0\r\n\r\n`. Всё, что осталось после него
(в примере — `G`), backend считает **началом следующего запроса** в том же
keep-alive соединении.

Последствия: отравление очереди запросов (следующий пользователь получает
ваш ответ), обход контроля доступа ( smuggling запроса к `/admin`),
кража учётных данных через отражение, обход WAF.
Отдельный подвид — CL.TE с использованием неоднозначности парсинга chunk-размера
и расширение `;` в Content-Length.

## Detection

1. Отправьте запрос с «зависшим» хвостом и измерьте время: если backend ждёт
   продолжение chunked-тела — будет таймаут (признак TE-парсинга).
2. Безопасная проверка: два последовательных запроса в одном соединении,
   где первый содержит `0\r\n\r\n` + мусор; если второй ответ сместился —
   desync подтверждён.
3. Инструменты: Burp Suite «HTTP/2 smuggling»- и «Request Smuggler»-расширения,
   `smuggler.py`.
4. Косвенные признаки: разные версии frontend/backend, `Connection: keep-alive`
   между ними, прокси, переписывающие заголовки.

## Remediation

- Отключить connection reuse между прокси и backend (или использовать HTTP/2
  end-to-end с одинаковой трактовкой фреймов).
- Отклонять запросы, содержащие и `Content-Length`, и `Transfer-Encoding`
  (RFC 7230 требует приоритета TE, но safest — 400).
- Отклонять неоднозначные формы: несколько TE-заголовков, TE с расширениями,
  `Content-Length` с пробелами/несколькими значениями, `\r` отдельно от `\n`.
- Единая версия и конфигурация прокси на всех узлах; обновлять HAProxy/nginx/
  Envoy (многие CVE smuggling-класса закрыты в свежих релизах).
- Нормализация запросов на границе: отбрасывать `Transfer-Encoding` при наличии CL.
- Мониторинг аномалий: запросы с обоими заголовками, 400-е от прокси.

## Detection rules

```yaml
title: Request smuggling CL.TE — конфликт Content-Length и Transfer-Encoding
id: e5f6a7b8-0092-4e5f-9a7b-000000000092
status: experimental
description: >-
  HTTP/1.1-запрос несёт и Content-Length, и Transfer-Encoding: chunked —
  фронтенд и бэкенд по-разному определяют границу тела, что позволяет
  протащить «хвост» как начало следующего запроса.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/request-smuggling
logsource:
  category: proxy
  definition: 'журнал HTTP-шлюза: заголовки CL/TE каждого запроса'
detection:
  http1:
    scheme: http/1.1
  cl_te_conflict:
    content_length_count|gte: 1
    transfer_encoding|contains: 'chunked'
  condition: http1 and cl_te_conflict
fields:
  - source_ip
  - method
  - path
  - content_lengths
  - transfer_encoding
  - status
falsepositives:
  - устаревшие клиенты, шлющие оба заголовка постоянно (стабильный источник —
    в исключения, но лучше чинить клиент)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.444
```
