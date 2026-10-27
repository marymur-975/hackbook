---
id: http-h2-cl-desync
title: "HTTP/2: десинхронизация через псевдозаголовки и downgrade"
type: http
target: http/2
category: web
difficulty: expert
bypass: waf
tags: [http2, smuggling, desync, downgrade]
tested_on: ["frontend с HTTP/2 + backend HTTP/1.1 (исторические CVE)"]
success_rate: 0.2
risk: critical
cwe: "CWE-444"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/research/browser-powered-desync-attacks"
  - "https://portswigger.net/research/http2"
graph:
  - target: "http-request-smuggling"
    type: instance_of
  - target: "headers"
    type: related_to
  - target: "dos"
    type: leads_to
  - target: "waf-bypass"
    type: technique_of
---

# HTTP/2: десинхронизация через псевдозаголовки и downgrade

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
:method: GET
:path: /\r\nTransfer-Encoding: chunked
content-length: 0
foo: bar\r\n\r\nGET /admin HTTP/1.1
```

## Explanation

HTTP/2 передаёт запрос бинарными фреймами, но многие frontend'ы конвертируют
его в HTTP/1.1 для backend'а. На этом стыке возникают уникальные desync'и:

- **H2.CL**: frontend считает длину по `content-length`, backend — по фактическому
  DATA-фрейму; лишние байты становятся новым запросом.
- **H2.TE**: в HTTP/2 заголовок `Transfer-Encoding` запрещён, но если frontend
  его пропускает при конвертации, backend включает chunked-парсинг.
- **инъекция CRLF в псевдозаголовки** (`:path`, `:authority`) — если frontend
  не валидирует `\r\n`, при конвертации получается новый заголовок или запрос.
- **client-side desync (CSD)**: браузер «дочитывает» ответ, не соответствующий
  фрейму, и рассинхронизируется с сервером.
- **CONTINUATION flood** (CVE-2024-27983-класс): бесконечные CONTINUATION-фреймы
  истощают память frontend'а.

Практический вывод: HTTP/2 не отменяет smuggling, а добавляет новые векторы.

## Detection

1. Определите, что frontend говорит по H2 (`curl -I --http2`), а backend — 1.1
   (видно по заголовкам/ошибкам).
2. Burp Suite: «HTTP/2 request smuggling»-расширение, режимы H2.CL / H2.TE.
3. Попробуйте вставить `\r\n` в `:path` и посмотрите, не появится ли новый заголовок.
4. Логи: 400 на запросах с `transfer-encoding` в H2, аномальные CONTINUATION.

## Remediation

- Не понижать версию протокола к backend без строгой нормализации; лучше
  HTTP/2 или HTTP/1.1 end-to-end.
- Валидировать псевдозаголовки: запрет CR/LF и управляющих символов в `:path`,
  `:authority`, `:method` (RFC 9113 §8.3).
- Отклонять `Transfer-Encoding` в HTTP/2-запросах.
- Лимит числа CONTINUATION-фреймов и размера заголовков (HPACK-лимиты).
- Обновлять nginx/HAProxy/Envoy/Apache: почти все H2-smuggling CVE закрыты
  в релизах 2023–2024 гг.
- Тестировать связку специализированным сканером при каждом обновлении прокси.

## Detection rules

```yaml
title: HTTP/2 desync — CL и TE одновременно или два Content-Length
id: e5f6a7b8-0084-4e5f-9a7b-000000000084
status: experimental
description: >-
  В HTTP/2 запрещены Transfer-Encoding и несколько Content-Length, но
  промежуточные серверы иногда транслируют их в HTTP/1.1 бэкенду — основа
  h2.cl/h2.te desync-атак. Признаки: CL+TE в одном запросе, count(CL) >= 2.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/research/http2
logsource:
  category: proxy
  definition: 'журнал HTTP-шлюза с числом заголовков CL и значением TE'
detection:
  http2:
    scheme: h2
  cl_with_te:
    content_length_count|gte: 1
    transfer_encoding|contains: 'chunked'
  dual_cl:
    content_length_count|gte: 2
  condition: http2 and (cl_with_te or dual_cl)
fields:
  - source_ip
  - method
  - path
  - content_lengths
  - transfer_encoding
  - status
falsepositives:
  - багованные HTTP-клиенты/библиотеки (постоянный источник — в исключения)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.444
```
