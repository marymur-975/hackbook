---
id: http-request-smuggling-te-te
title: "HTTP request smuggling: TE.TE (обфускация Transfer-Encoding)"
type: http
target: http
category: web
difficulty: expert
bypass: waf
tags: [http, smuggling, te-obfuscation, desync]
tested_on: ["nginx/haproxy/uWSGI исторические версии"]
success_rate: 0.2
risk: critical
cwe: "CWE-444"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/research/browser-powered-desync-attacks"
graph:
  - target: "http-request-smuggling"
    type: instance_of
  - target: "waf-bypass"
    type: technique_of
  - target: "headers"
    type: related_to
---

# HTTP request smuggling: TE.TE (обфускация Transfer-Encoding)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-encoding: identity
Transfer-Encoding:\tchunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked
```

## Explanation

Когда и frontend, и backend поддерживают chunked, desync возникает из-за
**неодинаковой нормализации** заголовка `Transfer-Encoding`. Один компонент
принимает заголовок за валидный, другой — нет, и переходит на `Content-Length`.
Рабочие обфускации:

- пробел перед двоеточием: `Transfer-Encoding : chunked`
- таб вместо пробела после двоеточия
- перенос строки (obs-fold): `Transfer-Encoding:\r\n chunked`
- неизвестное значение: `chunked, cow` / `xchunked`
- дублированные заголовки с разными значениями
- регистр: `transfer-ENCODING`
- HTTP/2-специфика: псевдозаголовок `:method`/`content-length` при downgrade

Это же семейство включает «client-side desync» (CSD) и HTTP/2-контрабанду,
описанные в исследовании Browser-Powered Desync Attacks (2023).

## Detection

1. Переберите 8–12 вариантов TE-заголовка с тайминг-анализом
   (Burp Request Smuggler делает это автоматически).
2. Признак: часть вариантов даёт зависание/таймаут, часть — мгновенный ответ.
3. CSD: запрос, после которого следующий ответ принадлежит чужому запросу
   (проверяется только на своей инфраструктуре!).
4. Логи прокси: 400/501 на нестандартных TE-заголовках — повод проверить пару.

## Remediation

- Строгая валидация заголовков: отклонять obs-fold, пробелы перед `:`,
  дублированные TE, неизвестные значения (RFC 7230 §3.3.3, 9.5).
- Отключить downgrade HTTP/2 → HTTP/1.1 к backend, либо нормализовать
  `Content-Length`/TE при переходе.
- Обновить все компоненты цепочки (CVE-2021-43791-класс, CVE-2023-44487).
- Не переиспользовать соединения между слоями с разными парсерами.
- Тестировать пару frontend/backend в CI специализированным сканером.

## Detection rules

```yaml
title: Request smuggling TE.TE — обфускация Transfer-Encoding
id: e5f6a7b8-0094-4e5f-9a7b-000000000094
status: experimental
description: >-
  Значение Transfer-Encoding намеренно искажено (таб/пробел после chunked,
  «chunked, identity», xchunked, несколько TE-заголовков), чтобы один из
  серверов цепи проигнорировал TE и переключился на Content-Length.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/request-smuggling
logsource:
  category: proxy
  definition: 'журнал HTTP-шлюза с сырым значением Transfer-Encoding'
detection:
  selection:
    transfer_encoding|contains:
      - "chunked\t"
      - "chunked "
      - 'chunked,'
      - 'chunked;'
      - 'xchunked'
      - 'identity'
      - "chunked\r"
  condition: selection
fields:
  - source_ip
  - method
  - path
  - transfer_encoding
  - status
falsepositives:
  - практически отсутствуют: корректный TE всегда ровно «chunked» без хвостов
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - attack.t1027
  - cwe.444
```
