---
id: http-web-cache-poisoning-unkeyed
title: "Web cache poisoning: неключевые заголовки и параметры"
type: http
target: http
category: web
difficulty: advanced
bypass: none
tags: [cache-poisoning, headers, cdn, unkeyed-inputs]
tested_on: ["Varnish", "Cloudflare/Akamai-подобные кеши", "nginx proxy_cache"]
success_rate: 0.3
risk: high
cwe: "CWE-525"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/web-cache-poisoning"
graph:
  - target: "cache-poisoning"
    type: instance_of
  - target: "headers"
    type: related_to
  - target: "xss"
    type: leads_to
  - target: "open-redirect"
    type: leads_to
---

# Web cache poisoning: неключевые заголовки и параметры

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
GET / HTTP/1.1
Host: target
X-Forwarded-Host: attacker.tld
X-Forwarded-Scheme: nohttps
X-Original-URL: /admin
```

## Explanation

Кеш формирует ключ из части запроса (обычно host + path + выбранные query-параметры).
Всё, что **не входит в ключ**, но влияет на ответ, — вектор отравления:
подставив значение один раз, вы заставляете кеш раздавать его всем пользователям.

Типовые неключевые входы:

- заголовки `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Port`,
  `X-Original-URL`, `X-Rewrite-URL`, `X-Host`
- `Cookie` (если не входит в ключ) и `Authorization`
- query-параметры, не включённые в ключ кеша (`?utm_*`, `?lang`)
- тело POST при кешировании GET-ответа, построенного на предыдущем состоянии
- заголовки, добавляемые самим прокси

Отравленный ответ может содержать ссылку на вредоносный JS (массовый XSS),
302-редирект на фишинг или подменённый `Content-Type`.

## Detection

1. Найдите отражение: подставьте уникальный маркер в каждый заголовок
   (Burp «Param Miner» делает это автоматически) и поищите его в ответе.
2. Определите ключ кеша: повторяющиеся запросы с разным `X-Forwarded-Host` —
   меняется ли `X-Cache: HIT/MISS` и содержимое.
3. Проверьте `Cache-Control`, `Vary` (если заголовка нет в `Vary`, он неключевой).
4. Подтверждение: добейтесь `X-Cache: HIT` с вашим маркером в теле ответа.
Только на своей инфраструктуре — отравление кеша задевает реальных пользователей.

## Remediation

- Не строить абсолютные URL и ссылки из `Host`/`X-Forwarded-*` — фиксированный
  base URL из конфигурации.
- Включать в ключ кеша всё, что влияет на ответ, либо отбрасывать эти заголовки
  на границе; настроить `Vary` корректно.
- Перезаписывать `X-Forwarded-*` своим reverse proxy (не доверять клиентским).
- Отключить кеширование для персонализированных ответов (`Cache-Control: private,
  no-store`) и для путей с `Cookie`/`Authorization`.
- Ограничить TTL и мониторить аномалии: один и тот же URL с разными заголовками.
- Тестировать конфигурацию кеша при каждом изменении инфраструктуры.

## Detection rules

```yaml
title: Web cache poisoning — unkeyed-заголовки в закэшированном ответе
id: e5f6a7b8-0096-4e5f-9a7b-000000000096
status: experimental
description: >-
  Ответ, ушедший в общий кэш (HIT), сформирован с участием заголовков, не
  входящих в ключ кэша: X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL.
  Атакующий отравляет кэш для всех пользователей.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/web-cache-poisoning
logsource:
  category: proxy
  definition: 'журнал кэширующего прокси с unkeyed-заголовками и cache_status'
detection:
  cache_hit:
    cache_status: HIT
  unkeyed_header:
    x_forwarded_host|contains: '.'
  unkeyed_scheme:
    x_forwarded_scheme|contains: 'http'
  filter_own_host:
    x_forwarded_host|contains: 'corp.lab'
  condition: cache_hit and (unkeyed_header or unkeyed_scheme) and not filter_own_host
fields:
  - source_ip
  - path
  - x_forwarded_host
  - x_forwarded_scheme
  - cache_status
falsepositives:
  - легитимные CDN-заголовки от своих балансировщиков (исключайте по source_ip)
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.525
```
