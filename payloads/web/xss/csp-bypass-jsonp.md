---
id: xss-csp-bypass-jsonp
title: "XSS: обход CSP через разрешённый JSONP/CDN-эндпоинт"
type: xss
target: html
category: web
difficulty: advanced
bypass: waf
tags: [xss, csp, bypass, jsonp]
tested_on: ["CSP script-src 'self' *.googleapis.com"]
success_rate: 0.4
risk: high
cwe: "CWE-79"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/xss/"
  - "https://portswigger.net/web-security/cross-site-scripting"
graph:
  - target: "xss"
    type: instance_of
  - target: "waf-bypass"
    type: technique_of
  - target: "csp"
    type: related_to
---

# XSS: обход CSP через разрешённый JSONP/CDN-эндпоинт

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert"></script>
```

## Explanation

Если CSP разрешает домен, на котором есть JSONP-эндпоинт или скрипт с управляемым
callback'ом, политику можно обойти: сервер вернёт `alert(...)` как JS, и он исполнится
в контексте цели. Типичные источники: `*.googleapis.com`, CDN с Angular, старые JSONP-API.
Отдельный класс — `unsafe-eval` + шаблонизаторы.

## Detection

1. Прочитайте заголовок `Content-Security-Policy`.
2. Выпишите разрешённые хосты и найдите на них JSONP (`?callback=`, `?jsonp=`).
3. Инструменты: CSP Evaluator (Google), ручной перебор gadget'ов.

## Remediation

- CSP без wildcard-хостов; `script-src` — точный список + nonce/hash.
- Никаких `unsafe-inline`, `unsafe-eval`, `*`.
- `report-uri`/`report-to` для мониторинга нарушений.
- Убрать JSONP-эндпоинты, перейти на CORS+JSON.
