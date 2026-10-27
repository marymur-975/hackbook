---
id: xss-dom-location-hash
title: "DOM-based XSS: источник location.hash"
type: xss
target: javascript
category: web
difficulty: intermediate
bypass: none
tags: [xss, dom, source-sink]
tested_on: ["Chrome 120"]
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
  - target: "client-side"
    type: category_of
---

# DOM-based XSS: источник location.hash

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
#<img src=x onerror=alert(document.domain)>
```

## Explanation

DOM-XSS живёт целиком в браузере: данные из «источника» (`location.hash`,
`location.search`, `document.referrer`, `postMessage`) попадают в «приёмник»
(`innerHTML`, `document.write`, `eval`, `setTimeout(string)`).
Фрагмент после `#` не отправляется на сервер, поэтому серверные логи и WAF такую
уязвимость не видят — анализ только клиентского кода.

## Detection

1. Найдите в JS-бандле небезопасные приёмники (`innerHTML`, `outerHTML`, `document.write`).
2. Проследите путь от `location.*` до приёмника (taint-анализ: Semgrep, CodeQL).
3. Вручную: `#test` — появилось ли `test` в DOM через небезопасный приёмник.

## Remediation

- `textContent` вместо `innerHTML`.
- Фреймворки с экранированием (React: `dangerouslySetInnerHTML` — только с DOMPurify).
- CSP `script-src 'self'` + Trusted Types (`require-trusted-types-for 'script'`).
- Валидация и нормализация URL перед использованием.

## Variants

```
#';alert(document.domain);//
```

```
?q=<svg onload=alert(1)>
```
