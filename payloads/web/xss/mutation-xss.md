---
id: xss-mutation-xss
title: "Mutation XSS (mXSS): пересборка DOM браузером"
type: xss
target: html
category: web
difficulty: expert
bypass: waf
tags: [xss, mxss, sanitizer-bypass]
tested_on: ["Chrome 120", "класс обходов санитайзеров 2018-2021"]
success_rate: 0.3
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
  - target: "client-side"
    type: category_of
---

# Mutation XSS (mXSS): пересборка DOM браузером

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<listing>&lt;img src=x onerror=alert(1)&gt;</listing>
```

## Explanation

mXSS возникает, когда санитайзер анализирует HTML как строку/DOM, а браузер затем
пересобирает фрагмент (через `innerHTML`), меняя смысл. Классические триггеры:
теги `listing`, `noscript`, `style`, `svg` + `foreignObject`, комментарии внутри атрибутов.
Строка, безопасная на входе, становится исполняемой после нормализации парсером браузера.
Это причина большинства исторических обходов DOMPurify/bleach.

## Detection

1. Проверьте, используется ли `innerHTML` после санитизации.
2. Тестируйте по базам mXSS-векторов (трекер DOMPurify, публикации Cure53).
3. Признак: `&lt;` в ответе превращается в реальный тег после рендера.

## Remediation

- Обновлять DOMPurify/bleach до актуальных версий (mXSS-фиксы).
- Запрет `listing`/`noscript`/`style` в whitelist санитайзера.
- Trusted Types в CSP: `require-trusted-types-for 'script'`.
- Не класть пользовательский HTML в `innerHTML` — использовать безопасные компоненты.

## Variants

```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```
