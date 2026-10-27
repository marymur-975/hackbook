---
id: xss-attribute-breakout-double-quote
title: "XSS: выход из атрибута (двойная кавычка)"
type: xss
target: html
category: web
difficulty: beginner
bypass: filter
tags: [xss, attribute, breakout]
tested_on: ["Chrome 120"]
success_rate: 0.85
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
---

# XSS: выход из атрибута (двойная кавычка)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
" autofocus onfocus=alert(document.domain) x="
```

## Explanation

Когда значение попадает внутрь атрибута (`<input value="ПОЛЬЗОВАТЕЛЬ">`), достаточно
закрыть кавычку и добавить собственный обработчик события. `autofocus onfocus=`
срабатывает без клика пользователя — удобно для PoC. Хвост `x="` «съедает» остаток
оригинального тега, сохраняя валидность HTML.

## Detection

Проверьте контекст: отражается ли значение внутри атрибута и экранируется ли `"`.
Отправьте `"` — если в ответе появилась «голая» кавычка, breakout возможен.

## Remediation

- Экранировать атрибуты: `&quot;`, `&#x27;`, `&#x60;`.
- Использовать API шаблонизатора для атрибутов, а не конкатенацию.
- CSP без `unsafe-inline` блокирует inline-обработчики (`onfocus=`).
- Whitelist-валидация значений, отражаемых в HTML.

## Variants

```
' autofocus onfocus=alert(1) x='
```

```
" onmouseover="alert(1)
```

```
" onerror="alert(1)
```
