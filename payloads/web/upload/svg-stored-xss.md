---
id: upload-svg-stored-xss
title: "Загрузка SVG: stored XSS и SSRF/XXE в конвертере"
type: upload
target: svg
category: web
difficulty: intermediate
bypass: none
tags: [file-upload, svg, xss, xxe, ssrf]
tested_on: ["браузеры Chrome/Firefox", "ImageMagick", "librsvg", "wkhtmltoimage"]
success_rate: 0.6
risk: high
cwe: "CWE-79"
lab: "labs/web-labs/upload-lab"
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "file-upload"
    type: instance_of
  - target: "xss"
    type: leads_to
  - target: "xxe"
    type: leads_to
  - target: "ssrf"
    type: leads_to
---

# Загрузка SVG: stored XSS и SSRF/XXE в конвертере

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <text x="10" y="20">hackbook</text>
</svg>
```

## Explanation

SVG — это XML+HTML-гибрид: он поддерживает `<script>`, обработчики событий
(`onload`, `onerror`), `foreignObject` и внешние ссылки. Загруженный как
«изображение» SVG:

1. **Stored XSS** — если он отдаётся с `Content-Type: image/svg+xml` и открывается
    в контексте домена (в новой вкладке, в `<object>`, в `<iframe>` без sandbox),
    скрипт исполняется в origin сайта. `<img src=x.svg>` скрипт не выполняет,
    но прямая навигация — выполняет.
2. **XXE** — серверный конвертер (ImageMagick, librsvg, Inkscape, PDF-рендер)
    парсит DTD и читает локальные файлы (см. `xxe-svg-upload-vector`).
3. **SSRF** — `<image href="http://169.254.169.254/...">` заставляет конвертер
    сделать внутренний запрос.
4. **Отравление кеша/фишинг** — SVG с редиректом или подменённым содержимым.

Отдельный подкласс — SVG-полиглот с встроенным HTML/JS, который проходит
проверку «это изображение».

## Detection

1. Загрузите SVG с `onload=alert(document.domain)` и откройте его по прямой ссылке.
2. Проверьте `Content-Type` и `Content-Disposition` в ответе.
3. Проверьте серверную конвертацию: SVG с `<image href="http://ваш-collaborator">` —
   пришёл ли запрос (SSRF/XXE).
4. В логах: исходящие запросы от воркера конвертации, чтение локальных файлов.
5. Проверьте, открывается ли SVG в `<iframe>` без `sandbox`.

## Remediation

- Санитизация SVG (DOMPurify с `USE_PROFILES: {svg: true, svgFilters: false}`,
  удаление скриптов, `onload`, внешних ссылок, `foreignObject`).
- Либо конвертация в растр (PNG/WebP) — скрипты исчезают физически.
- Отдавать с `Content-Disposition: attachment` и/или с отдельного
  cookie-less домена (`usercontent.example.com`).
- `X-Content-Type-Options: nosniff`, CSP `object-src 'none'`, `script-src 'self'`.
- Конвертер: изолированный воркер без доступа к ФС и сети (egress закрыт),
  ImageMagick `policy.xml` с запретом MSVG/URL/`@`.
- Не показывать загруженные SVG inline в админ-панели (blind XSS).

## Variants

```
<svg><script>alert(document.domain)</script></svg>
```

```
<svg><foreignObject><body onload=alert(1)></foreignObject></svg>
```

```
<svg><image href="http://169.254.169.254/latest/meta-data/"/></svg>
```

## Detection rules

```yaml
title: Stored XSS через загруженный SVG — onload/script внутри «картинки»
id: e5f6a7b8-0060-4e5f-9a7b-000000000060
status: experimental
description: >-
  Загруженный SVG содержит обработчики событий (onload, onerror, animate
  onbegin) или script — при встраивании картинки в страницу код выполняется
  в контексте домена приложения.
references:
  - https://attack.mitre.org/techniques/T1189/
logsource:
  category: application
  definition: 'логи загрузок с превью содержимого (SVG — текстовый формат)'
detection:
  svg_upload:
    event_action: file_upload
    filename|endswith: '.svg'
  script_in_svg:
    file_preview|contains:
      - 'onload='
      - '<script'
      - 'onerror='
      - 'onbegin='
      - 'javascript:'
      - '<animate'
      - '<foreignObject'
  condition: svg_upload and script_in_svg
fields:
  - source_ip
  - filename
  - file_preview
falsepositives:
  - интерактивные SVG-иллюстрации легитимных дизайнов (редко содержат script/onload)
level: high
tags:
  - attack.persistence
  - attack.t1189
  - cwe.79
```
