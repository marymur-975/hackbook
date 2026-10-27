---
id: xss-trusted-types-bypass
title: "Trusted Types и CSP: обходы и типовые ошибки настройки"
type: xss
target: frontend
category: web
difficulty: advanced
bypass: csp
tags: [xss, trusted-types, csp, dompurify, frontend-security]
tested_on: ["Chrome/Chromium (Trusted Types)", "собственные стенды"]
success_rate: 0.35
risk: medium
cwe: "CWE-79"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
  - "https://web.dev/trusted-types/"
  - "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
---

# Trusted Types и CSP: обходы и типовые ошибки настройки

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# ── что защищает Trusted Types ─────────────────────────────────────
# заголовок: Content-Security-Policy: require-trusted-types-for 'script'
# после этого браузер блокирует присваивание «сырой» строки в опасные
# стоки: innerHTML, outerHTML, document.write, eval, setTimeout(string),
# setAttribute('on*'), src у script/iframe и т.п.

# ── типовые обходы и ошибки ────────────────────────────────────────
# 1) политика без enforce: report-only не защищает
#    Content-Security-Policy-Report-Only: require-trusted-types-for 'script'

# 2) неполный список стоков: защита только для 'script', но приложение
#    использует опасные атрибуты/URL-стоки (javascript: в href)
document.location = 'javascript:alert(document.domain)'
location.assign('javascript:alert(document.domain)')

# 3) создание политики с разрешающей фабрикой (ошибка разработчика):
#    trustedTypes.createPolicy('default', { createHTML: s => s })
#    -> любая строка становится «доверенной», защита обнуляется

# 4) обход через DOM-узлы, а не строки: создание элемента и вставка
#    (Trusted Types не покрывает манипуляции с узлами)
const s = document.createElement('script')
s.textContent = 'alert(document.domain)'   // требуется trustedScript
document.body.appendChild(s)

# 5) стоки, не покрытые политикой: Element.setAttribute('formaction', ...),
#    srcdoc у iframe (зависит от версии браузера и настроек)

# 6) устаревшие/сторонние библиотеки, вызывающие innerHTML напрямую:
#    они ломаются в enforce-режиме; «починка» через createPolicy
#    с пропуском строки = обход (см. 3)

# 7) отсутствие sanitize-слоя: DOMPurify без RETURN_TRUSTED_TYPE
#    возвращает строку, которая всё равно блокируется (или, если политика
#    слабая, проходит как есть)

# ── корректная настройка ───────────────────────────────────────────
# Content-Security-Policy:
#   default-src 'self';
#   script-src 'self' https://cdn.example.com;
#   require-trusted-types-for 'script';
#   trusted-types default myPolicy dompurify;
#   report-uri /csp-report
#
# const policy = trustedTypes.createPolicy('default', {
#   createHTML: (input) => DOMPurify.sanitize(input, { RETURN_TRUSTED_TYPE: true }),
#   createScript: () => { throw new Error('eval запрещён'); },
#   createScriptURL: (url) => { if (new URL(url, location).origin === location.origin) return url; throw new Error('bad origin'); }
# });
```

## Explanation

**Trusted Types** — механизм браузера (в первую очередь Chromium),
который делает DOM-XSS структурно невозможным в защищённых стоках:
в `innerHTML`, `document.write`, `eval` и подобные можно передать только
объект «доверенного» типа, созданный через зарегистрированную политику.

Почему это важно: экранирование на выводе требует дисциплины в каждом
месте кода, а Trusted Types превращают пропуск в **исключение в рантайме**
— его видно сразу в отчётах CSP.

Типовые ошибки, из-за которых защита не работает:

1. **Report-Only вместо enforce**: `Content-Security-Policy-Report-Only`
    только сообщает о нарушениях. Для продакшена нужен обычный заголовок
    (report-only полезен на этапе внедрения).
2. **Пропускающая политика по умолчанию**:
    `createPolicy('default', { createHTML: s => s })` — фактически
    отключение защиты. Так часто «чинят» падающие библиотеки.
3. **Неполный охват стоков**: `require-trusted-types-for 'script'`
    покрывает основные, но `javascript:`-URL в `location`/`href` и часть
    атрибутов требуют отдельной CSP-директивы (`script-src` без
    `unsafe-inline`, `navigate-to` где поддерживается) и кодовых проверок.
4. **Манипуляции с узлами** не регулируются Trusted Types: создание
    `<script>`-элемента и присваивание `textContent` требует
    `trustedScript` только в части стоков; часть сценариев остаётся
    достижимой через `srcdoc`, `formaction`, `on*`-атрибуты.
5. **Санитайзер без интеграции**: DOMPurify должен вызываться с
    `RETURN_TRUSTED_TYPE: true` и быть зарегистрированной политикой,
    иначе результат — обычная строка.
6. **Сторонние скрипты** (реклама, аналитика, виджеты) создают свои
    политики или ломаются; `trusted-types`-директива с явным списком
    имён политик ограничивает этот риск.

Практический вывод: Trusted Types — сильный второй слой, но он не
отменяет экранирование и санитизацию. Правильная конфигурация:
`script-src 'self'` (без `unsafe-inline`), `require-trusted-types-for 'script'`,
ограниченный список `trusted-types`, sanитайзер в политике, и мониторинг
`report-uri`.

## Detection

* CSP-отчёты (`report-uri`/`report-to`): сообщения о нарушениях
  Trusted Types — это либо баг, либо попытка атаки. Агрегируйте
  по `document-uri`, `blocked-uri`, `effective-directive`.
* Алерт на всплеск `require-trusted-types-for`-нарушений с одного IP.
* Ревью кода: поиск `createPolicy('default'` с тривиальной фабрикой,
  прямых `innerHTML =` без санитайзера, `eval(`,
  `document.write(`, `setTimeout('...')` со строкой.
* Автоматизация: статический анализ (ESLint-плагины: `no-implied-eval`,
  `no-script-url`, правила DOMPurify) и DAST с проверкой наличия
  заголовков (`require-trusted-types-for`, `script-src` без `unsafe-inline`).
* Рантайм-мониторинг в браузере: перехват `SecurityPolicyViolationEvent`
  и отправка в SIEM через beacon.
* Инвентаризация политик: `trusted-types`-список должен быть коротким
  и задокументированным.

## Remediation

- Включить enforce-режим: `Content-Security-Policy:
  require-trusted-types-for 'script'` (не Report-Only) после обкатки.
- Политики Trusted Types: только санитайзер (DOMPurify с
  `RETURN_TRUSTED_TYPE: true`) и явный запрет `createScript`/`eval`.
- `script-src 'self'` без `unsafe-inline` и `unsafe-eval`; сторонние
  скрипты — с SRI (`integrity`) и из allowlist-доменов.
- Ограничить имена политик: `trusted-types default dompurify myPolicy`.
- Проверять URL-стоки: `createScriptURL` с валидацией origin,
  запрет `javascript:` и `data:` в `href`/`src`/`formaction`.
- Миграция кода: заменить `innerHTML` на `textContent`/DOM API,
  шаблоны с экранированием, компоненты фреймворка.
- Мониторинг CSP-отчётов в SIEM; процесс реагирования на новые нарушения
  (каждое нарушение = потенциальный XSS).
- Тестирование: негативные тесты с попыткой вставить разметку в каждый
  sink; проверка заголовков в CI (DAST/OWASP ZAP baseline).

## Detection rules

```yaml
title: Обход Trusted Types — CSP-отчёты require-trusted-types-for
id: e5f6a7b8-0054-4e5f-9a7b-000000000054
status: experimental
description: >-
  Браузер блокирует присваивание сырой строки в опасный sink (innerHTML и т.п.)
  и шлёт CSP-отчёт с violated_directive require-trusted-types-for. Такие
  отчёты — индикатор XSS-попыток на защищённой странице.
references:
  - https://web.dev/trusted-types/
  - https://attack.mitre.org/techniques/T1189/
logsource:
  category: application
  definition: 'endpoint сбора CSP-отчётов (report-to) с полями violated_directive/blocked_uri'
detection:
  selection:
    event_action: csp_report
    violated_directive|contains: 'trusted-types'
  condition: selection
fields:
  - source_ip
  - violated_directive
  - blocked_uri
falsepositives:
  - собственные легаси-скрипты сайта, не переведённые на Trusted Types
    (постоянный фоновый шум — заведите allowlisted-полиси)
level: medium
tags:
  - attack.initial_access
  - attack.t1189
  - cwe.79
```
