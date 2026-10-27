---
id: detection-stored-blind-xss-in-logs
title: "Детект stored и blind XSS: разметка в сохранённых данных и логах"
type: xss
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [detection, sigma, xss, blind-xss, log-analysis]
tested_on: ["application DB audit", "SIEM log viewers", "vuln-hub /echo"]
success_rate: 0.65
risk: low
cwe: "CWE-79"
lab: "labs/web-labs/vuln-hub"
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
---

# Детект stored и blind XSS: разметка в сохранённых данных и логах

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# воспроизведение: сохранение вектора в данные и его поиск в логах
python3 tools/lib/http_fetch.py "http://localhost:8090/echo?q=%3Csvg%20onload%3Dalert(1)%3E" 6 GET
python3 tools/lib/http_fetch.py http://localhost:8090/logs
```

## Explanation

Reflected XSS видно сразу (вектор в ответе), а stored и blind XSS
проявляются позже и в другом месте — в админ-панели, в SIEM, в отчёте.
Поэтому детект строится на **поиске разметки там, где её быть не должно**:

1. В сохранённых пользовательских данных: поля профиля, комментарии,
    имена файлов, описания задач — ищите `<script`, `onerror=`, `onload=`,
    `javascript:`, `data:text/html`, `<svg`, `<iframe`, `<img src=`.
2. В логах: те же маркеры в полях `user_agent`, `referer`, `query`,
    `username`, `filename` (см. `headers-user-agent-log-injection`).
3. В исходящих письмах и отчётах: вектор, прошедший через шаблон.
4. Поведенческий признак: запросы с маркерами callback-платформ
    (`burpcollaborator`, `interact.sh`, `xss.ht`, `ezssrf`, `pipedream`)
    в параметрах и заголовках.

Отдельно стоит детектировать **места вывода**: любой интерфейс, который
рендерит пользовательские данные без экранирования (админ-панели,
дашборды, тикет-системы), — это и есть точка исполнения blind XSS.
Проверка CSP на внутренних панелях — такая же обязательная мера,
как и на публичных страницах.

## Detection

Практический приём: периодический скан БД и логов на HTML-маркеры
в полях, которые должны содержать обычный текст. Запрос-пример для
SQL-хранилища:

```sql
SELECT id, field FROM user_content
 WHERE field LIKE '%<script%' OR field LIKE '%onerror=%'
    OR field LIKE '%onload=%' OR field LIKE '%javascript:%';
```

Правило ниже рассчитано на логи приложения/WAF; для сканирования БД
сделайте отдельную задачу по расписанию и алерт на любую находку.

## Remediation

- Экранирование на выводе в каждом контексте; санитайзер с whitelist
  (DOMPurify/bleach), если разметка разрешена.
- CSP на всех страницах, включая внутренние панели: `script-src 'self'`,
  `object-src 'none'`, Trusted Types где поддерживается.
- Хранить пользовательский контент отдельно от разметки; рендерить через
  компоненты, а не подстановкой строки.
- Валидация на входе (charset/структура) как дополнительный слой.
- Мониторинг: алерт на HTML-маркеры в полях и логах, на callback-домены
  в параметрах.
- Регулярный przegląd внутренних интерфейсов: они реже тестируются,
  но исполняют тот же пользовательский ввод.


## Detection rules

```yaml
title: HTML/JS-маркеры в пользовательских данных или логах (stored/blind XSS)
id: b2c3d4e5-0006-4b2c-8d3e-000000000106
status: experimental
description: >-
  Появление исполняемой разметки в полях, которые должны содержать обычный текст:
  параметры запросов, заголовки, имена пользователей и файлов, содержимое форм.
references:
  - https://attack.mitre.org/techniques/T1059/007/
  - payloads/web/xss/stored-in-profile.md
logsource:
  category: webserver
  definition: 'access-лог с query-строкой и заголовками'
detection:
  markup:
    cs-uri-query|contains:
      - '<script'
      - '<svg'
      - '<img'
      - '<iframe'
      - 'onerror='
      - 'onload='
      - 'ontoggle='
      - 'onfocus='
      - 'javascript:'
      - 'data:text/html'
  ua_marker:
    cs-user-agent|contains:
      - '<script'
      - '<svg'
      - 'onerror='
      - 'javascript:'
  callback_platform:
    cs-uri-query|contains:
      - 'burpcollaborator'
      - 'interact.sh'
      - 'xss.ht'
      - 'oastify'
      - 'pipedream'
  condition: markup or ua_marker or callback_platform
fields:
  - c-ip
  - cs-uri-stem
  - cs-uri-query
  - cs-user-agent
falsepositives:
  - легитимные значения с угловыми скобками (math-формулы, фрагменты кода в поиске)
  - собственные сканеры безопасности — выносите их IP в исключения
level: medium
tags:
  - attack.initial_access
  - attack.t1059.007
  - cwe.79
```
