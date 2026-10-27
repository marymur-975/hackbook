---
id: ssti-jinja2-detection
title: "SSTI (Jinja2): безопасная диагностика и математический тест"
type: ssti
target: python
category: web
difficulty: intermediate
bypass: none
tags: [ssti, jinja2, python, detection]
tested_on: ["Jinja2 3.x", "Flask"]
success_rate: 0.7
risk: medium
cwe: "CWE-1336"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/server-side-template-injection"
graph:
  - target: "ssti"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "fingerprinting"
    type: leads_to
---

# SSTI (Jinja2): безопасная диагностика и математический тест

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{{7*7}}
```

## Explanation

Первый шаг — отличить шаблонизацию на сервере от простого отражения.
Отправьте `{{7*7}}`: если в ответе `49` (а не литерал) — выражение вычислено на сервере.
Дальше определяют движок: `{{7*'7'}}` даст `7777777` в Jinja2 (повтор строки)
и ошибку/`49` в Twig/других. `${7*7}` — Java (Freemarker/Velocity), `#{7*7}` — Ruby/Thymeleaf,
`{{constructor}}` — JS-шаблоны (Angular, Handlebars).
Важно: тестировать нужно в разных контекстах (тело письма, имя в отчёте, страница ошибки).

## Detection

1. Внедрите безобидные маркеры: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
2. Сравните с ожидаемым литералом.
3. Инструменты: `tplmap`, Burp-расширения для SSTI.
Типовые точки: пользовательское имя в письме, тема/шаблон отчёта, страница 404 с параметром.

## Remediation

- Никогда не собирать шаблон из пользовательских данных: шаблон — код, данные — контекст.
- Если пользовательская разметка нужна — песочница: Jinja2 `SandboxedEnvironment`,
  ограничение атрибутов, запрет `__globals__`.
- Рендерить пользовательские шаблоны в отдельном процессе без доступа к ФС/сети.
- Логировать факт компиляции шаблона из пользовательского ввода.

## Variants

```
{{7*'7'}}
```

```
${7*7}
```

```
<%= 7*7 %>
```

```
#{7*7}
```

```
{{config}}
```
