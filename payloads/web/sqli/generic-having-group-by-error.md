---
id: sqli-generic-having-group-by-error
title: "Общее: HAVING/GROUP BY для перечисления колонок по ошибкам"
type: sqli
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [sqli, error-based, enumeration]
tested_on: ["MySQL 5.7", "MSSQL 2019"]
success_rate: 0.6
risk: low
cwe: "CWE-89"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://portswigger.net/web-security/sql-injection"
graph:
  - target: "sqli"
    type: instance_of
  - target: "info-disclosure"
    type: leads_to
---

# Общее: HAVING/GROUP BY для перечисления колонок по ошибкам

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' HAVING 1=1 -- -
```

## Explanation

`HAVING` без `GROUP BY` вызывает ошибку, в которой СУБД перечисляет колонки запроса:
`Column 'users.id' is invalid in the select list...`. Добавляя колонки в `GROUP BY`
по одной, можно восстановить полный список полей таблицы без UNION и без
`information_schema`. Работает только при видимых ошибках СУБД.

## Detection

В ответах ищите `is invalid in the select list`, `must appear in the GROUP BY clause`,
`In aggregated query without GROUP BY`.

## Remediation

- Отключить вывод ошибок СУБД.
- Параметризация.
- Единый формат ответа для «нет данных» и «ошибка».

## Variants

```
' GROUP BY id -- -
```

```
' GROUP BY id,login -- -
```
