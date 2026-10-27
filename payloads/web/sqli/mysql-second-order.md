---
id: sqli-mysql-second-order
title: "MySQL: second-order инъекция (отложенное срабатывание)"
type: sqli
target: mysql
category: web
difficulty: advanced
bypass: filter
tags: [sqli, mysql, second-order, stored]
tested_on: ["MySQL 8.0"]
success_rate: 0.5
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
  - target: "auth-bypass"
    type: leads_to
---

# MySQL: second-order инъекция (отложенное срабатывание)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
admin'-- -
```

## Explanation

Полезная нагрузка сохраняется в БД (например, как «имя пользователя» при регистрации),
а исполняется позже — в другом запросе, который подставляет это значение строкой:
`UPDATE users SET password='...' WHERE username='$stored'`.
Классический эффект: смена пароля администратора без знания старого.
Экранирование на входе не помогает, если данные переиспользуются без параметризации.

## Detection

1. Зарегистрируйте пользователя с именем `admin'-- -`.
2. Воспользуйтесь функцией «смена пароля» / «профиль».
3. Проверьте, изменился ли пароль учётки `admin`.

## Remediation

- Параметризовать ВСЕ запросы, включая работающие с сохранёнными данными.
- Валидация имён пользователей на уровне схемы (charset, длина, blacklist).
- Не использовать имя пользователя как ключ в `UPDATE` без подтверждения владения.
