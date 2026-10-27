---
id: sqli-mysql-like-wildcard
title: "MySQL: wildcard-инъекция в LIKE (обход поиска/фильтра)"
type: sqli
target: mysql
category: web
difficulty: beginner
bypass: filter
tags: [sqli, mysql, like, wildcard]
tested_on: ["MySQL 8.0"]
success_rate: 0.7
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

# MySQL: wildcard-инъекция в LIKE (обход поиска/фильтра)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
%' OR '1'='1
```

## Explanation

В контексте `LIKE '%...%'` символы `%` и `_` — метасимволы шаблона, а не строковые.
Даже при корректном экранировании кавычек пользователь управляет шаблоном:
`%` возвращает все строки, `_` заменяет один символ. Это ломает логику поиска,
раскрывает данные и создаёт нагрузку на БД.

## Detection

Отправьте `%` и `____` в поле поиска и сравните число результатов.
Если `%` возвращает всю таблицу — шаблон формируется из пользовательских данных
без экранирования.

## Remediation

- Экранировать `%`, `_` и `\` через `ESCAPE '\'` в запросе.
- Параметризованный `LIKE CONCAT('%', ?, '%')`.
- Ограничивать длину поисковой строки и число результатов.

## Variants

```
%%
```

```
admin%
```

```
_dmin
```
