---
id: sqli-mysql-boolean-blind
title: "MySQL: boolean-based blind (побитовое извлечение данных)"
type: sqli
target: mysql
category: web
difficulty: intermediate
bypass: none
tags: [sqli, mysql, blind, boolean]
tested_on: ["MySQL 8.0", "SQLite 3.40 (sqli-lab)"]
success_rate: 0.8
risk: medium
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

# MySQL: boolean-based blind (побитовое извлечение данных)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
1' AND SUBSTRING((SELECT user()),1,1)='r' -- -
```

## Explanation

Когда ошибки СУБД скрыты, но ответ приложения различается для «истина/ложь»,
данные извлекаются побитово: условие сравнивает очередной символ результата
вложенного `SELECT`. `SUBSTRING(x, N, 1)` — N-й символ; ответ «есть результат» = совпадение.
Бинарный поиск по ASCII сокращает число запросов примерно с 95 до 7 на символ.

## Detection

1. Найдите параметр, где `AND 1=1` и `AND 1=2` дают разные ответы.
2. Зафиксируйте стабильный «эталонный» ответ (длина, наличие строки).
3. Автоматизируйте перебор: `sqlmap --technique=B`.

## Remediation

- Параметризованные запросы: blind-инъекция невозможна без конкатенации.
- Rate limiting и алерты на аномальное число однотипных запросов.
- Не возвращать различимые ответы для «нет данных» и «ошибка запроса».

## Variants

```
1' AND ASCII(SUBSTRING(database(),1,1))>109 -- -
```

```
1 AND (SELECT COUNT(*) FROM information_schema.tables)>0 -- -
```
