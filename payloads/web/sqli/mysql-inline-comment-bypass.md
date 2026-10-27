---
id: sqli-mysql-inline-comment-bypass
title: "MySQL: обход фильтрации через inline-комментарии /*!...*/"
type: sqli
target: mysql
category: web
difficulty: intermediate
bypass: waf
tags: [sqli, mysql, waf-bypass, comments]
tested_on: ["MySQL 5.7", "MySQL 8.0", "SQLite 3.40 (sqli-lab)"]
success_rate: 0.75
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
  - target: "waf-bypass"
    type: technique_of
---

# MySQL: обход фильтрации через inline-комментарии /*!...*/

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
/*!50000UNION*/ /*!50000SELECT*/ 1,2,3 -- -
```

## Explanation

MySQL-специфичные «версионные» комментарии `/*!NNNNN ... */` исполняются сервером,
но многими WAF и регулярными фильтрами воспринимаются как обычный SQL-комментарий.
Число `50000` — минимальная версия сервера, для которой код внутри комментария активен.
Разбиение ключевых слов ломает сигнатуры вида `UNION SELECT`.

## Detection

Сравните поведение на `UNION SELECT` (блокируется) и `/*!UNION*/ /*!SELECT*/` (проходит).
Если первый вариант даёт 403, а второй — обычный ответ, фильтр обходится.

## Remediation

- WAF: правила, нормализующие MySQL-комментарии перед сопоставлением.
- Главное — параметризация: WAF снижает риск, но не устраняет его.
- Мониторинг аномальных запросов с `/*!` в параметрах.

## Variants

```
/*!UNION*/+/*!SELECT*/+1,2
```

```
UN/**/ION SE/**/LECT 1,2
```
