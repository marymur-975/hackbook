---
id: sqli-generic-comment-terminators
title: "Общее: терминация запроса комментариями"
type: sqli
target: generic
category: web
difficulty: beginner
bypass: filter
tags: [sqli, comments, syntax, reference]
tested_on: ["MySQL", "PostgreSQL", "MSSQL", "SQLite", "Oracle", "SQLite 3.40 (sqli-lab)"]
success_rate: 0.9
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
  - target: "fingerprinting"
    type: leads_to
---

# Общее: терминация запроса комментариями

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
' -- -
```

## Explanation

Комментарий отбрасывает остаток запроса (проверку пароля, закрывающую кавычку, `LIMIT`).
Синтаксис различается:

| СУБД | Однострочный | Многострочный | Особенность |
|------|--------------|---------------|-------------|
| MySQL/MariaDB | `-- ` (с пробелом), `#` | `/* */` | `/*! ... */` исполняется |
| PostgreSQL | `--` | `/* */` | вложенные `/* */` допустимы |
| MSSQL | `--` | `/* */` | `;` разделяет запросы |
| SQLite | `--` | `/* */` | — |
| Oracle | `--` | `/* */` | нужен `FROM dual` |

`-- -` — универсальная форма: после `--` идёт пробел, затем дефис как наполнитель.

## Detection

Переберите терминации для одного payload'а: если `-- -` работает, а `#` — нет,
это MySQL/MariaDB. Различия в поведении указывают на backend.

## Remediation

- Параметризация устраняет смысл терминации.
- WAF: нормализация комментариев перед анализом.
- Логирование запросов с `--`, `#`, `/*` в параметрах.

## Variants

```
'#
```

```
'/*
```

```
') -- -
```

```
' --+
```
