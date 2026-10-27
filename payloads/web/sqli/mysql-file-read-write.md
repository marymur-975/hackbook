---
id: sqli-mysql-file-read-write
title: "MySQL: LOAD_FILE / INTO OUTFILE (чтение и запись файлов)"
type: sqli
target: mysql
category: web
difficulty: advanced
bypass: none
tags: [sqli, mysql, file-access]
tested_on: ["MySQL 5.7 (secure_file_priv пуст)"]
success_rate: 0.4
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
  - target: "rce"
    type: leads_to
    description: "Запись webshell в веб-корень"
---

# MySQL: LOAD_FILE / INTO OUTFILE (чтение и запись файлов)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
-1' UNION SELECT LOAD_FILE('/etc/passwd'),2,3 -- -
```

## Explanation

При пустом `secure_file_priv` и привилегии `FILE` учётка БД может читать файлы сервера
(`LOAD_FILE`) и писать их (`INTO OUTFILE`). Запись в веб-каталог — типичный путь
к выполнению кода (PHP-webshell). В современных сборках MySQL `secure_file_priv`
ограничен, поэтому успех не гарантирован.

## Detection

Проверьте `SELECT @@secure_file_priv, @@version_compile_os`. Ошибка
`Access denied; you need ... FILE privilege` — хороший знак для защиты.
В логах БД ищите `INTO OUTFILE` / `LOAD_FILE`.

## Remediation

- Убрать привилегию `FILE` у учётки приложения.
- `secure_file_priv=/var/lib/mysql-files` (не пусто).
- `read_only=ON` для реплик; изоляция ФС контейнера БД от веб-корня.
- Параметризация запросов.

## Notes

Запись файлов в веб-корень ведёт к RCE — в лабораториях этого репозитория
веб-корень и каталог данных MySQL разделены именно поэтому.
