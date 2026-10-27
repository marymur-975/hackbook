---
id: headers-x-forwarded-for-spoofing
title: "X-Forwarded-For: подмена IP и обход geo/ACL-ограничений"
type: header
target: http
category: web
difficulty: beginner
bypass: filter
tags: [headers, ip-spoofing, acl, rate-limit]
tested_on: ["nginx", "Apache", "Cloud-балансировщики"]
success_rate: 0.5
risk: medium
cwe: "CWE-290"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "headers"
    type: instance_of
  - target: "waf-bypass"
    type: technique_of
  - target: "bruteforce"
    type: related_to
---

# X-Forwarded-For: подмена IP и обход geo/ACL-ограничений

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
X-Forwarded-For: 127.0.0.1
```

## Explanation

Приложение берёт «IP клиента» из заголовка, который клиент полностью контролирует.
Последствия:

- обход ACL/geo-блокировок и whitelist'ов «только из офиса»
- обход rate limiting (новый «IP» на каждый запрос) — усложняет защиту от bruteforce
- подмена `127.0.0.1` для внутренних эндпоинтов (`/actuator`, `/metrics`, `/admin`),
  если правило доступа основано на IP
- отравление логов и аналитики, обход антифрода
- в связке с кешем — отравление кеша (IP в ключе кеша)

Встречаются также `X-Real-IP`, `X-Client-IP`, `X-Originating-IP`, `CF-Connecting-IP`,
`True-Client-IP`, `X-Remote-Addr`.

## Detection

1. Найдите эндпоинт, реагирующий на IP (403 «доступ только из сети X»).
2. Переберите заголовки из списка выше с нужным IP.
3. Проверьте rate limiting: шлите запросы с меняющимся `X-Forwarded-IP` —
   срабатывает ли блокировка.
Инструменты: `param-miner`, Burp-расширение `Header Injection`.

## Remediation

- Доверять только последнему заголовку, добавленному СВОИМ reverse proxy;
  все входящие `X-Forwarded-*` от клиента — отбрасывать/перезаписывать.
- nginx: `real_ip_header X-Forwarded-For; set_real_ip_from <proxy-subnet>;`
  + `real_ip_recursive on`.
- ACL и rate limiting — по адресу соединения (L3/L4), а не по заголовку.
- Единая точка нормализации IP в middleware; тесты на подмену в CI.

## Variants

```
X-Real-IP: 127.0.0.1
```

```
X-Client-IP: 10.0.0.1
```

```
X-Originating-IP: 127.0.0.1
```

```
CF-Connecting-IP: 127.0.0.1
```
