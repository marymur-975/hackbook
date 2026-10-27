---
id: ssrf-dns-rebinding
title: "SSRF: DNS rebinding (TOCTOU на резолве)"
type: ssrf
target: dns
category: web
difficulty: advanced
bypass: filter
tags: [ssrf, dns, rebinding, toctou]
tested_on: ["Singularity-класс атак", "Python requests + свой DNS"]
success_rate: 0.4
risk: high
cwe: "CWE-918"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
  - "https://portswigger.net/web-security/ssrf"
graph:
  - target: "ssrf"
    type: instance_of
  - target: "waf-bypass"
    type: technique_of
  - target: "network"
    type: related_to
---

# SSRF: DNS rebinding (TOCTOU на резолве)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
http://7f000001.c0a80001.rb.example.tld/
```

## Explanation

Приложение проверяет URL (резолвит DNS -> публичный IP -> OK), а затем делает запрос
повторно, и второй резолв возвращает `127.0.0.1`. Классическая гонка «проверка/использование».
Достигается TTL=0 и чередованием A-записей либо специальным сервисом rebinding.
Так обходят даже корректные blacklist-фильтры по IP.

## Detection

Признак уязвимости: фильтр валидирует IP, но приложение делает отдельный запрос позже
(или открывает соединение заново). Проверяется контролируемым DNS с TTL=0 и двумя A-записями.

## Remediation

- Резолвить один раз и передавать в HTTP-клиент уже готовый IP (pinning),
  подставляя `Host:` отдельно.
- Исходящий прокси, который сам контролирует соединения (никаких прямых запросов из приложения).
- Запретить повторный резолв: connection pooling + `--resolve`-подобный механизм.
- Egress-фильтрация на уровне сети как последний рубеж.
