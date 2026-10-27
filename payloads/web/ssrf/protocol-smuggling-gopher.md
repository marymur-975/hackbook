---
id: ssrf-protocol-smuggling-gopher
title: "SSRF: небезопасные схемы (gopher/dict/file)"
type: ssrf
target: http
category: web
difficulty: advanced
bypass: filter
tags: [ssrf, protocol, gopher, redis]
tested_on: ["curl (gopher)", "Python urllib (file)"]
success_rate: 0.35
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
  - target: "rce"
    type: leads_to
    description: "gopher в Redis/Memcached может дать запись и выполнение кода"
  - target: "network"
    type: related_to
---

# SSRF: небезопасные схемы (gopher/dict/file)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
gopher://127.0.0.1:6379/_INFO%0d%0a
```

## Explanation

Если URL обрабатывает библиотека общего назначения (curl, libcurl-обвязки, `urllib`
с кастомным opener), атакующий выбирает не только хост, но и протокол:

- `file:///etc/passwd` — локальное чтение файлов
- `gopher://host:port/_<raw>` — произвольный TCP-поток: Redis, Memcached, SMTP, MySQL, FastCGI
- `dict://host:11211/version` — probe внутренних сервисов
- `ldap://`, `ftp://`, `sftp://` — разведка и аутентификация

Через `gopher` в Redis без аутентификации записывают ключи, что даёт RCE
(модули, `CONFIG SET dir` + `SAVE` в cron/authorized_keys).

## Detection

Переберите схемы: `file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`.
Ответ с содержимым файла или ошибкой протокола = схема разрешена.
Сканером: `gopherus`, `Gopherus`-генераторы полезной нагрузки.

## Remediation

- Whitelist схем: только `https` (и `http` при необходимости).
- Использовать HTTP-клиент, который физически не поддерживает иные схемы
  (например, `requests` без кастомных адаптеров не ходит в `gopher`).
- Внутренние сервисы (Redis, Memcached) — только с аутентификацией и в изолированной сети.
- Egress-прокси с разрешёнными портами 80/443.

## Variants

```
file:///etc/passwd
```

```
dict://127.0.0.1:6379/info
```

```
ftp://127.0.0.1/
```
