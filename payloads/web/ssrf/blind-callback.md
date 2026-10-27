---
id: ssrf-blind-callback
title: "Blind SSRF: подтверждение через внешний callback"
type: ssrf
target: http
category: web
difficulty: beginner
bypass: none
tags: [ssrf, blind, oob]
tested_on: ["Burp Collaborator", "interactsh"]
success_rate: 0.7
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
  - target: "oob"
    type: technique_of
  - target: "network"
    type: related_to
---

# Blind SSRF: подтверждение через внешний callback

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
http://burpcollaborator.example/
```

## Explanation

Часто ответ приложения не показывает содержимое запрошенного URL (blind SSRF):
например, сервер лишь «обновляет аватар» или ставит задачу в очередь.
Единственный способ подтвердить — заставить цель сделать запрос на контролируемый хост.
Важно проверять не только HTTP, но и DNS-запрос (он проходит даже при закрытом egress-HTTP),
а также задержки: `http://10.255.255.1/` даст таймаут, если порт закрыт —
так сканируют внутреннюю сеть по времени ответа.

## Detection

1. Внедрите свой домен во все URL-параметры, заголовки (`Referer`, `User-Agent`, `X-Forwarded-Host`),
   XML/JSON-тела и поля импорта.
2. Смотрите DNS+HTTP-хиты на collaborator.
3. Сканирование диапазонов: перебор внутренних IP по таймингам.

## Remediation

- Не принимать произвольные URL из пользовательских данных; если необходимо —
  изолированный воркер без доступа к внутренней сети (отдельный VPC/namespace).
- Egress-only прокси, запрет link-local и RFC1918.
- Таймауты и лимит редиректов.
- Логирование всех исходящих запросов с URL и инициатором.

## Variants

```
http://10.0.0.1:8080/
```

```
http://192.168.1.1/admin
```
