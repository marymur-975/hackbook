---
id: ssrf-redirect-chain-bypass
title: "SSRF: обход валидации через HTTP-редирект"
type: ssrf
target: http
category: web
difficulty: intermediate
bypass: filter
tags: [ssrf, redirect, bypass]
tested_on: ["Python requests (allow_redirects=True)", "curl -L"]
success_rate: 0.6
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
  - target: "open-redirect"
    type: related_to
  - target: "waf-bypass"
    type: technique_of
---

# SSRF: обход валидации через HTTP-редирект

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
https://allowed.example.com/r?to=http://169.254.169.254/latest/meta-data/
```

## Explanation

Валидатор проверяет исходный URL (он в whitelist), а клиент затем следует редиректу
на внутренний адрес. Большинство HTTP-библиотек по умолчанию делают до 5–30 переходов
и не повторяют проверки. Достаточно любого открытого редиректа на разрешённом домене
или собственного сервера, отвечающего `302 Location: http://169.254.169.254/...`.

## Detection

1. Укажите свой хост, который отвечает 302 на внутренний адрес цели.
2. Если в ответе приложения появились данные метаданных — редиректы не валидируются.
Побочно: ищите открытые редиректы (`Location:` из параметра) — это отдельная находка.

## Remediation

- Отключить авто-follow редиректов; обрабатывать каждый переход вручную с повторной валидацией.
- Если редиректы нужны — валидировать каждый `Location` по тем же правилам (схемы + IP).
- Whitelist доменов + egress-прокси.
- Не возвращать содержимое fetched-URL пользователю вслепую (риск XSS/утечки).
