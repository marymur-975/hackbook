---
id: headers-cors-misconfiguration
title: "CORS: отражение Origin и доверие null"
type: header
target: http
category: web
difficulty: intermediate
bypass: none
tags: [cors, misconfiguration, origin]
tested_on: ["nginx", "Express", "Spring"]
success_rate: 0.5
risk: high
cwe: "CWE-942"
lab: null
last_verified: "2026-10-23"
graph:
  - target: "headers"
    type: instance_of
  - target: "session-hijacking"
    type: leads_to
  - target: "data-exfiltration"
    type: leads_to
---

# CORS: отражение Origin и доверие null

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
Origin: https://attacker.tld
```

## Explanation

Некорректная настройка CORS — самый частый способ превратить XSS на чужом домене
или поддомен в чтение данных жертвы:

- `Access-Control-Allow-Origin` отражает любой `Origin` + `Allow-Credentials: true`
  -> произвольный сайт читает ответы с cookie жертвы.
- Проверка «endswith('legit.com')» обходится доменом `legit.com.attacker.tld`.
- `Origin: null` разрешён -> срабатывает из sandboxed iframe/data-URL.
- Разрешены все поддомены, включая забытый/угнанный staging.
- Различие между префлайтом и реальным запросом (валидация только OPTIONS).

## Detection

1. Отправьте запрос с `Origin: https://attacker.tld` и проверьте ответный
   `Access-Control-Allow-Origin`.
2. Попробуйте `Origin: null` и поддомены-похожие имена (`legit.com.evil.tld`,
   `notlegit.com`).
3. Проверьте наличие `Allow-Credentials: true` — без него чтение cookie невозможно.
Инструменты: `corsy`, `CORS-scanner`.

## Remediation

- Точный whitelist Origin (полное совпадение, со схемой и портом), без отражения.
- `Allow-Credentials: true` только для доверенных Origin.
- Не использовать `*` вместе с credentials (браузер и так запретит, но это сигнал
  о настройке «по умолчанию»).
- Ограничить методы/заголовки (`Allow-Methods`, `Allow-Headers`), `Max-Age`.
- Инвентаризация поддоменов: удалённый staging не должен быть в whitelist.

## Variants

```
Origin: null
```

```
Origin: https://legit.com.attacker.tld
```

```
Origin: https://notlegit.com
```
