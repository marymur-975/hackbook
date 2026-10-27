---
id: auth-bypass-jwt-alg-none
title: "JWT: алгоритм none (подпись не проверяется)"
type: auth-bypass
target: jwt
category: web
difficulty: intermediate
bypass: auth
tags: [jwt, auth-bypass, token]
tested_on: ["jsonwebtoken (node) legacy", "python-jose", "собственные реализации"]
success_rate: 0.35
risk: high
cwe: "CWE-347"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/"
graph:
  - target: "auth-bypass"
    type: instance_of
  - target: "jwt"
    type: related_to
  - target: "privilege-escalation"
    type: leads_to
---

# JWT: алгоритм none (подпись не проверяется)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"alg":"none","typ":"JWT"}.<base64url payload>.
```

## Explanation

Некоторые библиотеки принимают `alg: none` как «подпись не требуется» и возвращают
token как валидный. Достаточно перекодировать заголовок и убрать подпись
(оставив точку). Варианты регистра (`None`, `NONE`, `nOnE`) обходят наивные проверки.
Отдельный класс — `kid`/`jku`/`x5u` инъекции: путь к ключу или его URL подконтрольны
атакующему, а также подмена `RS256` -> `HS256` с публичным ключом в роли секрета.

## Detection

1. Декодируйте JWT (jwt.io / `jq`), посмотрите `alg`.
2. Попробуйте `alg: none` с пустой подписью и с вариантами регистра.
3. Проверьте, принимает ли сервер изменённый payload (например, `role: admin`).
Инструменты: `jwt_tool`, Burp JWT-расширение.

## Remediation

- Явно задавать ожидаемый алгоритм на сервере и отклонять любой другой (allowlist).
- Обновить библиотеки: современные версии запрещают `none` без явного флага.
- Никогда не брать `kid`/`jku`/`x5c` из токена без валидации (SQLi/SSRF/path traversal в `kid`).
- Короткий TTL + refresh-ротация, отзыв токенов.
- Для критичных операций — повторная аутентификация, а не только токен.

## Variants

```
{"alg":"None"}.<payload>.
```

```
{"alg":"NONE","typ":"JWT"}.<payload>.
```
