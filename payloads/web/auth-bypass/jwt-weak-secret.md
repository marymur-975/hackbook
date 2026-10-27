---
id: auth-bypass-jwt-weak-secret
title: "JWT: подбор слабого секрета HS256"
type: auth-bypass
target: jwt
category: web
difficulty: intermediate
bypass: auth
tags: [jwt, bruteforce, hs256]
tested_on: ["HS256 с секретом из top-1000"]
success_rate: 0.3
risk: high
cwe: "CWE-798"
lab: null
last_verified: "2026-10-23"
graph:
  - target: "auth-bypass"
    type: instance_of
  - target: "bruteforce"
    type: related_to
  - target: "jwt"
    type: related_to
---

# JWT: подбор слабого секрета HS256

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<JWT HS256 token> + словарь wordlists/passwords/jwt-secrets.txt
```

## Explanation

Симметричный HS256 подписывается общим секретом. Если секрет короткий или взят
из примеров документации (`secret`, `changeme`, `123456`, `your-256-bit-secret`),
его можно подобрать офлайн: подпись проверяется локально, запросы к серверу не нужны.
После подбора атакующий выпускает токены с любыми claims (`sub: admin`, `role: superuser`).

## Detection

1. Сохраните токен, запустите офлайн-перебор (`hashcat -m 16500`, `jwt_tool -C -d dict`).
2. Признаки риска: `alg: HS256` + сервис с публичной документацией/демо-ключами.
3. Проверьте, совпадает ли секрет с известными из открытых репозиториев.

## Remediation

- Секрет >= 256 бит энтропии (случайный), хранение в vault/KMS, регулярная ротация.
- Предпочесть асимметричные алгоритмы (RS256/ES256): приватный ключ только у эмитента.
- Валидировать `alg` на сервере (allowlist), отклонять `none` и неожиданные алгоритмы.
- Мониторинг аномальных claims; аудит `sub`/`role` в логах.
