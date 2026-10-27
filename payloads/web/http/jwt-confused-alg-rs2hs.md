---
id: auth-bypass-jwt-confused-alg-rs2hs
title: "JWT: подмена алгоритма RS256 -> HS256 (публичный ключ как секрет)"
type: auth-bypass
target: jwt
category: web
difficulty: advanced
bypass: auth
tags: [jwt, algorithm-confusion, rs256, hs256]
tested_on: ["node-jsonwebtoken < 8.5.1", "pyjwt < 1.5", "самописные валидаторы"]
success_rate: 0.25
risk: critical
cwe: "CWE-347"
lab: null
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "jwt"
    type: related_to
  - target: "auth-bypass"
    type: instance_of
  - target: "session-hijacking"
    type: leads_to
---

# JWT: подмена алгоритма RS256 -> HS256 (публичный ключ как секрет)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"alg":"HS256","typ":"JWT"}  // подпись = HMAC-SHA256(публичный ключ RSA)
```

## Explanation

Сервис проверяет RS256-токены публичным ключом. Если библиотека позволяет
клиенту выбирать алгоритм через заголовок `alg`, атакующий переключает его
на HS256 и подписывает токен **симметрично**, используя публичный RSA-ключ
как секрет HMAC. Публичный ключ открыт (JWKS-эндпоинт, сертификат, `-----BEGIN
PUBLIC KEY-----`), поэтому подпись воспроизводится.

Условия успеха: валидатор не фиксирует алгоритм и передаёт один и тот же ключ
в обе ветки проверки. Класс закрыт в современных версиях библиотек
(pyjwt, node-jsonwebtoken, jose), но до сих пор встречается в самописных
реализациях и в «обновлённых» конфигах со старыми флагами.

Важно: секретом должен быть **точный** байтовый вид ключа (PEM целиком,
с переводами строк, или DER) — подбор формата это половина работы.

## Detection

1. Прочитайте `alg` в заголовке: `RS256`/`ES256`?
2. Найдите источник публичного ключа (`/.well-known/jwks.json`, `x5c`, сертификат).
3. `jwt_tool -X a` (или `jwt_tool -T` с ключом) — переподписать токен как HS256
   и проверить принятие.
4. В коде ищите `verify(token, key)` без параметра `algorithms=[...]`.
5. Признак в логах: токены с `alg=HS256`, которые проходят проверку на сервисе с RSA.

## Remediation

- Явно фиксировать список разрешённых алгоритмов при валидации
  (`algorithms=["RS256"]`, `verify_options`), игнорировать `alg` из токена.
- Разделять ключевые материалы: симметричный секрет никогда не должен совпадать
  с публичным ключом.
- Обновить библиотеки (pyjwt ≥ 2.4, node-jsonwebtoken ≥ 9, jose актуальные).
- Отклонять `alg: none`, неизвестные и смешанные семейства.
- Валидировать `iss`/`aud`/`exp`/`nbf`, использовать короткие TTL и revocation.
- Тест в CI: токен с подменённым `alg` обязан быть отклонён.

## Detection rules

```yaml
title: JWT RS2HS — HMAC-подпись токена проверяется публичным RSA-ключом
id: e5f6a7b8-0087-4e5f-9a7b-000000000087
status: experimental
description: >-
  Токен с alg=HS256, у которого kid указывает на асимметричный (RSA) ключ:
  атакующий подписывает токен публичным ключом как HMAC-секретом. Признак —
  сочетание HS*-алгоритма с rsa-* в kid; успех такой проверки критичен.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/jwt/algorithm-confusion
logsource:
  category: application
  definition: 'логи верификации JWT: jwt_alg, jwt_kid, исход проверки'
detection:
  selection:
    event_action: jwt_verify
    jwt_alg:
      - HS256
      - HS384
      - HS512
  rsa_kid:
    jwt_kid|contains:
      - 'rsa'
      - 'RSA'
      - 'asymmetric'
      - 'public'
  condition: selection and rsa_kid
fields:
  - source_ip
  - jwt_alg
  - jwt_kid
  - token_sub
  - event_outcome
falsepositives:
  - гибридные схемы с осознанным kid=rsa-*+HMAC (практически не встречаются;
    если есть — внесите в исключения и задокументируйте)
level: critical
tags:
  - attack.credential_access
  - attack.t1190
  - attack.t1606
  - cwe.347
```
