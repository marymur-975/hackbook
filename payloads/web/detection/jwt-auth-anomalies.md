---
id: detection-jwt-auth-anomalies
title: "Детект атак на JWT: alg=none, перебор секрета, подделка claims"
type: auth-bypass
target: jwt
category: web
difficulty: intermediate
bypass: none
tags: [detection, sigma, jwt, auth, application-logs]
tested_on: ["application/auth logs", "vuln-hub /login /me /admin"]
success_rate: 0.6
risk: low
cwe: "CWE-347"
lab: "labs/web-labs/vuln-hub"
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
---

# Детект атак на JWT: alg=none, перебор секрета, подделка claims

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# воспроизведение (локальная лаборатория): токен с alg=none и подделанной ролью
python3 - <<'PY'
import sys; sys.path.insert(0, 'labs/web-labs/vuln-hub')
from selftest import forge_token, fetch
print(fetch('http://localhost:8090', '/admin', token=forge_token(alg='none'))[:160])
PY
python3 tools/lib/http_fetch.py http://localhost:8090/logs
```

## Explanation

Атаки на JWT оставляют следы в трёх местах: в логах аутентификации
(отказы проверки подписи), в логах приложения (несоответствие claims
серверному состоянию) и в сетевом трафике (сам токен виден в заголовке).

Что реально детектируется:

1. **Всплеск отказов проверки подписи** (`invalid signature`,
   `SignatureDoesNotMatch`) — признак подбора секрета или подделки.
2. **Токен с неожиданным `alg`**: `none`, `HS256` там, где сервис
    работает на `RS256`, неизвестный `kid`.
3. **Несоответствие claims и серверного состояния**: `role=admin` в токене
    при `role=user` в БД — прямое свидетельство подделки.
4. **Аномалии использования**: один токен с разных IP/UA одновременно,
    токены, предъявляемые до выдачи (replay), `exp` в далёком будущем.
5. **Поведенческий паттерн**: много запросов к `/admin` с кодом 403
    от одной сессии, чередующихся с попытками `/login`.

Пункт 3 — самый надёжный: он не зависит от криптографии и ловит даже
успешную подделку. Для этого сервер обязан сверять критичные claims
с актуальным состоянием, а не только проверять подпись.

## Detection

Логируйте (без записи самого токена!) факт отказа проверки, заявленный `alg`,
`kid`, `sub` и IP. Правило ниже использует поля приложения — замените имена
на свои. Дополнительно: алерт на появление `alg=none` в любом входящем токене
и на `sub` с ролью, которой нет в БД.

## Remediation

- Allowlist алгоритмов на сервере, отказ от `none`, раздельные ключевые
  материалы для HMAC и RSA (см. `auth-bypass-jwt-confused-alg-rs2hs`).
- Короткий TTL access-токена + refresh с ротацией и обнаружением повторного
  использования (reuse detection).
- Критичные claims сверять с серверным состоянием; при расхождении —
  отказ и алерт.
- Секрет ≥ 256 бит энтропии из vault, ротация; мониторинг попыток подбора
  (частые invalid signature с одного IP).
- Не логировать токены целиком: только `jti`/хеш и метаданные.
- Отзыв (revocation list / jti-кеш) для критичных операций.


## Detection rules

```yaml
title: Аномалии валидации JWT (подделка токена или подбор секрета)
id: b2c3d4e5-0004-4b2c-8d3e-000000000104
status: experimental
description: >-
  Отказы проверки подписи JWT, неожиданный алгоритм в заголовке токена или
  несоответствие роли в claims серверному состоянию. Поля приложения —
  замените имена на фактические для своего стека.
references:
  - https://attack.mitre.org/techniques/T1606/001/
  - payloads/web/auth-bypass/jwt-alg-none.md
logsource:
  category: application
  product: jwt
  definition: 'структурированные логи сервиса аутентификации'
detection:
  signature_failures:
    event_action: jwt_verify
    event_outcome: failure
    failure_reason|contains:
      - 'invalid signature'
      - 'signature'
  forbidden_alg:
    event_action: jwt_verify
    jwt_alg:
      - 'none'
      - 'None'
      - 'NONE'
  role_mismatch:
    event_action: authorization
    event_outcome: failure
    mismatch_kind: token_role_vs_store
  volume:
    event_action: jwt_verify
    event_outcome: failure
  timeframe: 5m
  condition: forbidden_alg or role_mismatch or (volume | count() by source_ip > 10)
fields:
  - source_ip
  - user_agent
  - jwt_alg
  - jwt_kid
  - token_sub
falsepositives:
  - рассинхрон часов (exp/nbf) — проверяйте separate-правилом
  - ротация ключей без overlap-периода
level: high
tags:
  - attack.credential_access
  - attack.t1606.001
  - cwe.347
```
