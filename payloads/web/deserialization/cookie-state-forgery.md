---
id: deserialization-cookie-state-forgery
title: "Клиентское состояние: подделка подписанных, но не шифрованных cookie"
type: deserialization
target: generic
category: web
difficulty: intermediate
bypass: auth
tags: [cookie, session, state-forgery, privilege-escalation]
tested_on: ["Flask (itsdangerous)", "Rails (MessageVerifier)", "Laravel (signed cookie)"]
success_rate: 0.5
risk: critical
cwe: "CWE-565"
lab: null
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "deserialization"
    type: related_to
  - target: "auth-bypass"
    type: leads_to
  - target: "session-hijacking"
    type: leads_to
  - target: "privilege-escalation"
    type: leads_to
  - target: "info-disclosure"
    type: leads_to
---

# Клиентское состояние: подделка подписанных, но не шифрованных cookie

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# Flask: cookie подписан, но НЕ зашифрован — содержимое читается
flask-unsign --decode --cookie 'eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.Zx1y…'
# -> {'user': 'guest', 'role': 'user'}
```

## Explanation

Многие фреймворки кладут состояние в cookie, подписывая его секретом
(HMAC), но не шифруя. Содержимое видно любому, кто владеет cookie, а значит:

1. **Раскрытие данных**: роли, id, e-mail, права, иногда токены и PII
   попадают к клиенту (и в логи прокси, и в браузерную историю).
2. **Подделка при утечке секрета**: если `SECRET_KEY` слабый, лежит в репозитории,
   в `.env` из бэкапа, в публичном Docker-образе или равен значению из
   документации — подпись пересчитывается, и вы становитесь администратором.
3. **Сериализация внутри cookie**: Flask (`pickle` в старых схемах),
   Rails (`Marshal`), Laravel (`serialized`) — подделанное значение может
   содержать сериализованный объект, то есть это уже RCE-вектор
   (см. `deser-python-pickle`, `deser-php-unserialize-pop`).

Практика показывает: дефолтные и «документационные» секреты встречаются
в production чаще, чем кажется.

## Detection

1. Декодируйте cookie: base64/JWT-like структура с точками = подписанное значение.
2. `flask-unsign --unsign --cookie <c> --wordlist wordlists/passwords/jwt-secrets.txt`
   или аналоги для Rails/Laravel — подбор секрета офлайн.
3. Проверьте, меняется ли поведение при подмене значения БЕЗ пересчёта подписи
   (не должно; если меняется — подпись не проверяется вообще).
4. Ищите секрет в артефактах: `.env` в бэкапах, `config/`, Docker-образы,
   публичные репозитории, `/proc/self/environ` через LFI.
5. В логах: аномальные роли у пользователей, `SignatureDoesNotMatch`-подобные ошибки.

## Remediation

- Состояние сессии — на сервере (session store), в cookie только случайный id.
- Если клиентское состояние необходимо: **шифровать** (JWE, Fernet, Rails
  `MessageEncryptor`), а не только подписывать.
- Секрет: ≥256 бит энтропии, из vault/KMS, ротация, никогда не в репозитории
  и не в образе; отдельные секреты на окружения.
- Проверять подпись до десериализации и не десериализовать pickle/Marshal
  из cookie.
- Не класть в cookie PII, роли и токены; `HttpOnly`, `Secure`, `SameSite=Lax/Strict`.
- Алерты на несоответствие роли в токене и в БД, на частые ошибки проверки подписи.

## Variants

```
Rails Marshal.load в cookie
```

```
Laravel serialized payload
```

```
JWT с ролью в claims (см. jwt-карточки)
```

## Detection rules

```yaml
title: Подделка состояния в подписанном cookie — role escalation и сбой подписи
id: e5f6a7b8-0108-4e5f-9a7b-000000000108
status: experimental
description: >-
  Сессия читается из подписанного, но не зашифрованного cookie: видны провалы
  проверки подписи (подделку не удалось скрыть) и расхождение роли из cookie
  с ролью в БД (подделка удалась — например, flask-unsign + свой секрет).
references:
  - https://attack.mitre.org/techniques/T1606/
  - https://flask.palletsprojects.com/en/latest/security/
logsource:
  category: application
  definition: 'логи приложения: события session_load с результатом и ролями'
detection:
  tamper_failure:
    event_action: session_load
    failure_reason|contains:
      - 'signature mismatch'
      - 'bad signature'
      - 'tamper'
  role_conflict:
    event_action: session_load
    session_role: admin
    expected_role: user
  condition: tamper_failure or role_conflict
fields:
  - source_ip
  - request_path
  - session_role
  - expected_role
  - failure_reason
falsepositives:
  - ротация секретов подписи (валидные старые cookie отваливаются пачкой —
    сверяйте с временем релиза)
level: high
tags:
  - attack.credential_access
  - attack.t1606
  - cwe.345
```
