---
id: http-open-redirect-chain
title: "Открытый редирект и его использование в цепочках"
type: http
target: http
category: web
difficulty: beginner
bypass: none
tags: [open-redirect, phishing, oauth, ssrf]
tested_on: ["nginx", "Express", "Spring", "PHP"]
success_rate: 0.6
risk: medium
cwe: "CWE-601"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "open-redirect"
    type: instance_of
  - target: "headers"
    type: related_to
  - target: "auth-bypass"
    type: leads_to
  - target: "ssrf"
    type: related_to
  - target: "cache-poisoning"
    type: related_to
---

# Открытый редирект и его использование в цепочках

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
/redirect?url=https://attacker.tld/
```

## Explanation

Приложение делает `302 Location: <значение из параметра>` без валидации.
Само по себе это низкорисковая находка, но она становится оружием в цепочках:

1. **Фишинг**: ссылка выглядит как доверенный домен (`https://bank.com/logout?next=…`).
2. **OAuth/OIDC**: если `redirect_uri` проверяется по префиксу или не проверяется,
   код авторизации утекает на ваш домен -> перехват аккаунта.
3. **SSRF**: сервис, который «ходит по redirect'у», уходит во внутреннюю сеть
   (см. `payloads/web/ssrf/redirect-chain-bypass.md`).
4. **Web cache poisoning**: отравленный 302-ответ раздаётся всем пользователям.
5. **Обход whitelist'ов**: `allowlist.com.attacker.tld`, `//attacker.tld`,
   `https:/attacker.tld`, `\\attacker.tld`.

Обходы фильтров: `/%2f%2fattacker.tld`, `/redirect?url=javascript:alert(1)`
(в старых браузерах), `?url=//attacker.tld`, `?url=https://ok.com#@attacker.tld`.

## Detection

1. Найдите параметры `url`, `next`, `redirect`, `return_to`, `continue`, `target`,
   `r`, `u`, `go`, `out`, `view` и подставьте свой домен.
2. Проверьте ответ: `302` с вашим `Location` = открытый редирект.
3. Проверьте варианты обхода префиксной проверки (`https://ok.attacker.tld`,
   `https://ok@attacker.tld`).
4. Отдельно проверьте OAuth-flow: `redirect_uri` на соответствие точному списку.

## Remediation

- Не принимать внешний URL: использовать **таблицу алиасов** (`?next=profile`)
  или относительные пути с запретом `//` и `\\` в начале.
- Если внешний URL необходим — точный whitelist доменов (полное совпадение host),
  без проверок «startswith» и «contains».
- Показывать промежуточную страницу «вы покидаете сайт» для внешних ссылок.
- В OAuth: `redirect_uri` из зарегистрированного списка, точное совпадение,
  `state` + PKCE.
- `Referrer-Policy: no-referrer` на страницах-редиректах, чтобы не утекал токен в URL.

## Variants

```
/logout?next=//attacker.tld
```

```
/go?to=https:/attacker.tld
```

```
/redirect?url=https://ok.com.attacker.tld/
```

```
/r?u=/%2f%2fattacker.tld
```

## Detection rules

```yaml
title: Open redirect — внешний адрес в параметре перенаправления
id: e5f6a7b8-0090-4e5f-9a7b-000000000090
status: experimental
description: >-
  Редирект-эндпоинт (/redirect, /go, /out) отдаёт 30x на URL из параметра,
  ведущий на внешний домен. Используется для фишинга и как звено обхода
  валидации redirect_uri в OAuth/SSRF.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: webserver
  definition: 'access-лог с query-строкой и кодом ответа'
detection:
  selection_param:
    cs-uri-query|contains:
      - 'url=https://'
      - 'url=http://'
      - 'next=//'
      - 'to=https://'
      - 'redirect=http'
      - 'dest=http'
      - 'continue=http'
  redirect_status:
    sc-status:
      - 301
      - 302
      - 303
      - 307
      - 308
  filter_internal:
    cs-uri-query|contains:
      - 'corp.lab'
      - 'app.example.com'
  condition: selection_param and redirect_status and not filter_internal
fields:
  - c-ip
  - cs-uri-stem
  - cs-uri-query
  - sc-status
falsepositives:
  - легитимные редирект-шлюзы с подписанными ссылками — исключайте их по cs-uri-stem
level: medium
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.601
```
