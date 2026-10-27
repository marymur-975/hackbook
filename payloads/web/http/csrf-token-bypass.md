---
id: http-csrf-token-bypass
title: "CSRF: отсутствие, непривязанность и обход токена"
type: http
target: http
category: web
difficulty: intermediate
bypass: filter
tags: [csrf, cookie, samesite, token]
tested_on: ["SameSite=Lax по умолчанию", "самописные CSRF-защиты"]
success_rate: 0.45
risk: high
cwe: "CWE-352"
lab: null
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "headers"
    type: related_to
  - target: "auth-bypass"
    type: related_to
  - target: "session-hijacking"
    type: leads_to
---

# CSRF: отсутствие, непривязанность и обход токена

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<form action="https://target/account/email" method="POST">
  <input name="email" value="attacker@evil.tld">
</form>
<script>document.forms[0].submit()</script>
```

## Explanation

CSRF эксплуатирует то, что браузер **сам** прикладывает cookie к запросу
на чужой сайт. Защита — токен, который атакующий не может прочитать
(same-origin policy). Типовые дыры:

1. Токена нет вообще для state-changing запросов (особенно для «мелких»:
   смена e-mail, телефона, роли, привязки OAuth).
2. Токен проверяется только при наличии: удалить cookie/заголовок — и проверка
   пропускается (`if (token != null) verify(token)`).
3. Токен не привязан к сессии: один и тот же токен работает для всех пользователей
   (его можно взять из своей сессии).
4. Токен валиден после logout или не инвалидируется при смене пароля.
5. Обход через subdomain: установка cookie на `.target.com` из XSS/открытого
   редиректа на поддомене (cookie tossing).
6. Метод не проверяется: `GET /account/delete?id=1` или смена метода POST→GET.
7. `Content-Type: application/json` принимается как form-data
   (`multipart/form-data` и `text/plain` разрешены в simple CORS-запросах).

`SameSite=Lax/Strict` заметно снижает риск, но **не отменяет** CSRF:
Lax пропускает cookie при top-level GET-навигации, а старые браузеры
и мобильные webview могут игнорировать атрибут.

## Detection

1. Найдите state-changing запрос и удалите из него CSRF-токен — прошёл ли?
2. Подставьте токен из другой сессии — принят ли?
3. Поменяйте метод (POST→GET/PUT/PATCH/HEAD) и `Content-Type`.
4. Проверьте `SameSite` у session-cookie и наличие CORS `Allow-Credentials`.
5. Соберите PoC-страницу и откройте её в своей сессии (только на тестовом аккаунте).
Инструменты: Burp «CSRF PoC Generator», ручная проверка атрибутов cookie.

## Remediation

- Синхронизатор-токен (double-submit cookie + серверное хранение) или
  `SameSite=Strict` **вместе** с токеном, а не вместо него.
- Токен обязателен: отсутствие токена = 403; токен привязан к сессии и пользователю.
- Ротация токена после логина и смены пароля; инвалидация при logout.
- Проверка `Origin`/`Referer` как дополнительный слой (не единственный).
- Запрет state-changing GET; требование `Content-Type: application/json`
  + preflight для API.
- Для критичных операций — повторная аутентификация (step-up) и подтверждение
  по второму каналу (смена e-mail/телефона с подтверждением старого).
- `HttpOnly`, `Secure`, `Domain` без wildcard на поддомены.

## Detection rules

```yaml
title: CSRF — межсайтовый POST без токена и проваленная CSRF-проверка
id: e5f6a7b8-0083-4e5f-9a7b-000000000083
status: experimental
description: >-
  POST на изменяющий данные эндпоинт приходит с Referer стороннего сайта
  (или без Referer при включённой защите), либо приложение само логирует
  провал CSRF-проверки (token missing/mismatch).
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
logsource:
  category: webserver
  definition: 'access-лог с Referer + логи приложения с результатом CSRF-проверки'
detection:
  selection_access:
    cs-method: POST
    cs-referer|contains: 'http'
  filter_own_referer:
    cs-referer|contains:
      - 'corp.lab'
      - 'app.example'
  selection_app:
    event_action: csrf_check
    event_outcome: failure
  condition: (selection_access and not filter_own_referer) or selection_app
fields:
  - c-ip
  - cs-uri-stem
  - cs-referer
  - request_path
  - failure_reason
falsepositives:
  - мобильные приложения и интеграции без Referer — для них действует второй
    признак (csrf_check failure), а не отсутствие заголовка
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.352
```
