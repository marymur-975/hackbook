---
id: headers-host-cache-poisoning
title: "Host header: отравление кеша и сброс пароля"
type: header
target: http
category: web
difficulty: advanced
bypass: none
tags: [host-header, cache-poisoning, password-reset]
tested_on: ["Varnish/CDN + nginx", "самописные reset-flow"]
success_rate: 0.35
risk: high
cwe: "CWE-644"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "headers"
    type: instance_of
  - target: "cache-poisoning"
    type: leads_to
  - target: "auth-bypass"
    type: leads_to
---

# Host header: отравление кеша и сброс пароля

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
Host: attacker.tld
```

## Explanation

Заголовок `Host` часто используется приложением для построения абсолютных URL.
Два основных следствия:

1. Отравление кеша: если `Host` участвует в ключе кеша и отражается в ответе
   (ссылки на статику, canonical, og:url), подстановка своего домена кэшируется
   и раздаётся другим пользователям.
2. Сброс пароля: письмо «восстановление пароля» содержит ссылку вида
   `https://<Host>/reset?token=...` — токен уходит на контролируемый домен.

Векторы подачи: `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`,
дублированный `Host` (`Host: legit\r\nHost: attacker`), абсолютный URI в request-line.

## Detection

1. Подставьте свой домен в `Host`/`X-Forwarded-Host` и поищите его в ответе.
2. Проверьте, меняется ли ключ кеша (`X-Cache: HIT` на своём варианте).
3. Пройдите flow сброса пароля с подменённым Host и посмотрите ссылку в письме (в лабе).
Инструменты: `smuggler`, `param-miner` (Burp), `Web-Cache-Vulnerabilities`-сканеры.

## Remediation

- Не строить абсолютные URL из `Host`: использовать фиксированный base URL из конфигурации.
- Валидировать `Host` по whitelist виртуальных хостов; 444/400 на неизвестные.
- Исключить `X-Forwarded-Host` из логики приложения; доверять только заголовкам
  от своего reverse proxy.
- Включить `Host` в ключ кеша явно и валидировать до кэширования.
- Ссылки в письмах — из конфигурации, токен одноразовый и короткий.

## Variants

```
X-Forwarded-Host: attacker.tld
```

```
X-Host: attacker.tld
```

```
X-Forwarded-Scheme: nohttps
```
