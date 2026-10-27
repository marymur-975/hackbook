---
id: xss-stored-in-profile
title: "Stored XSS: сохранённая нагрузка в профиле"
type: xss
target: html
category: web
difficulty: intermediate
bypass: none
tags: [xss, stored, persistent]
tested_on: ["Chrome 120"]
success_rate: 0.75
risk: high
cwe: "CWE-79"
lab: "labs/web-labs/xss-lab"
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/xss/"
  - "https://portswigger.net/web-security/cross-site-scripting"
graph:
  - target: "xss"
    type: instance_of
  - target: "session-hijacking"
    type: leads_to
  - target: "admin-panel"
    type: leads_to
    description: "Blind XSS исполняется в контексте администратора"
---

# Stored XSS: сохранённая нагрузка в профиле

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<details open ontoggle=alert(document.domain)>click</details>
```

## Explanation

Stored-XSS сохраняется в БД (имя, био, комментарий, имя файла, User-Agent) и исполняется
у каждого, кто откроет страницу. Опаснее reflected: не нужна доставка ссылки жертве.
`<details open ontoggle=...>` срабатывает автоматически при рендере и часто не покрыт
сигнатурами фильтров. Отдельный класс — blind XSS: нагрузка исполняется во внутренней
панели администратора (логи, тикеты, CRM).

## Detection

1. Внедрите метку в поля профиля/комментариев/имён файлов.
2. Проверьте все места вывода, включая админ-панель, письма, отчёты, мобильное приложение.
3. Для blind-XSS используйте callback-платформы с уникальным ID.

## Remediation

- Экранирование на ВЫВОДЕ в каждом контексте, а не только на вводе.
- Санитизация HTML, если разметка разрешена (DOMPurify/bleach + whitelist тегов).
- CSP для всех страниц, включая админ-панель.
- `HttpOnly`/`SameSite=Lax` для cookie; отдельный домен для пользовательского контента.

## Variants

```
<marquee onstart=alert(1)>
```

```
<input autofocus onfocus=alert(1)>
```
