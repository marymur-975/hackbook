---
id: auth-bypass-idor-sequential-ids
title: "IDOR: последовательные идентификаторы объектов"
type: auth-bypass
target: http
category: web
difficulty: beginner
bypass: auth
tags: [idor, authorization, logic]
tested_on: ["REST API", "GraphQL"]
success_rate: 0.6
risk: high
cwe: "CWE-639"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "auth-bypass"
    type: instance_of
  - target: "data-exfiltration"
    type: leads_to
  - target: "privilege-escalation"
    type: leads_to
---

# IDOR: последовательные идентификаторы объектов

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
/api/v1/invoices/1002  (вместо своего 1001)
```

## Explanation

Приложение проверяет, что пользователь аутентифицирован, но не проверяет,
принадлежит ли ему объект с данным ID. Последовательные числовые ID делают перебор
тривиальным. Варианты: `?id=`, путь `/user/{id}`, GraphQL-аргументы,
имена файлов в загрузках, `uuid` в одном диапазоне, автоинкремент в БД.
Отдельный подкласс — «массовое назначение» (mass assignment): добавление
`"role": "admin"` или `"user_id": 2` в тело запроса.

## Detection

1. Заведите две тестовые учётки (A и B).
2. Из сессии A запросите объект B по его ID — вернулись ли данные?
3. Проверьте PUT/PATCH/DELETE, экспорт, а также косвенные эндпоинты
   (`/invoices/{id}/pdf`, `/users/{id}/avatar`).
4. Mass assignment: добавьте в тело лишние поля и посмотрите, применились ли они.

## Remediation

- Проверка владения на уровне сервиса для КАЖДОГО запроса (object-level authorization).
- Непредсказуемые идентификаторы (UUIDv7) — защита от перебора, но не замена проверке прав.
- DTO/whitelist полей при десериализации (никаких `role`, `is_admin` из клиента).
- Автоматические тесты на горизонтальные/вертикальные привилегии в CI.

## Variants

```
{"id": 1002}
```

```
?user_id=2
```

```
/graphql { invoice(id: 1002) { total } }
```
