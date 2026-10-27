---
# ─────────────────────────────────────────────────────────────
# ШАБЛОН PAYLOAD'А — скопируйте в payloads/<категория>/<тип>/имя.md
# Все поля front-matter проверяются CI (validate-payloads.yml).
# ─────────────────────────────────────────────────────────────
id: unique-payload-id          # обязателен, kebab-case, уникален в репозитории
title: "Человекочитаемое название"
type: sqli                     # sqli | xss | ssrf | lfi | rfi | xxe | cmdi | ssti | auth-bypass | header | network | cloud
target: mysql                  # СУБД / ОС / сервис / "generic"
category: web                  # web | network | active-directory | cloud | privilege-escalation
difficulty: intermediate       # beginner | intermediate | advanced
bypass: none                   # none | waf | filter | encoding | auth | sandbox | csp
tags: [sqli, mysql, tautology]
tested_on: ["MySQL 8.0"]       # где проверено вручную или в лабе
success_rate: 0.8              # 0.0–1.0, субъективная оценка воспроизводимости
risk: medium                   # low | medium | high — насколько разрушителен payload
cwe: "CWE-89"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
lab: labs/web-labs/sqli-lab    # необязательно: где можно воспроизвести
tester: auto                   # auto | manual (manual — не проверяется одним запросом)
last_verified: "2026-01-01"
---

# Название payload'а

!!! warning "Этика"
    Используйте только в лабораториях этого репозитория или в системах,
    на тестирование которых у вас есть письменное разрешение.

## Payload

```
' OR '1'='1' --
```

## Explanation

Почему это работает: разбор синтаксиса, что именно ломается в запросе.

## Detection

Как найти уязвимость: признаки в ответе, тайминги, ошибки СУБД.

## Remediation

Как чинить: параметризованные запросы, валидация, WAF-правила.

## Variants

```
' OR 1=1 --
' OR 'a'='a
```
