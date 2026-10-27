---
title: "Cross-Site Scripting (XSS)"
chapter: 1.2
difficulty: intermediate
tags: [web, xss, javascript]
---

# Cross-Site Scripting (XSS)

## Что это такое

XSS — это внедрение вредоносного JavaScript-кода в страницу, который исполняется в браузере жертвы. Это позволяет красть куки, сессии и перенаправлять пользователей.

## Базовый Reflected XSS

Простой пример внедрения тега `<script>`:

{{ include "payloads/web/xss/reflected-basic-script.md" }}

## Обход фильтров

Если тег `<script>` запрещен, можно использовать обработчик событий `onerror`:

{{ include "payloads/web/xss/img-onerror-no-script-tag.md" }}

## Практика

Проверь эти векторы на нашей XSS-лаборатории:
`labs/web-labs/xss-lab`
