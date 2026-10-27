---
title: "SQL Injection (SQLi)"
chapter: 1.1
difficulty: intermediate
tags: [web, sqli, database]
---

# SQL Injection (SQLi)

## Что это такое

SQL-инъекция — это атака, при которой злоумышленник вставляет вредоносный SQL-код в поля ввода (логин, поиск и т.д.), чтобы получить доступ к базе данных или обойти аутентификацию.

## Базовый пример

Классический обход формы логина с помощью тавтологии:

{{ include "payloads/web/sqli/mysql-tautology-auth-bypass.md" }}

## Извлечение данных

Если форма уязвима, можно использовать UNION-инъекцию для вытаскивания версии базы данных:

{{ include "payloads/web/sqli/mysql-union-select-enumeration.md" }}

## Практика

## Прогресс

- [ ] Я изучил эту тему

Попробуй выполнить эти атаки на нашей локальной лаборатории:
`labs/web-labs/sqli-lab`
