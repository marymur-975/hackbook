---
id: sqli-lab-walkthrough
title: "Сквозной сценарий: SQL Injection Lab"
difficulty: beginner
labs: ["sqli-lab"]
steps: ["sqli-mysql-tautology-auth-bypass", "sqli-mysql-union-based"]
---

# Сквозной сценарий: SQL Injection Lab

В этом сценарии мы шаг за шагом пройдем локальную лабораторию SQLi (`labs/web-labs/sqli-lab`), используя карточки из нашего учебника.

## Шаг 1. Разведка

Запустим лабораторию (если ещё не запущена):

```bash
cd labs/setup && docker compose up -d
```

````

Откроем браузер по адресу `http://localhost:8080`. Мы видим форму логина и поиска.

## Шаг 2. Обход аутентификации

Первым делом попробуем войти в систему, используя классическую тавтологию. В поле логина вводим:
`' OR '1'='1`

Подробнее о том, почему это работает, читай в карточке:

{{ include "payloads/web/sqli/mysql-tautology-auth-bypass.md" }}

## Шаг 3. Извлечение данных (UNION)

После входа мы видим поиск по товарам. Попробуем извлечь версию базы данных через UNION-инъекцию.
В поиске вводим:
`' UNION SELECT 1, version(), 3 -- -`

Подробнее в карточке:

{{ include "payloads/web/sqli/mysql-union-based.md" }}

## Вывод

Мы прошли путь от простого обхода логина до извлечения данных. Теперь ты знаешь, как это работает на практике.

```
````
