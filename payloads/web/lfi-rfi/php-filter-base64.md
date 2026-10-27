---
id: lfi-php-filter-base64
title: "LFI: php://filter для чтения исходного кода"
type: lfi
target: php
category: web
difficulty: intermediate
bypass: none
tags: [lfi, php, wrapper, source-disclosure]
tested_on: ["PHP 7.4", "PHP 8.2"]
success_rate: 0.7
risk: high
cwe: "CWE-22"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Path_Traversal"
graph:
  - target: "lfi-rfi"
    type: instance_of
  - target: "info-disclosure"
    type: leads_to
---

# LFI: php://filter для чтения исходного кода

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
php://filter/convert.base64-encode/resource=index.php
```

## Explanation

Обычный `include('index.php')` исполнит код, а не покажет его. Обёртка `php://filter`
с фильтром `convert.base64-encode` возвращает файл в base64 — так читают исходники
приложения, находят учётные данные, секретные ключи и точки для дальнейшей атаки.
Цепочки фильтров (`convert.iconv.*`) позволяют не только читать, но и синтезировать
произвольное содержимое (техника PHP filter chains).

## Detection

1. Проверьте, PHP ли backend (заголовки, `.php` в URL, cookie `PHPSESSID`).
2. Подставьте `php://filter/convert.base64-encode/resource=<известный файл>`.
3. Ответ — длинная base64-строка: декодируйте и читайте код.

## Remediation

- `allow_url_include=Off`, `open_basedir` на каталог приложения.
- Whitelist подключаемых файлов (никаких пользовательских значений в `include`).
- Отключить ненужные stream wrappers; не держать секреты в коде (vault/env).
- Разделение: веб-процесс без доступа к конфигам других сервисов.

## Variants

```
php://filter/read=string.rot13/resource=index.php
```

```
php://filter/convert.base64-encode/resource=../config.php
```
