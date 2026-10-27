---
id: lfi-php-input-data-wrapper
title: "LFI -> RCE: php://input и data://"
type: lfi
target: php
category: web
difficulty: advanced
bypass: none
tags: [lfi, rfi, php, rce]
tested_on: ["PHP 7.x (allow_url_include=On)"]
success_rate: 0.25
risk: high
cwe: "CWE-94"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Path_Traversal"
graph:
  - target: "lfi-rfi"
    type: instance_of
  - target: "rce"
    type: leads_to
---

# LFI -> RCE: php://input и data://

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
php://input
```

## Explanation

`php://input` позволяет выполнить PHP-код из тела POST-запроса, а `data://` —
из самого URL. Это превращает LFI в RCE, но требует `allow_url_include=On`
(по умолчанию выключено с PHP 5.2) либо иной возможности выполнить includ'имый файл.
Практический аналог без этого флага — запись PHP-файла через загрузку, логи,
сессионные файлы или SSH `authorized_keys`, затем подключение его через LFI.

## Detection

Отправьте POST с телом `<?php echo 'HB-MARK'; ?>` и `?page=php://input`.
Появление `HB-MARK` в ответе — выполнение кода. Это критическая находка.

## Remediation

- `allow_url_include=Off` и `allow_url_fopen=Off`, если не требуется.
- Никакого пользовательского ввода в `include`/`require`.
- `open_basedir`, отдельный пользователь веб-сервера без прав записи в веб-корень.
- WAF + мониторинг появления новых `.php` в загружаемых каталогах.

## Variants

```
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
```
