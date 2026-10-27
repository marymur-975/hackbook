---
id: upload-extension-blacklist-bypass
title: "Загрузка файлов: обход blacklist расширений"
type: upload
target: http
category: web
difficulty: beginner
bypass: filter
tags: [file-upload, blacklist, webshell, rce]
tested_on: ["PHP + Apache", "ASP.NET + IIS", "nginx + PHP-FPM"]
success_rate: 0.5
risk: critical
cwe: "CWE-434"
lab: "labs/web-labs/upload-lab"
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "file-upload"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "waf-bypass"
    type: technique_of
---

# Загрузка файлов: обход blacklist расширений

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
shell.php5
```

## Explanation

Blacklist расширений — самая распространённая и самая хрупкая защита загрузки.
Обходы, которые стоит проверять по порядку:

1. **альтернативные исполняемые расширения**: `.php3 .php4 .php5 .php7 .phtml .phar`,
    `.asp .asa .cer .cdx .aspx .asmx .ashx .asmx`, `.jsp .jspx .jsw .jsv .jspf`,
    `.cgi .pl .py .rb .war`
2. **регистр и пробелы**: `.PhP`, `.php ` (пробел в конце), `.php.`, `.php%00.jpg`
    (null-byte — исторический, работает на старых PHP), `.php::$DATA` (NTFS ADS)
3. **двойные расширения**: `shell.php.jpg`, `shell.jpg.php` — зависит от того,
    как сервер выбирает обработчик (Apache `mod_mime` берёт последнее известное)
4. **переопределение обработчика**: загрузка `.htaccess` с
    `AddType application/x-httpd-php .jpg` — после этого «картинки» исполняются
5. **несоответствие проверки и сохранения**: валидатор смотрит на `Content-Type`,
    а на диск пишется оригинальное имя

Успех даёт выполнение кода на сервере (webshell) — критическая находка.

## Detection

1. Загрузите файл с расширением из списка выше и попробуйте его открыть.
2. Загрузите безобидный PHP-файл `<?php echo 'HBMARK'; ?>` с расширением `.phar`.
3. Проверьте, что сохраняется на диске: имя, каталог, права, доступность по URL.
4. Отдельно проверьте переименование (сохраняется ли оригинальное имя)
   и путь (можно ли выйти traversal'ом из каталога загрузок).
5. Признаки в логах: POST на upload-эндпоинт с последующим GET того же файла
   и кодом 200 вместо 403/404.

## Remediation

- **Whitelist расширений** (только `.jpg .png .pdf .docx`), а не blacklist.
- Переименовывать файл при сохранении (UUID + разрешённое расширение),
  хранить вне веб-корня, отдавать через обработчик с `Content-Disposition: attachment`
  и принудительным `Content-Type`.
- Проверять содержимое: magic bytes, пересборка изображения (ImageMagick/GD),
  антивирусное сканирование, запрет встроенных скриптов в SVG/Office.
- Отдельный домен/cookie-less origin для пользовательского контента.
- В каталоге загрузок отключить исполнение скриптов
  (nginx: `location ~* /uploads/.*\.php$ { deny all; }`, Apache: `php_admin_flag engine off`).
- Лимиты размера, числа файлов и типов; аудит прав на каталог загрузок.

## Variants

```
shell.phtml
```

```
shell.PhP
```

```
shell.php%00.jpg
```

```
shell.jpg.php
```

```
.htaccess
```


## Detection rules

```yaml
title: Исполнение скрипта из каталога загрузок
id: 3f2b8c1a-9d4e-4a2b-8f7c-1e5d6a7b8c90
status: experimental
description: >-
  Запрос к .php/.phtml/.phar внутри каталога пользовательских загрузок
  почти всегда означает успешный upload-обход и webshell.
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains:
      - '/uploads/'
      - '/upload/'
      - '/media/'
      - '/files/'
    cs-uri-stem|endswith:
      - '.php'
      - '.phtml'
      - '.phar'
      - '.php5'
      - '.jspx'
      - '.asp'
      - '.aspx'
  filter_static:
    sc-status: 404
  condition: selection and not filter_static
level: critical
tags: [attack.initial_access, attack.t1190, cwe.434]
falsepositives:
  - легитимные скрипты в каталоге media (редко; исправьте архитектуру)
```
