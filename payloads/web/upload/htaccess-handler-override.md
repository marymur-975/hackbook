---
id: upload-htaccess-handler-override
title: "Загрузка .htaccess: переопределение обработчика файлов"
type: upload
target: apache
category: web
difficulty: intermediate
bypass: filter
tags: [file-upload, htaccess, apache, rce]
tested_on: ["Apache 2.4 с AllowOverride All"]
success_rate: 0.45
risk: critical
cwe: "CWE-434"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "file-upload"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "persistence"
    type: leads_to
    description: ".user.ini с auto_prepend_file исполняется на каждый запрос"
---

# Загрузка .htaccess: переопределение обработчика файлов

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# .htaccess в каталоге загрузок
AddType application/x-httpd-php .jpg .png .txt
# или
SetHandler application/x-httpd-php
```

## Explanation

Если разрешена загрузка «безобидных» файлов и каталог загрузок лежит
внутри DocumentRoot с `AllowOverride All`, то `.htaccess` меняет правила
обработки для всего каталога: `AddType application/x-httpd-php .jpg`
превращает загруженные ранее «картинки» в исполняемый PHP.
Это обходит whitelist расширений: сам исполняемый файл загружен легально.

Аналоги в других стеках:

- IIS: `web.config` с `<handlers>` -> исполнение произвольных расширений
- nginx: `.user.ini` (PHP-FPM) с `auto_prepend_file=/path/to/shell.jpg`
- Tomcat: `WEB-INF/web.xml` в загруженном WAR
- Node/Python: `.env`, `package.json` (postinstall), `requirements.txt`
  в CI-контексте

Отдельный риск — `.user.ini` с `auto_prepend_file`: код выполняется при
**каждом** запросе к любому PHP-файлу каталога, даже без явного обращения
к загруженному файлу.

## Detection

1. Попробуйте загрузить `.htaccess` (и `.user.ini`, `web.config`) — принят ли?
2. Если фильтр по расширению — попробуйте `.htaccess.jpg`, `ht.access`, `.ht%2eaccess`.
3. После загрузки проверьте, исполняется ли ранее загруженный `.jpg` с PHP-кодом.
4. В логах Apache: появление 500-х ошибок после загрузки (синтаксис `.htaccess`),
   запросы к файлам в uploads с кодом 200.
5. На сервере: найдите все `.htaccess`/`.user.ini`/`web.config` вне ожидаемых каталогов.

## Remediation

- `AllowOverride None` для каталогов с пользовательским контентом
  (или глобально, с конфигурацией в `<Directory>`).
- Каталог загрузок **вне** DocumentRoot; отдача через скрипт-обработчик.
- Whitlist расширений + блокировка имён, начинающихся с точки
  (`.htaccess`, `.user.ini`, `.env`, `.git`).
- nginx: `location ~ /\.(ht|user) { deny all; }`, запрет `auto_prepend_file`.
- Мониторинг появления конфигурационных файлов в uploads (FIM/auditd).
- Исполнение скриптов в uploads отключено.

## Variants

```
.user.ini (auto_prepend_file)
```

```
web.config (<handlers>)
```

```
.htaccess.jpg
```

## Detection rules

```yaml
title: Загрузка .htaccess/.user.ini — переопределение обработчика расширений
id: e5f6a7b8-0056-4e5f-9a7b-000000000056
status: experimental
description: >-
  Пользователь загружает конфигурационный файл веб-сервера (.htaccess,
  .user.ini, web.config) с AddType/SetHandler application/x-httpd-php —
  после этого «картинки» в каталоге загрузок исполняются как PHP. На файловой
  системе видно как запись .htaccess процессом веб-сервера.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://attack.mitre.org/techniques/T1505/003/
logsource:
  category: application
  definition: 'логи загрузок + auditd на запись конфигурационных файлов веб-сервера'
detection:
  upload_config:
    event_action: file_upload
    filename|endswith:
      - '.htaccess'
      - '.user.ini'
      - 'web.config'
      - '.htpasswd'
  handler_body:
    file_preview|contains:
      - 'AddType application/x-httpd-php'
      - 'SetHandler application/x-httpd-php'
      - 'php_value auto_prepend_file'
      - 'php_flag engine on'
  audit_write:
    EventType: PATH
    Name|endswith:
      - '.htaccess'
      - '.user.ini'
  condition: upload_config or handler_body or audit_write
fields:
  - source_ip
  - filename
  - file_preview
  - Name
  - Image
falsepositives:
  - деплой легитимных .htaccess через CI/CD (исключайте по Image/User в auditd)
level: high
tags:
  - attack.persistence
  - attack.t1190
  - attack.t1505.003
  - cwe.434
```
