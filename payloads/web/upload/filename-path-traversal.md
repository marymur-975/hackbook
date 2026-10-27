---
id: upload-filename-path-traversal
title: "Загрузка файлов: traversal в имени файла"
type: upload
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [file-upload, path-traversal, filename, overwrite]
tested_on: ["PHP", "Node multer", "Python Flask/Werkzeug", "Java Spring"]
success_rate: 0.45
risk: critical
cwe: "CWE-22"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "file-upload"
    type: instance_of
  - target: "lfi-rfi"
    type: related_to
  - target: "rce"
    type: leads_to
---

# Загрузка файлов: traversal в имени файла

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
filename="../../../../var/www/html/shell.php"
```

## Explanation

Имя файла из multipart-запроса используется как часть пути сохранения.
Без нормализации `../` выводит запись за пределы каталога загрузок:
в веб-корень (исполняемый файл), в каталог автозапуска, в `~/.ssh/authorized_keys`,
в cron-каталог или поверх существующего файла (перезапись `.htaccess`,
`index.php`, конфигов).

Варианты, которые нужно проверять:

- `../../x.php`, `..\..\x.php`, `....//....//x.php`
- абсолютный путь: `filename="/var/www/html/x.php"`
- URL-кодирование: `%2e%2e%2f`, двойное `%252e%252e%252f`
- null-byte: `x.php%00.jpg` (исторические версии)
- смена регистра/разделителей на Windows: `..\..\inetpub\wwwroot\x.aspx`
- unicode-нормализация: `..%c0%af`, `..%ef%bc%8f`

Отдельный класс — **перезапись** существующего файла (например, `index.php`)
и гонка при сохранении (см. `http-race-condition-single-packet`).

## Detection

1. Загрузите файл с `filename="../../hb-test.txt"` и проверьте, появился ли он
   вне каталога загрузок (нужен доступ к ФС или предсказуемый URL).
2. Сравните сохранённое имя с отправленным (логи приложения/веб-сервера).
3. Попробуйте абсолютный путь и закодированные варианты.
4. Признак в логах: пути сохранения, содержащие `..`, или запросы к файлам
   вне ожидаемого каталога.
5. Статический анализ: поиск `os.path.join(UPLOADS, request.filename)`,
   `move_uploaded_file($_FILES[..]['name'])`.

## Remediation

- Никогда не использовать оригинальное имя файла: генерировать UUID.
  Если нужно сохранить «человеческое» имя — только в метаданных БД,
  с валидацией charset и длины.
- Нормализовать путь (`realpath`) и проверять, что он внутри разрешённого
  каталога (`is_relative_to`).
- Каталог загрузок вне веб-корня, права без исполнения, отдельный пользователь.
- Запрет перезаписи: уникальные имена, проверка существования.
- В Werkzeug: `secure_filename()` (но не полагаться только на неё —
  она не защищает от всех вариантов).
- Мониторинг записи в системные каталоги (auditd/FIM).

## Variants

```
filename="..\\..\\x.php"
```

```
filename="/var/www/html/x.php"
```

```
filename="x.php%00.jpg"
```

```
filename="..%c0%af..%c0%afx.php"
```

## Detection rules

```yaml
title: Загрузка файла с traversal в имени — запись вне каталога загрузок
id: e5f6a7b8-0055-4e5f-9a7b-000000000055
status: experimental
description: >-
  В имени загружаемого файла встречаются ../, ..\ или абсолютные пути
  веб-корня (/var/www, inetpub) — попытка записать файл за пределами
  каталога загрузок.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: application
  definition: 'логи загрузок с именем файла (event_action file_upload)'
detection:
  upload:
    event_action: file_upload
  traversal:
    filename|contains:
      - '../'
      - '..\'
      - '/var/www'
      - 'C:\inetpub'
      - '/srv/www'
  condition: upload and traversal
fields:
  - source_ip
  - request_path
  - filename
falsepositives:
  - массовые импорты с относительными путями внутри пакета (исключайте доверенные API-ключи)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.434
  - cwe.22
```
