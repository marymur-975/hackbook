---
id: upload-race-double-extension
title: "Загрузка файлов: гонка с антивирусом и двойные расширения"
type: upload
target: generic
category: web
difficulty: advanced
bypass: filter
tags: [file-upload, race-condition, double-extension, av-bypass-context]
tested_on: ["схемы «загрузить -> проверить -> удалить»", "Apache mod_mime"]
success_rate: 0.3
risk: high
cwe: "CWE-367"
lab: "labs/web-labs/upload-lab"
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "file-upload"
    type: instance_of
  - target: "race-condition"
    type: related_to
  - target: "rce"
    type: leads_to
---

# Загрузка файлов: гонка с антивирусом и двойные расширения

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) двойное расширение (порядок обработчика зависит от сервера)
shell.php.jpg     # Apache: обработает как PHP, если AddType настроен на .php
shell.jpg.php     # почти всегда исполняется как PHP

# 2) гонка: загрузить и запросить до завершения проверки
for i in $(seq 1 200); do curl -s http://target/uploads/shell.php & done
```

## Explanation

**Двойное расширение.** `mod_mime` выбирает обработчик по последнему
распознанному расширению, поэтому `shell.jpg.php` исполняется как PHP,
а `shell.php.jpg` — как картинка (но часть конфигураций с `AddHandler`
срабатывает и на `.php` в середине имени). Проверять нужно оба порядка
и варианты `.php.png`, `.phtml.jpg`.

**Гонка с проверкой.** Схема «сохранить файл -> запустить антивирус/валидацию
-> удалить при провале» оставляет окно, в течение которого файл доступен
по URL. Многопоточная отправка (20–200 параллельных запросов) позволяет
выполнить код до удаления. Та же логика работает для «одноразовых» ссылок,
квот и лимитов (см. `http-race-condition-single-packet`).

Важно: речь о воспроизведении **в своей лаборатории**; обход антивируса
на чужих системах в проект не входит.

## Detection

1. Загрузите `hb.php.jpg` и `hb.jpg.php`, запросите оба — какой исполняется?
2. Для гонки: загрузите файл с заведомо безобидным маркером и параллельно
   запрашивайте его 100–200 раз; зафиксируйте, сколько запросов вернули 200
   до удаления.
3. В логах: GET к файлу в uploads с кодом 200 сразу после POST загрузки,
   затем 404 — признак временного окна.
4. Проверьте, где хранится файл до завершения валидации.

## Remediation

- Проверять содержимое **до** записи в доступное место: принимать поток
  в памяти/временном каталоге вне веб-доступа, валидировать, пересобирать,
  только затем публиковать под сгенерированным именем.
- Whitelist расширений (не blacklist), переименование файла, хранение вне
  DocumentRoot, запрет исполнения скриптов в uploads.
- Атомарность: публикация файла — одна операция (`rename` из temp),
  а не «записать, потом проверить».
- Нормализация имени: отбрасывать всё, кроме `[a-z0-9._-]`, запрещать
  несколько точек и ведущие точки.
- Rate limiting на загрузку и на запросы к uploads.

## Variants

```
shell.phtml.png
```

```
shell.php%00.jpg
```

```
shell.php%20
```

```
shell.php.
```

## Detection rules

```yaml
title: Двойное расширение и гонка загрузки — shell.php.jpg исполняется как PHP
id: e5f6a7b8-0059-4e5f-9a7b-000000000059
status: experimental
description: >-
  Имена файлов с двойными расширениями (.php.jpg, .jpg.php) в загрузках и
  последующие запросы к ним внутри каталога загрузок. Второй признак гонки —
  запрос к файлу раньше, чем отработала антивирусная проверка.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: webserver
  definition: 'access-лог + логи загрузок с именем файла'
detection:
  upload_marker:
    event_action: file_upload
    filename|contains:
      - '.php.jpg'
      - '.php.png'
      - '.php.gif'
      - '.jpg.php'
      - '.png.php'
      - '.gif.php'
      - '.phtml.'
      - '.php%00'
  access_marker:
    cs-uri-stem|contains:
      - '.jpg.php'
      - '.png.php'
      - '.gif.php'
      - '.php.jpg'
  condition: upload_marker or access_marker
fields:
  - c-ip
  - cs-uri-stem
  - sc-status
  - filename
falsepositives:
  - конвертеры изображений с именами вида photo.php.jpg (практически не встречаются)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.434
```
