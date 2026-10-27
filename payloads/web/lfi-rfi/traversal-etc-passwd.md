---
id: lfi-traversal-etc-passwd
title: "LFI: path traversal к /etc/passwd"
type: lfi
target: linux
category: web
difficulty: beginner
bypass: none
tags: [lfi, path-traversal, linux]
tested_on: ["PHP 8.x", "Node.js", "Java", "Python"]
success_rate: 0.8
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
  - target: "rce"
    type: leads_to
    description: "Чтение конфигов/ключей часто ведёт к выполнению кода"
---

# LFI: path traversal к /etc/passwd

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
../../../../../../etc/passwd
```

## Explanation

Приложение подставляет пользовательское значение в путь файла (`include`, `readFile`, `open`).
Последовательности `../` поднимаются по дереву каталогов, пока не достигнут корня;
дальше идёт абсолютный путь. `/etc/passwd` — каноническая цель: всегда читаем,
содержит список пользователей (но не хеши в современных системах).
Число `../` подбирается с запасом — лишние уровни от корня игнорируются.

## Detection

1. Подставьте уникальное имя файла и посмотрите, отражается ли ошибка `failed to open stream`.
2. Сравните `?file=index` и `?file=../index` — изменение поведения подтверждает traversal.
3. Признак успеха: строки вида `root:x:0:0:root:/root:/bin/bash`.
Инструменты: `dotdotpwn`, `ffuf` со словарём traversal.

## Remediation

- Whitelist имён (карта «алиас -> реальный путь»), никаких пользовательских путей.
- Нормализовать путь (`realpath`) и проверять, что он начинается с разрешённого каталога.
- chroot/контейнер без чувствительных файлов; read-only ФС.
- Отключить вывод ошибок, раскрывающих пути.

## Variants

```
..\..\..\windows\win.ini
```

```
....//....//etc/passwd
```

```
%2e%2e%2f%2e%2e%2fetc/passwd
```

```
/etc/passwd%00
```
