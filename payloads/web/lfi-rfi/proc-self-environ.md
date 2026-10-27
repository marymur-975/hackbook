---
id: lfi-proc-self-environ
title: "LFI: /proc/self — окружение, cmdline и дескрипторы процесса"
type: lfi
target: linux
category: web
difficulty: intermediate
bypass: none
tags: [lfi, proc, linux, info-disclosure]
tested_on: ["Linux kernel 5.x (procfs)"]
success_rate: 0.5
risk: high
cwe: "CWE-200"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Path_Traversal"
graph:
  - target: "lfi-rfi"
    type: instance_of
  - target: "info-disclosure"
    type: leads_to
  - target: "privilege-escalation"
    type: related_to
---

# LFI: /proc/self — окружение, cmdline и дескрипторы процесса

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
/proc/self/environ
```

## Explanation

procfs раскрывает внутренности процесса без всяких паролей:

- `/proc/self/environ` — переменные окружения (часто с секретами: `DB_PASSWORD`, API-ключи)
- `/proc/self/cmdline` — аргументы запуска
- `/proc/self/cwd` — рабочий каталог (обход `open_basedir` в некоторых конфигурациях)
- `/proc/self/fd/N` — открытые дескрипторы: логи, сокеты, временные файлы
- `/proc/self/status`, `/proc/self/maps` — память и привилегии процесса
- `/proc/version`, `/proc/cpuinfo` — fingerprinting ядра и железа

`/proc/self/fd/N` особенно полезен: если веб-сервер держит лог открытым,
его можно прочитать через дескриптор, минуя проверку пути к файлу.

## Detection

Переберите `/proc/self/environ`, `/proc/self/cmdline`, `/proc/self/fd/0..20`.
Содержимое с `PATH=`, `DB_`, `SECRET` — критическая утечка.

## Remediation

- `open_basedir` / chroot / контейнер: procfs монтируется read-only и ограничен
  (`/proc` с `hidepid=2`).
- Не передавать секреты через переменные окружения веб-процессу — использовать
  vault/секрет-менеджер с короткоживущими токенами.
- Устранить сам LFI (whitelist путей).
- `ProtectSystem=strict`, `PrivateTmp=` в systemd-юнитах.

## Variants

```
/proc/self/cmdline
```

```
/proc/self/fd/0
```

```
/proc/version
```

```
/proc/self/status
```
