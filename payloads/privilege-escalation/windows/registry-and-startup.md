---
id: windows-registry-and-startup
title: "Windows: автозапуск через реестр и записываемые ключи HKCU"
type: privesc
target: windows
category: web
difficulty: beginner
bypass: none
tags: [privesc, windows, persistence, registry, autoruns, run-keys]
tested_on: ["Windows 10/11 (собственные ВМ)"]
success_rate: 0.6
risk: high
cwe: "CWE-284"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/techniques/T1547/001/"
  - "https://lolbas-project.github.io/"
---

# Windows: автозапуск через реестр и записываемые ключи HKCU

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) ключи автозапуска
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

# 2) что лежит в автозапуске и доступны ли эти файлы на запись
for /f "tokens=2*" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') do @icacls "%b" 2>nul | findstr /i "Users:(M) Users:(F)"

# 3) каталоги автозапуска
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"

# 4) Image File Execution Options (IFEO) — перехват запуска по имени EXE
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
# ключ Debugger у задачи = выполнение своего бинарника вместо оригинала
# SilentProcessExit + MonitorProcess — запуск при завершении процесса

# 5) службы, COM-перехват, AppInit_DLLs, Winlogon-ключи
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v Shell
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v Userinit
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows /v AppInit_DLLs

# 6) планировщик задач (отдельный большой класс)
schtasks /query /fo CSV /v > %TEMP%\tasks.csv

# 7) комплексная проверка: Sysinternals Autoruns (своя ВМ)
#    autorunsc64.exe -a * -c -h -s -t > autoruns.csv
```

## Explanation

Реестр — основной механизм автозапуска в Windows. Для эскалации и
закрепления используются два свойства:

1. **HKCU-ключи выполняются в контексте пользователя**, а HKLM — при
    входе любого пользователя (часто от администратора). Если админ
    входит в систему, в которой обычный пользователь может менять HKCU Run,
    код пользователя не выполнится от админа — но если цель — сама учётка,
    закрепление работает.
2. **Записываемые исполняемые файлы, на которые ссылаются HKLM-ключи** —
    настоящая эскалация: админ-автозапуск вызывает программу из
    каталога, куда есть запись у пользователя (частая ошибка установщиков).

Отдельные мощные механизмы:

* **IFEO `Debugger`**: подмена запускаемого бинарника по имени
  (`sethc.exe`, `utilman.exe` — «sticky keys»-техника доступа к SYSTEM
  на экране блокировки).
* **Winlogon `Shell` / `Userinit`**: выполнение при каждом входе.
* **AppInit_DLLs**: загрузка DLL во все GUI-процессы (сейчас ограничен,
  но встречается на старых системах).
* **COM-перехват** (HKCU\Software\Classes\CLSID): подмена обработчика
  COM-объекта, который использует привилегированное приложение.
* **Планировщик задач**: задачи от SYSTEM с записываемым исполняемым
  файлом или аргументами.

Методика аудита: Autoruns (или `autorunsc -a *`) + проверка прав на
каждый файл из списка автозапуска; отдельно — IFEO и Winlogon.

## Detection

* Sysmon EventID 12/13/14 (реестр): изменения в `...\CurrentVersion\Run*`,
  `...\Winlogon`, `Image File Execution Options`, `AppInit_DLLs`,
  `HKCU\Software\Classes\CLSID`.
* Алерт на значение `Debugger` в IFEO — легитимных случаев почти нет.
* EventID 4688: запуск `sethc.exe`/`utilman.exe` до входа пользователя
  (признак sticky-keys техники).
* Контроль файлов автозапуска: hash-инвентаризация и алерт на изменение.
* EventID 4698/4699/4702 (планировщик): создание/изменение задач.
* Baseline ACL: файлы, на которые ссылаются HKLM-ключи, должны быть
  root/Administrators-only.
* GPO-контроль: запрет изменения Run-ключей пользователями (приемлемо
  не везде — проверяйте совместимость).

## Remediation

- Установщики: файлы автозапуска только в защищённые каталоги;
  проверка ACL на них в CI-тестах продукта.
- Использовать службы/планировщик с явными учётками вместо Run-ключей
  для привилегированных задач.
- WDAC/AppLocker в режиме enforcement: неподписанный код не выполнится,
  даже если ключ автозапуска изменён.
- Контроль целостности реестра (Sysmon + SIEM-алерты на Run-ключи,
  IFEO, Winlogon).
- Минимизация числа пользователей с локальным админ-доступом:
  большинство техник требуют elevated-контекста для HKLM.
- Регулярный аудит автозапуска (Autoruns/`autorunsc`) в baseline-отчёте.
- Отключить `AppInit_DLLs` (требует SecureBoot в новых версиях).
- Для рабочих станций: ASR-правила (Attack Surface Reduction)
  «Block persistence through WMI event subscription» и подобные.


## Detection rules

```yaml
title: Изменение механизмов автозапуска Windows (Run-ключи, IFEO, Winlogon)
id: c3d4e5f6-0011-4c3d-9e4f-000000000211
status: test
description: >-
  Запись в ключи автозапуска, Image File Execution Options и Winlogon —
  основные точки закрепления и эскалации через автозапуск.
references:
  - https://attack.mitre.org/techniques/T1547/001/
  - https://attack.mitre.org/techniques/T1546/012/
  - https://attack.mitre.org/techniques/T1547/004/
logsource:
  product: windows
  service: sysmon
  definition: 'Sysmon EventID 12/13 (Registry object added/changed, value set)'
detection:
  run_keys:
    EventID: 13
    TargetObject|contains:
      - '\Microsoft\Windows\CurrentVersion\Run'
      - '\Microsoft\Windows\CurrentVersion\RunOnce'
      - '\Policies\Explorer\Run'
  ifeo:
    EventID: 13
    TargetObject|contains: '\Image File Execution Options\'
    TargetObject|contains|all:
      - 'Debugger'
  winlogon:
    EventID: 13
    TargetObject|contains: '\CurrentVersion\Winlogon\'
    TargetObject|contains:
      - 'Shell'
      - 'Userinit'
      - 'Notify'
  appinit:
    EventID: 13
    TargetObject|contains: 'AppInit_DLLs'
  com_hijack:
    EventID: 13
    TargetObject|contains: 'HKCU\Software\Classes\CLSID'
    TargetObject|contains: 'InprocServer32'
  suspicious_path:
    Details|contains:
      - '\Users\Public\'
      - '\AppData\Local\Temp\'
      - '\ProgramData\'
      - 'powershell'
      - 'mshta'
      - 'rundll32'
      - 'regsvr32'
      - 'wscript'
      - 'cscript'
  condition: ifeo or winlogon or appinit or (run_keys and suspicious_path) or com_hijack
fields:
  - TargetObject
  - Details
  - Image
  - User
falsepositives:
  - установка и обновление легитимного ПО (фильтруйте по подписанному Image)
  - COM-регистрация при инсталляции приложений
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1547.001
  - attack.t1546.012
```
