---
id: windows-enumeration-checklist
title: "Windows: систематическая разведка для эскалации привилегий"
type: privesc
target: windows
category: web
difficulty: beginner
bypass: none
tags: [privesc, windows, enumeration, methodology, recon]
tested_on: ["Windows Server 2022", "Windows 11 (собственные ВМ)"]
success_rate: 0.9
risk: low
cwe: "CWE-200"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/techniques/T1082/"
  - "https://lolbas-project.github.io/"
  - "https://github.com/carlospolop/PEASS-ng"
---

# Windows: систематическая разведка для эскалации привилегий

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1. контекст и права
whoami /all & whoami /priv
net user %USERNAME% & net localgroup Administrators
systeminfo | findstr /i "OS Name Version Hotfix"
wmic qfe get HotFixID,InstalledOn | more

# 2. процессы, службы, драйверы
tasklist /svc | more
sc query state= all | findstr SERVICE_NAME
driverquery /v | findstr /i "Running"

# 3. сеть и локальные сервисы
netstat -ano | findstr LISTENING
netsh advfirewall show allprofiles state

# 4. установленное ПО и пути
wmic product get name,version,vendor 2>nul
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr DisplayName

# 5. записываемые каталоги в PATH и Program Files
echo %PATH%
icacls "C:\Program Files" | findstr /i "Users"
for /d %d in ("C:\Program Files\*") do @icacls "%d" 2>nul | findstr /i "Users:(M) Users:(F)" >nul && echo WRITABLE: %d

# 6. планировщик, автозапуск, реестр
schtasks /query /fo LIST /v | findstr /i "TaskName Run As Task To Run"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# 7. учётные данные в файлах и истории
cmdkey /list
type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" 2>nul
dir /s /b C:\*.config C:\*.txt C:\*.xml 2>nul | findstr /i "unattend web.config appsettings" | more
findstr /si password C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini C:\inetpub\wwwroot\web.config 2>nul

# 8. групповые политики и SYSVOL
gpresult /h %TEMP%\gp.html & start %TEMP%\gp.html

# 9. защита и телеметрия (что включено)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -GetFiles 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell /s 2>nul

# автоматизация (только на своём стенде): winPEAS.exe, Seatbelt, SharpUp
```

## Explanation

Как и в Linux, разведка даёт больше, чем эксплойты. Порядок обхода:

1. **Контекст**: `whoami /priv` показывает привилегии токена
    (см. `windows-token-and-uac-bypass`), `net localgroup` — членство
    в группах (`Backup Operators`, `Print Operators`, `Hyper-V Admins`
    дают эскалацию).
2. **Патч-уровень**: `systeminfo` + `wmic qfe`; сравнивать с датой
    выпуска критичных обновлений.
3. **Службы и binPath**: права на объекты служб, права на файлы,
    unquoted paths (`windows-service-permissions`).
4. **Планировщик**: задачи от SYSTEM с записываемыми файлами.
5. **Автозапуск и реестр**: Run-ключи, IFEO, Winlogon
    (`windows-registry-and-startup`).
6. **PATH и Program Files**: записываемые каталоги — DLL hijacking.
7. **Учётные данные**: автологон, задачи, IIS-конфиги, unattend,
    история PowerShell, `cmdkey`, файлы на дисках
    (`windows-credential-harvesting`).
8. **Установленное ПО**: известные уязвимые версии (старые Java, Node,
    Python, Tomcat, Jenkins, Git, Putty) — у них бывают локальные
    уязвимости и слабые ACL.
9. **Защита**: включён ли Defender/Credential Guard/AMSI/Script Block
    Logging — от этого зависит выбор техник и уровень шума.

Группы, дающие эскалацию без эксплойтов: `Backup Operators`
(чтение/запись любых файлов), `Print Operators`, `Server Operators`,
`Account Operators`, `Hyper-V Administrators`, `DnsAdmins`,
`Power Users` (на старых системах).

## Detection

* EventID 4688 с включённой командной строкой: паттерны `whoami /priv`,
  `net localgroup`, `sc query`, `schtasks /query /v`, `reg query ... Run`,
  `icacls`, `systeminfo` от одной сессии за короткое время.
* Детект инструментов перечисления: `winPEAS`, `Seatbelt`, `SharpUp`,
  `PowerUp.ps1`, `JAWS`, `Windows-Exploit-Suggester`
  (имена процессов, хеши, строки в PowerShell-логах).
* PowerShell Script Block Logging (EventID 4104) — ловит obfuscated
  перечисление.
* Аномальный объём чтения файлов в `C:\Users\*` и `C:\Program Files`
  от одной сессии.
* `cmdkey /list`, чтение `ConsoleHost_history.txt`, `findstr /si password`
  — индикаторы поиска учётных данных.
* Поведенческий детект: последовательность «whoami → net localgroup →
  sc query → icacls» от новой сессии (типичный сценарий после foothold).

## Remediation

- Минимизация локальных прав: пользователи не в `Administrators`;
  отдельные привилегированные учётки (LAPS для локальных админов).
- Убрать «опасные» членства в группах (`Backup Operators`,
  `Print Operators` и т.п.) там, где они не нужны.
- Включить PowerShell Script Block Logging, Transcription, Module Logging;
  AMSI; Constrained Language Mode для непривилегированных.
- Включить command-line auditing (EventID 4688 с аргументами) —
  без него детект перечисления невозможен.
- Defender ASR-правила в режиме block для рабочих станций.
- Патч-менеджмент с SLA; инвентаризация ПО и удаление неиспользуемого.
- ACL-гигиена: `Program Files` и системные каталоги без записи
  для `Users`; проверка в CI для собственных установщиков.
- Хранить логи вне хоста (WEF/SIEM), иначе атакующий их очищает.


## Detection rules

```yaml
title: Последовательность команд перечисления Windows (post-exploitation recon)
id: c3d4e5f6-0012-4c3d-9e4f-000000000212
status: experimental
description: >-
  Несколько команд разведки прав, служб и учётных данных от одной сессии
  за короткое время — типичное поведение после получения первичного доступа.
references:
  - https://attack.mitre.org/techniques/T1082/
  - https://attack.mitre.org/techniques/T1087/001/
  - https://attack.mitre.org/techniques/T1007/
logsource:
  product: windows
  service: security
  definition: 'EventID 4688 с аудитом командной строки'
detection:
  discovery:
    EventID: 4688
    CommandLine|contains:
      - 'whoami /priv'
      - 'whoami /all'
      - 'net localgroup'
      - 'net user'
      - 'systeminfo'
      - 'sc query'
      - 'sc qc'
      - 'schtasks /query'
      - 'tasklist /svc'
      - 'driverquery'
      - 'wmic qfe'
      - 'icacls'
      - 'accesschk'
      - 'cmdkey /list'
      - 'reg query'
      - 'netstat -ano'
      - 'findstr /si password'
  tools:
    EventID: 4688
    CommandLine|contains:
      - 'winpeas'
      - 'seatbelt'
      - 'sharpup'
      - 'powerup.ps1'
      - 'jaws.ps1'
      - 'sherlock'
      - 'watson'
  timeframe: 10m
  condition: tools or (discovery | count() by LogonId > 8)
fields:
  - CommandLine
  - ParentProcessName
  - AccountName
  - LogonId
falsepositives:
  - администраторы при диагностике (сужайте по ParentProcessName и учётке)
  - инвентаризационные агенты и сканеры уязвимостей
level: medium
tags:
  - attack.discovery
  - attack.t1082
  - attack.t1087.001
  - attack.t1007
```
