---
id: windows-credential-harvesting
title: "Windows: локальные учётные данные — LSASS, SAM, кэши, автологон"
type: privesc
target: windows
category: web
difficulty: advanced
bypass: none
tags: [privesc, windows, lsass, sam, credentials, cached-creds, gpp]
tested_on: ["Windows Server 2022 (собственная ВМ)"]
success_rate: 0.5
risk: critical
cwe: "CWE-522"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/techniques/T1003/"
  - "https://lolbas-project.github.io/"
---

# Windows: локальные учётные данные — LSASS, SAM, кэши, автологон

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# ВСЁ — только на своей ВМ. Команды показаны для понимания мест хранения;
# использование на чужих системах незаконно.

# 1) автологон и секреты в реестре
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v Security Packages

# 2) SAM/SYSTEM/SECURITY — офлайн-извлечение хешей локальных учёток
#    (требует прав администратора; чтение через VSS или reg save на своей ВМ)
# reg save HKLM\SAM C:\Temp\sam.hiv && reg save HKLM\SYSTEM C:\Temp\sys.hiv

# 3) кэш доменных учётных данных (DCC2) — HKLM\SECURITY\Cache
#    нужен для офлайн-подбора при недоступности DC

# 4) LSASS — процесс с билетами Kerberos, NTLM-хешами, паролями (WDigest)
#    доступ к памяти требует SeDebugPrivilege; защита: RunAsPPL, Credential Guard

# 5) хранилище учётных данных Windows
cmdkey /list
# 6) планировщик: пароли в задачах
schtasks /query /fo LIST /v | findstr /i "TaskName Run As Task To Run"
type C:\Windows\System32\Tasks\* 2>nul | findstr /i "<UserId> <Command>"

# 7) IIS: пароли в appcmd/конфигах (ApplicationHost.config)
# 8) сервисы: пароли в binPath (sc qc <svc>)
sc qc | findstr /i "BINARY_PATH_NAME" | findstr /i "password\|pwd"

# 9) GPP-пароли в SYSVOL (устаревшие, но встречаются): Groups.xml с cpassword
# 10) Unattend/Panther: C:\Windows\Panther\Unattend.xml, autounattend.xml
# 11) файлы на дисках: *.kdbx, *.ppk, id_rsa, web.config, .env, *.config
# 12) история PowerShell: C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

## Explanation

Локальная эскалация часто идёт не через уязвимость, а через **найденные
учётные данные**: пароль администратора в задаче планировщика, автологон,
конфиге приложения или истории PowerShell. Полный список мест хранения —
это одновременно чек-лист аудита и чек-лист защиты.

Классы источников:

* **Память LSASS**: NTLM-хеши, Kerberos-билеты, пароли в открытом виде
  (при включённом WDigest). Требует `SeDebugPrivilege` или локального
  администратора.
* **SAM/SYSTEM/SECURITY в реестре**: хеши локальных учёток и кэш доменных
  паролей (DCC2).
* **DPAPI**: защищённые секреты приложений (браузеры, почта, RDP-клиент),
  расшифровываются в контексте пользователя.
* **Планировщик и службы**: пароли в XML-задачах и в `binPath`.
* **Конфигурации**: IIS `ApplicationHost.config`, `web.config` (строки
  подключения), `.env`, unattend-файлы, `Panther`.
* **История и артефакты**: PSReadline history, `.bash_history` в WSL,
  файлы на общих ресурсах, `*.kdbx`, приватные SSH-ключи.
* **GPP `cpassword`**: устаревшая, но всё ещё встречающаяся схема
  хранения паролей групповых политик (ключ опубликован Microsoft).

Практический вывод для защиты: большинство этих мест закрывается
не «секретным хранилищем», а гигиеной — отсутствие паролей в файлах,
gMSA для служб, LAPS для локальных админов, Credential Guard и PPL
для LSASS.

## Detection

* Sysmon EventID 10 (ProcessAccess) на `lsass.exe` с `GrantedAccess`
  0x1010/0x1410/0x1438/0x1fffff — классический признак дампа.
* EventID 4663/4656: доступ к `HKLM\SAM`, `HKLM\SECURITY`, `HKLM\SYSTEM`.
* EventID 4688: `reg save`, `vssadmin create shadow`, `ntdsutil`,
  `diskshadow`, `wmic shadowcopy`, `esentutl`, `rundll32 comsvcs.dll,
  MiniDump`.
* EventID 11 (Sysmon): создание файлов `sam.hiv`, `system.hiv`,
  `*.dmp` в нестандартных каталогах.
* EventID 4624 type 9 (NewCredentials) и type 3 с NTLM вместо Kerberos.
* Чтение `ConsoleHost_history.txt`, `Unattend.xml`, `Groups.xml`
  нетипичными процессами.
* Алерт на появление `cpassword` в SYSVOL (скан групповых политик).
* Credential Guard/PPL: попытка доступа к LSASS блокируется и логируется.

## Remediation

- LAPS (Windows LAPS) для паролей локальных администраторов: уникальные,
  ротируемые, в защищённом хранилище AD.
- gMSA для служб и задач планировщика вместо паролей в конфигурации.
- Credential Guard + HVCI + `RunAsPPL=1` (LSASS как protected process).
- Отключить WDigest (`UseLogonCredential=0`), запретить кэширование
  доменных учётных данных на рабочих станциях (`CachedLogonsCount`).
- Запрет хранения паролей: автологон, `DefaultPassword`, пароли в
  `binPath` служб, unattend-файлы (удалять после установки),
  GPP-пароли (убрать из SYSVOL).
- Секреты приложений — в vault/Key Vault/Secrets Manager, не в конфигах.
- Ограничить админ-доступ: отдельные учётки, JIT/PAM, запрет
  интерактивного входа доменных админов на рабочие станции.
- Мониторинг и алерты на доступ к LSASS и теневым копиям.
- Регулярный скан файловых ресурсов на пароли и ключи (secret scanning).


## Detection rules

```yaml
title: Доступ к LSASS или извлечение SAM/SYSTEM/NTDS
id: c3d4e5f6-0009-4c3d-9e4f-000000000209
status: stable
description: >-
  Открытие процесса lsass.exe сторонним процессом, создание теневых копий,
  reg save системных кустов, dump-файлы в нестандартных каталогах.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/003/
logsource:
  product: windows
  service: sysmon
  definition: 'Sysmon EventID 1, 10, 11; Security 4663/4688'
detection:
  lsass_access:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
      - '0x1fffff'
  shadow_copy:
    EventID: 1
    Image|endswith:
      - '\vssadmin.exe'
      - '\wmic.exe'
      - '\diskshadow.exe'
      - '\ntdsutil.exe'
      - '\esentutl.exe'
    CommandLine|contains:
      - 'shadowcopy'
      - 'create shadow'
      - 'backup'
  reg_save:
    EventID: 1
    Image|endswith: '\reg.exe'
    CommandLine|contains:
      - 'save'
      - 'HKLM\sam'
      - 'HKLM\system'
      - 'HKLM\security'
  comsvcs_dump:
    EventID: 1
    CommandLine|contains:
      - 'comsvcs.dll'
      - 'MiniDump'
  dump_file:
    EventID: 11
    TargetFilename|contains:
      - '\lsass'
      - '.dmp'
  condition: lsass_access or shadow_copy or reg_save or comsvcs_dump or dump_file
fields:
  - Image
  - CommandLine
  - TargetImage
  - User
falsepositives:
  - антивирусы и EDR-агенты (исключайте по подписи и пути)
  - легитимные операции резервного копирования (выделенная учётка, расписание)
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003.002
  - attack.t1003.003
```
