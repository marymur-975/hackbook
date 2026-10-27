---
id: windows-token-and-uac-bypass
title: "Windows: манипуляции с токенами и обход UAC"
type: privesc
target: windows
category: web
difficulty: advanced
bypass: none
tags: [privesc, windows, token-impersonation, uac-bypass, seimpersonate]
tested_on: ["Windows Server 2022", "Windows 11 (собственные ВМ)"]
success_rate: 0.5
risk: high
cwe: "CWE-269"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/techniques/T1134/"
  - "https://lolbas-project.github.io/"
---

# Windows: манипуляции с токенами и обход UAC

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) какие привилегии есть у текущей сессии
whoami /priv
# критичные: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege,
# SeDebugPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege,
# SeRestorePrivilege, SeLoadDriverPrivilege, SeTcbPrivilege

# 2) SeImpersonate/SeAssignPrimaryToken — классический путь к SYSTEM
#    (техника «Potato»-семейства: перехват аутентификации и запуск
#     процесса с токеном SYSTEM). Проверка наличия привилегии:
whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"
# кто обычно имеет: сервисные учётки (IIS APPPOOL, MSSQL, SQL Server
# Agent), задачи планировщика, NETWORK SERVICE

# 3) SeDebugPrivilege — доступ к памяти любого процесса
#    чтение секретов LSASS, инъекция в привилегированный процесс

# 4) SeBackupPrivilege / SeRestorePrivilege — чтение/запись любых файлов
#    (обход ACL): чтение SAM/SYSTEM, запись в Program Files

# 5) SeTakeOwnershipPrivilege — смена владельца файла и затем ACL

# 6) UAC: уровень и режим
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy
# auto-elevate бинарники с подписью Microsoft (fodhelper, computerdefaults,
# sdclt, wsreset) — техники обхода через подмену ассоциаций/HKCU-ключей
# (проверять на своей ВМ; конкретные команды намеренно не приводятся)
```

## Explanation

В Windows привилегии делятся на две группы: **права в ACL** и
**привилегии токена** (`whoami /priv`). Вторая группа часто упускается
из аудита, хотя даёт эскалацию без единой записи в ACL.

Ключевые привилегии:

* `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege` — позволяют
  создать процесс с чужим токеном. Сервисные учётки (IIS, MSSQL) имеют их
  по умолчанию: отсюда семейство техник «Potato», где процесс перехватывает
  аутентификацию SYSTEM и запускает код от его имени.
* `SeDebugPrivilege` — открывает любой процесс: чтение памяти LSASS
  (секреты, хеши), инъекция кода в привилегированный процесс.
* `SeBackupPrivilege` / `SeRestorePrivilege` — обход ACL при чтении/записи:
  чтение SAM/SYSTEM/NTDS.dit, запись в защищённые каталоги.
* `SeTakeOwnershipPrivilege` — смена владельца объекта, затем правка ACL.
* `SeLoadDriverPrivilege` — загрузка драйвера: доступ к ядру.
* `SeTcbPrivilege` — полная смена контекста (фактически SYSTEM).

**UAC-обход** — отдельный класс: это не «взлом», а использование
auto-elevate бинарников и доверия к подписанным компонентам (подмена
ассоциаций, HKCU-ключей, DLL-поиска). Практический смысл для защиты:
`EnableLUA=1`, `ConsentPromptBehaviorAdmin=2` (не 5), отключённый
`LocalAccountTokenFilterPolicy`, а главное — пользователь не должен быть
локальным администратором: тогда обход UAC не даёт ничего сверх прав
пользователя.

## Detection

* EventID 4672: «специальные привилегии назначены новому входу» —
  перечисляет привилегии токена; алерт при `SeDebugPrivilege`,
  `SeImpersonatePrivilege`, `SeTcbPrivilege` у не-администраторов.
* EventID 4673/4674: использование привилегированных операций
  (SeTakeOwnership, SeBackup, SeRestore, SeLoadDriver).
* Sysmon EventID 10 (ProcessAccess) с `GrantedAccess` на `lsass.exe`.
* Sysmon EventID 1: процессы, порождённые сервисными учётками
  (`IIS APPPOOL\...`, `NT AUTHORITY\SERVICE`) с `cmd.exe`/`powershell.exe`.
* Детект техник UAC-обхода: запуск `fodhelper.exe`, `computerdefaults.exe`,
  `sdclt.exe`, `wsreset.exe` с последующим порождением shell;
  изменения HKCU `Software\Classes\ms-settings\shell\open\command`.
* EventID 4688 с `IntegrityLevel` выше, чем у родителя (признак обхода UAC).
* EventID 7045, 4697 — новые службы.
* Контроль реестра: `EnableLUA`, `ConsentPromptBehaviorAdmin`,
  `LocalAccountTokenFilterPolicy` (Sysmon EventID 12/13).

## Remediation

- Убрать привилегии токена у сервисных учёток, где они не нужны
  (локальная политика безопасности: «Act as part of the operating system»,
  «Impersonate a client after authentication», «Debug programs»).
- Виртуальные сервисные учётки / gMSA вместо общих аккаунтов;
  запуск служб с минимальными правами (`NT AUTHORITY\NetworkService`
  вместо `LocalSystem`).
- Пользователи — не локальные администраторы; админ-доступ через
  отдельные учётки и PAM/JIT.
- UAC на максимум: `EnableLUA=1`, `ConsentPromptBehaviorAdmin=2`,
  `FilterAdministratorToken=1`, `LocalAccountTokenFilterPolicy=0`.
- Защита LSASS: `RunAsPPL=1`, Credential Guard, запрет доступа
  не-системных процессов.
- Запрет `SeLoadDriverPrivilege` у пользователей; контроль драйверов
  (HVCI/Memory Integrity, blocklist уязвимых драйверов).
- Аудит привилегий через GPO и регулярная сверка с baseline.


## Detection rules

```yaml
title: Назначение или использование опасных привилегий токена
id: c3d4e5f6-0008-4c3d-9e4f-000000000208
status: experimental
description: >-
  Пользователю назначены или использованы привилегии, дающие эскалацию
  (SeDebug, SeImpersonate, SeTcb, SeLoadDriver, SeBackup, SeRestore,
  SeTakeOwnership) вне ожидаемого контекста.
references:
  - https://attack.mitre.org/techniques/T1134/
  - https://attack.mitre.org/techniques/T1548/002/
logsource:
  product: windows
  service: security
  definition: 'аудит привилегий: события 4672-4674'
detection:
  assigned:
    EventID: 4672
    SeDebugPrivilege: 'present'
  used:
    EventID:
      - 4673
      - 4674
    PrivilegeList|contains:
      - 'SeDebugPrivilege'
      - 'SeImpersonatePrivilege'
      - 'SeAssignPrimaryTokenPrivilege'
      - 'SeTcbPrivilege'
      - 'SeLoadDriverPrivilege'
      - 'SeBackupPrivilege'
      - 'SeRestorePrivilege'
      - 'SeTakeOwnershipPrivilege'
  uac_bypass_processes:
    EventID: 1
    Image|endswith:
      - '\fodhelper.exe'
      - '\computerdefaults.exe'
      - '\sdclt.exe'
      - '\wsreset.exe'
      - '\slui.exe'
  condition: used or uac_bypass_processes
fields:
  - AccountName
  - PrivilegeList
  - Image
  - CommandLine
falsepositives:
  - резервное копирование (SeBackup) и восстановление (SeRestore) у профильных учёток
  - отладчики у разработчиков (SeDebug) — выносите в исключения по учётке и хосту
level: high
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1134
  - attack.t1548.002
```
