---
id: ad-gpp-cpassword-sysvol
title: "GPP cPassword в SYSVOL: пароли в политике (MS14-025)"
type: ad
target: active-directory
category: active-directory
difficulty: beginner
bypass: none
tags: [gpo, sysvol, cpassword, credentials, active-directory]
tested_on: ["SYSVOL с историческими Groups.xml", "Windows Server 2008 R2/2012 артефакты"]
success_rate: 0.35
risk: high
cwe: "CWE-256"
lab: null
last_verified: "2026-10-23"
references:
  - "https://adsecurity.org/"
  - "https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-management/admin-security-settings-not-applied"
graph:
  - target: "gpo"
    type: instance_of
  - target: "credential-access"
    type: leads_to
  - target: "info-disclosure"
    type: leads_to
  - target: "lateral-movement"
    type: leads_to
---

# GPP cPassword в SYSVOL: пароли в политике (MS14-025)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# поиск артефактов GPP в SYSVOL (чтение доступно любому пользователю домена)
smbclient //dc01.lab.local/SYSVOL -U 'lab\\user%Passw0rd!' -c \
  'recurse on; prompt off; mget *Groups.xml *Services.xml *ScheduledTasks.xml *DataSources.xml'

grep -rniE 'cpassword|<Properties .*password' ./lab.local/Policies/ 2>/dev/null
```

## Explanation

Group Policy Preferences позволяли задать локальную учётку/пароль через политику.
Пароль хранился в XML-файлах SYSVOL (`Groups.xml`, `Services.xml`,
`ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`) в атрибуте
`cPassword`, «зашифрованном» AES-ключом, который Microsoft **опубликовала**
в документации. То есть значение расшифровывается кем угодно, кто может
прочитать SYSVOL — а это любой аутентифицированный пользователь домена.

MS14-025 (2014) запретил задавать пароль через GPP, но **существующие файлы
остались** в SYSVOL тысяч организаций и до сих пор находятся аудитах:
пароли там часто совпадают с актуальными (локальный админ на всех машинах OU).

Родственный класс — всё, что лежит в SYSVOL и читаемо всем: скрипты входа
с учётными данными внутри, `net use \\share /user:x password`, подключённые
диски, инсталляторы с параметрами, `.ps1` с `$cred = ...`.

## Detection

1. Прочитать SYSVOL (доступен любому пользователю домена) и найти файлы
   политик: `\\<domain>\SYSVOL\<domain>\Policies\<GUID>\Machine\Preferences\`.
2. Поиск по содержимому: `cPassword`, `password=`, `/user:`, `ConvertTo-SecureString`
   с literal-значениями, `-Password` в аргументах задач.
3. Проверить не только активные политики, но и архивы/бэкапы GPO, SYSVOL-реплики
   на всех DC, а также DFS-копии.
4. В логах: аномально массовое чтение SYSVOL одной учёткой
   (Event 5145 с путями `\SYSVOL\...\Policies\*`).
5. Инструменты аудита: PingCastle, GPP-сканеры в CIRT-наборах.

## Remediation

- Удалить все GPP-файлы с `cPassword` из SYSVOL (и из бэкапов политик!),
  затем **сменить** все затронутые пароли: сам факт удаления не отзывает пароль.
- Заменить на LAPS/Windows LAPS (уникальные локальные админ-пароли с ротацией)
  или на gMSA для служб.
- Провести аудит всего SYSVOL на предмет секретов в скриптах и задачах;
  ввести правило CI/сканера: никаких literal-паролей в GPO-скриптах.
- Мониторинг 5145 на массовое чтение SYSVOL.
- Процесс: хранение секретов только в vault, доступ по ролям, ротация;
  запрет «пароль в политике» в стандарте конфигурации.
- Проверить, не использовался ли найденный пароль на других системах
  (переиспользование — обычное дело).

## Detection rules

```yaml
title: Чтение GPP-файлов из SYSVOL — поиск cpassword
id: a7b8c9d0-0009-4a7b-9c8d-000000000009
status: experimental
description: >-
  Массовое чтение Groups.xml/Services.xml/ScheduledTasks.xml/DataSources.xml
  из SYSVOL не-администратором (event 4663): в них могут лежать зашифрованные
  AES-256 ключом Microsoft (давно опубликован) пароли cpassword.
references:
  - https://attack.mitre.org/techniques/T1552/006/
logsource:
  product: windows
  service: security
  definition: 'SACL Object Access на шаре SYSVOL + сетевой доступ к \\\\dc\\SYSVOL'
detection:
  sysvol_path:
    EventID: 4663
    ObjectName|contains: 'SYSVOL'
  gpp_files:
    ObjectName|contains:
      - 'Groups.xml'
      - 'Services.xml'
      - 'ScheduledTasks.xml'
      - 'DataSources.xml'
      - 'Printers.xml'
      - 'Drives.xml'
  condition: sysvol_path and gpp_files
fields:
  - SubjectUserName
  - ObjectName
  - IpAddress
falsepositives:
  - применение политик самими DC (исключайте машинные учётки DC) и аудит
    безопасности — сверяйте с расписанием сканов
level: high
tags:
  - attack.credential_access
  - attack.t1552.006
  - cwe.312
```
