---
id: smb-null-session
title: "SMB: null session и перечисление через RPC"
type: network
target: smb
category: network
difficulty: intermediate
bypass: auth
tags: [smb, rpc, enumeration, windows]
tested_on: ["Windows Server 2019 (RestrictAnonymous=1)", "Samba 4"]
success_rate: 0.5
risk: medium
cwe: "CWE-287"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0006/"
  - "https://adsecurity.org/"
graph:
  - target: "network"
    type: instance_of
  - target: "active-directory"
    type: related_to
  - target: "enumeration"
    type: leads_to
---

# SMB: null session и перечисление через RPC

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
rpcclient -U '' -N 10.10.10.5
```

## Explanation

Анонимное подключение к IPC$ (пустые логин/пароль) открывает доступ к части RPC-интерфейсов:
перечисление пользователей, групп, общих ресурсов, политик паролей, информации о домене.
В современных Windows по умолчанию `RestrictAnonymous=1`, поэтому объём данных ограничен,
но в доменной среде и на старых системах часто доступно многое.
Полезные команды `rpcclient`: `enumdomusers`, `enumdomgroups`, `querydominfo`,
`enumprivs`, `lsaquery` (получение SID домена), `srvinfo`.
Через SMB также проверяются подписи и возможность relay (см. `smb-signing-relay`).

## Detection

1. `nmap --script smb-enum-users,smb-enum-shares,smb-os-discovery -p445 <host>`.
2. `crackmapexec smb <host> -u '' -p '' --shares --users`.
3. `smbclient -L //<host> -N`.
4. В логах Windows: Event ID 4624 с типом входа 3 и пустым именем,
   5140 (доступ к IPC$).

## Remediation

- `RestrictAnonymous=1` и `RestrictAnonymousSAM=1`; политика
  «Network access: Do not allow anonymous enumeration of SAM accounts and shares».
- Отключить гостевой доступ к SMB, запретить незащищённые гостевые входы.
- Требовать SMB-подпись (mandatory), SMBv1 отключить полностью.
- Сегментация: 445/139 не должны быть доступны из пользовательских VLAN наружу.
- Аудит анонимных сессий и включение LSA protection.

## Variants

```
smbclient -L //10.10.10.5 -N
```

```
crackmapexec smb 10.10.10.5 -u '' -p '' --users
```

```
enum4linux -a 10.10.10.5
```

## Detection rules

```yaml
title: SMB null-сессия — анонимный сетевой вход и доступ к IPC$
id: a7b8c9d0-0005-4a7b-9c8d-000000000005
status: experimental
description: >-
  Event 4624 (LogonType 3) для ANONYMOUS LOGON и/или записи smbd о NULL-сессии
  и анонимном доступе к IPC$ — перечисление шар, пользователей и пайпов
  без учётных данных.
references:
  - https://attack.mitre.org/techniques/T1087/002/
  - https://attack.mitre.org/techniques/T1135/
logsource:
  product: windows
  service: security
  definition: 'аудит logon-событий + журнал smbd (Samba) для не-Windows узлов'
detection:
  selection_windows:
    EventID: 4624
    LogonType: 3
    TargetUserName|contains: 'ANONYMOUS'
  selection_samba:
    service: smbd
    message|contains:
      - 'NULL session'
      - 'anonymous'
  condition: selection_windows or selection_samba
fields:
  - IpAddress
  - TargetUserName
  - source_ip
  - message
falsepositives:
  - легаси-устройства (принтеры, сканеры), опрашивающие IPC$ — выносите по IpAddress;
    глобально лечится RestrictAnonymous=1
level: medium
tags:
  - attack.discovery
  - attack.t1087.002
  - attack.t1135
  - cwe.306
```
