---
id: smb-signing-relay
title: "SMB: отсутствие подписи и relay-атака"
type: network
target: smb
category: network
difficulty: advanced
bypass: auth
tags: [smb, relay, signing, ntlm, active-directory]
tested_on: ["Windows Server 2019 (signing disabled)"]
success_rate: 0.4
risk: high
cwe: "CWE-345"
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
  - target: "privilege-escalation"
    type: leads_to
  - target: "credential-access"
    type: related_to
---

# SMB: отсутствие подписи и relay-атака

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay.txt
```

## Explanation

Если SMB-подпись не обязательна (`SMB signing: False`), аутентификацию NTLM можно
перехватить и «переложить» на другую машину: атакующий выступает прокси между жертвой
и целью. Жертва аутентифицируется на машине атакующего (через LLMNR/NBNS-spoofing,
вредоносную ссылку на `\\attacker\share`, или принуждение к аутентификации —
printer bug, WebClient), а её учётные данные применяются к цели.
Если у жертвы права локального администратора на цели — получаем выполнение команд.
Релейт также работает в LDAP/AD CS (сертификаты), HTTP (NTLM-эндпоинты), MSSQL.

## Detection

1. `crackmapexec smb <subnet> --gen-relay-list relay.txt` — список хостов без подписи.
2. `nmap --script smb2-security-mode -p445 <host>` -> `Message signing enabled but not required`.
3. В логах Windows: Event 4624 type 3 с необычного источника, аутентификации
   к хостам, куда пользователь не обращался; NTLM вместо Kerberos там, где ожидается Kerberos.
4. Признак в сети: LLMNR/NBT-NS трафик (порт 5355/137) — рассинхрон имён.

## Remediation

- SMB-подпись обязательна на всех хостах (GPO: `Microsoft network server/client:
  Digitally sign communications (always)`).
- Блокировать исходящий NTLM наружу; включить `RestrictSendingNTLMTraffic`.
- Отключить LLMNR (GPO `Turn off multicast name resolution`) и NBT-NS.
- Переход на Kerberos, отключение NTLM там, где возможно.
- LDAP-подпись и LDAPS-channel-binding для контроллеров домена.
- EPA (Extended Protection for Authentication) на веб-сервисах с NTLM.
- Сегментация и LAPS/группа «локальные администраторы уникальны» — relay теряет смысл
  без прав на цели.

## Detection rules

```yaml
title: NTLM-relay — сетевой вход машинной учётки с чужого IP
id: a7b8c9d0-0006-4a7b-9c8d-000000000006
status: experimental
description: >-
  Event 4624 (LogonType 3, NTLM), где TargetUserName — машинная учётка ($),
  а IpAddress не совпадает с зарегистрированным адресом узла: атакующий
  ретранслировал NTLM-аутентификацию (signing не обязателен).
references:
  - https://attack.mitre.org/techniques/T1557/001/
logsource:
  product: windows
  service: security
  definition: 'аудит logon-событий; для точности сопоставляйте IpAddress с CMDB/DNS'
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    TargetUserName|endswith: '$'
  filter_dc:
    TargetUserName:
      - DC01$
      - DC02$
  condition: selection and not filter_dc
fields:
  - TargetUserName
  - IpAddress
  - LogonProcessName
falsepositives:
  - легитимный межсерверный NTLM (файловые кластеры, легаси-интеграции) —
    сверяйте IpAddress с инвентаризацией узла; целевое состояние — SMB signing
    required и отказ от NTLM
level: high
tags:
  - attack.credential_access
  - attack.t1557.001
  - cwe.294
```
