---
id: ad-laps-misconfiguration
title: "LAPS: чтение локальных админ-паролей и типовые ошибки настройки"
type: ad
target: active-directory
category: active-directory
difficulty: intermediate
bypass: auth
tags: [laps, local-admin, permissions, credential-access, active-directory]
tested_on: ["Legacy LAPS (AdmPwd)", "Windows LAPS (Server 2025 / 2022+)"]
success_rate: 0.45
risk: high
cwe: "CWE-732"
lab: null
last_verified: "2026-10-23"
references:
  - "https://learn.microsoft.com/en-us/windows-server/identity/"
  - "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
graph:
  - target: "credential-access"
    type: instance_of
  - target: "active-directory"
    type: related_to
  - target: "lateral-movement"
    type: related_to
  - target: "privilege-escalation"
    type: leads_to
---

# LAPS: чтение локальных админ-паролей и типовые ошибки настройки

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# кто может читать пароль LAPS (ExtendedRight на ms-Mcs-AdmPwd)
(Get-Acl 'AD:\OU=Servers,DC=lab,DC=local').Access |
  ? { $_.ObjectType -match 'ms-Mcs-AdmPwd' -or
        $_.IdentityReference -match 'Domain Users|Everyone|Authenticated' } |
  ft IdentityReference, ActiveDirectoryRights, ObjectType -Auto

# покрытие: у каких машин пароль вообще не управляется LAPS
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime |
  ? { -not $_.'ms-Mcs-AdmPwdExpirationTime' } | select Name
```

## Explanation

LAPS хранит уникальный локальный админ-пароль каждой машины в атрибуте
`ms-Mcs-AdmPwd` (legacy) или в зашифрованном виде (Windows LAPS) и ротирует
его по расписанию. Это закрывает главную проблему домена — одинаковый
локальный админ на всех хостах (pass-the-hash по всему парку).

Но LAPS сам становится целью при ошибках настройки:

1. Право чтения атрибута выдано слишком широко (`Domain Users`, группа
    техподдержки со всеми участниками, наследование от корневого OU).
2. `AllExtendedRights`/`GenericAll` на OU компьютеров — включает чтение пароля.
3. Legacy LAPS хранит пароль **в открытом виде** в атрибуте: чтение права =
    локальный админ на всех машинах OU.
4. LAPS включён не везде: часть парка остаётся с общим паролем
    (проверка по `ms-Mcs-AdmPwdExpirationTime`).
5. Клиент LAPS не обновлён на хостах — пароль не ротируется, значение устаревает.
6. Пароль не сбрасывается при отзыве доступа (чтение исторических значений
    из бэкапов AD, из реплик, из снятых образов).
7. Права на сброс пароля (`ms-Mcs-AdmPwdResetPassword`) у тех, кому это не нужно.

## Detection

1. Аудит ACE на OU компьютеров: кто имеет `ReadProperty`/`ExtendedRight` на
   `ms-Mcs-AdmPwd` и `ms-Mcs-AdmPwdResetPassword`.
2. **Event 4662** с `Properties` включающими GUID атрибута LAPS и субъектом,
   не входящим в разрешённый список (нужен SACL на OU).
3. Coverage-отчёт: компьютеры без `ms-Mcs-AdmPwdExpirationTime` (LAPS не
   применяется) и с истёкшим сроком (ротация не работает).
4. Аномалии: массовое чтение атрибутов компьютеров одной учёткой
   (LDAP-запросы к `ms-Mcs-AdmPwd`).
5. Проверить наличие одинаковых локальных хешей на разных хостах
   (признак, что LAPS не работает).
6. Инструменты: `LAPSToolkit`, PingCastle-правила, PowerShell-аудит ACE.

## Remediation

- Мигрировать на **Windows LAPS** (шифрует пароль в AD, поддерживает аудит
  чтения и историю) вместо legacy AdmPwd.
- Право чтения — только у конкретных ролей (helpdesk-группа по области),
  никакого `Domain Users`/`Everyone`; убрать наследуемые ACE с корневого OU.
- Включить SACL-аудит чтения атрибута и алертить на каждый доступ
  (чтение пароля LAPS должно быть редким и объяснимым событием).
- Покрытие 100% доменных машин + проверка, что клиент LAPS обновлён;
  политика ротации ≤ 30 дней и сброс при смене администратора.
- Уникальное имя локальной админ-учётки (не `Administrator`) — усложняет
  автоматизированный pass-the-hash.
- При компрометации: немедленно сбросить пароли LAPS на затронутых OU,
  проверить бэкапы AD на наличие исторических значений.
- Локальные админы не должны иметь доменных привилегий; tiering.

## Detection rules

```yaml
title: Чтение LAPS-пароля (ms-Mcs-AdmPwd) не привилегированной учёткой
id: a7b8c9d0-0010-4a7b-9c8d-000000000010
status: experimental
description: >-
  Event 4662 с Properties ms-Mcs-AdmPwd: кто-то читает локальный пароль
  администратора машины из LAPS. Если читает не helpdesk-группа или читает
  массово — это горизонтальное перемещение (пароль = локальный админ на узле).
references:
  - https://attack.mitre.org/techniques/T1552/
  - https://adsecurity.org/?p=3164
logsource:
  product: windows
  service: security
  definition: 'SACL Directory Service Access на атрибуте ms-Mcs-AdmPwd (компьютеры)'
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - 'ms-Mcs-AdmPwd'
      - 'msLAPS-Password'
  filter_laps_admins:
    SubjectUserName|contains:
      - 'svc_laps'
      - 'lapsadmin'
  condition: selection and not filter_laps_admins
fields:
  - SubjectUserName
  - ObjectName
  - Properties
falsepositives:
  - легитимный helpdesk, получающий пароль через UI LAPS/Windows LAPS —
    ведите список групп и дополняйте filter_laps_admins
level: high
tags:
  - attack.credential_access
  - attack.t1552
  - cwe.522
```
