---
id: ad-acl-abuse-genericall
title: "ACL-эскалация: GenericAll/WriteDacl/ForceChangePassword/AddMembers"
type: ad
target: active-directory
category: active-directory
difficulty: advanced
bypass: auth
tags: [acl, permissions, privilege-escalation, bloodhound, active-directory]
tested_on: ["Windows Server 2019/2022", "типовые «исторические» ACE"]
success_rate: 0.5
risk: critical
cwe: "CWE-269"
lab: null
last_verified: "2026-10-23"
references:
  - "https://adsecurity.org/"
  - "https://attack.mitre.org/techniques/T1098/"
graph:
  - target: "privilege-escalation"
    type: instance_of
  - target: "active-directory"
    type: related_to
  - target: "credential-access"
    type: leads_to
  - target: "delegation"
    type: related_to
---

# ACL-эскалация: GenericAll/WriteDacl/ForceChangePassword/AddMembers

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# опасные ACE на привилегированной группе
Get-Acl 'AD:\CN=Domain Admins,CN=Users,DC=lab,DC=local' |
  Select -Expand Access |
  ? { $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|ExtendedRight' } |
  ft IdentityReference, ActiveDirectoryRights, ObjectType, AccessControlType -Auto

# что разрешено конкретной учётке
Get-ADPermission -Identity 'CN=Domain Admins,CN=Users,DC=lab,DC=local' |
  ? { $_.ExtendedRights -match 'User-Force-Change-Password|DS-Replication' }
```

## Explanation

Права в AD хранятся как ACL на объектах. Исторически накопленные ACE
(от установщиков, «временных» настроек, делегирования задач) дают ordinary
пользователю возможности, эквивалентные админским:

| Право | Что даёт |
|-------|----------|
| `GenericAll` на пользователя | смена пароля, добавление SPN (kerberoast), настройка RBCD |
| `GenericAll` на группу | добавление себя в группу |
| `GenericAll` на компьютер | RBCD, чтение LAPS-пароля (если включён) |
| `WriteDacl` | выдать себе любые права, включая Full Control |
| `WriteOwner` | стать владельцем -> поменять DACL |
| `ForceChangePassword` (`User-Force-Change-Password`) | смена пароля цели без знания старого |
| `AddMembers` / `Self-Membership` | вступление в привилегированную группу |
| `GenericWrite` на пользователя | записать `scriptPath`, `profilePath` -> выполнение кода при входе |
| `DS-Replication-Get-Changes(-All)` | DCSync: дамп всех хешей домена |
| `CreateChild` + `WriteProperty` на OU | наследуемые права на все объекты OU |

BloodHound автоматизирует поиск таких путей; но ценность не в инструменте,
а в инвентаризации ACE — её надо делать регулярно и на всех tier-0 объектах.

## Detection

1. Регулярный экспорт и diff прав: `Get-Acl`/`ADRecon`/`PingCastle` —
   сравнивать с baseline, алертить на новые ACE для не-админ субъектов.
2. **Event 5136** (изменение объекта каталога, атрибут `ntSecurityDescriptor`)
   и **4662** с доступом к `WriteDacl`/`WriteOwner`.
3. **Event 4728/4732/4756** — добавление в глобальные/локальные/universal группы
   безопасности; алерт на добавление в Domain/Enterprise/Schema Admins.
4. **Event 4724** — попытка сброса пароля другим пользователем.
5. Аномалии: обычная учётка меняет пароль привилегированной, добавляет SPN
   (Event 5136 на `servicePrincipalName`), правит `msDS-AllowedToActOnBehalf…`.
6. Поиск «коротких путей» в BloodHound: `MATCH p=shortestPath((u:User)-[*1..4]->(g:Group))
   WHERE g.name =~ '.*ADMINS.*'`.

## Remediation

- Ревизия ACE на tier-0 объектах (Domain Admins, DC, OU админ-групп,
  krbtgt, объекты с `AdminCount=1`): удалить наследуемые от обычных
  пользователей/групп права; `AdminSDHolder` должен содержать только нужные ACE.
- Запретить обычным пользователям `WriteDacl`/`WriteOwner`/`GenericAll`
  на привилегированных объектах; делегировать задачи точечно
  (конкретное ExtendedRight, конкретный OU).
- `ms-DS-MachineAccountQuota = 0`; право `Add/Remove self` из групп убрать.
- LAPS (или Windows LAPS) для локальных админов: чтение пароля — только
  у авторизованных ролей, аудит чтения (Event 4662 на `ms-Mcs-AdmPwd`).
- Tiering + Protected Users + Authentication Policies.
- Процессы: ежеквартальный access review привилегий, baseline прав в git,
  автоматический diff и алерт на отклонения.
- Аудит 4662/5136 включён и уходит в SIEM (без этого изменения ACL невидимы).


## Detection rules

```yaml
title: Добавление участника в привилегированную группу AD
id: a1b2c3d4-0005-4a1b-9c1d-000000000005
status: stable
description: >-
  Events 4728/4732/4756/4761 для групп, содержащих Admins/Operators.
  Легитимные изменения редки и должны соответствовать заявке.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4728    # добавление в глобальную группу
      - 4732    # добавление в локальную группу
      - 4756    # добавление в universal-группу
      - 4761    # добавление в универсальную группу (alt)
    GroupName:
      - 'Domain Admins'
      - 'Enterprise Admins'
      - 'Schema Admins'
      - 'Administrators'
      - 'Account Operators'
      - 'Backup Operators'
      - 'Server Operators'
      - 'Print Operators'
      - 'Group Policy Creator Owners'
      - 'DnsAdmins'
  filter_print:
    GroupName:
      - 'Print Operators'               # пример осознанного исключения
  condition: selection and not filter_print
falsepositives:
  - плановые изменения по заявке (сопоставляйте с ITSM)
level: high
tags: [attack.persistence, attack.t1098]
```
