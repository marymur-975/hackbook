---
id: ad-constrained-delegation-rbcd
title: "Constrained и resource-based delegation: права на целевом объекте"
type: ad
target: active-directory
category: active-directory
difficulty: advanced
bypass: auth
tags: [delegation, rbcd, kerberos, active-directory, msds-allowedtoact]
tested_on: ["Windows Server 2019/2022", "RBCD на машинной учётке"]
success_rate: 0.35
risk: critical
cwe: "CWE-269"
lab: null
last_verified: "2026-10-23"
references:
  - "https://adsecurity.org/"
  - "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
graph:
  - target: "delegation"
    type: instance_of
  - target: "kerberos"
    type: related_to
  - target: "privilege-escalation"
    type: leads_to
  - target: "lateral-movement"
    type: leads_to
  - target: "active-directory"
    type: related_to
---

# Constrained и resource-based delegation: права на целевом объекте

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# найти constrained delegation
ldapsearch -x -H ldap://dc01.lab.local -b 'DC=lab,DC=local' \
  '(msDS-AllowedToDelegateTo=*)' dn msDS-AllowedToDelegateTo userAccountControl

# найти RBCD: кто разрешён действовать от имени других на ЭТОМ объекте
ldapsearch -x -H ldap://dc01.lab.local -b 'DC=lab,DC=local' \
  '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' dn
```

## Explanation

**Constrained delegation** ограничивает список сервисов, к которым можно
обращаться от имени пользователя (`msDS-AllowedToDelegateTo`). Но если у
объекта дополнительно установлен флаг `TRUSTED_TO_AUTH_FOR_DELEGATION`
(protocol transition), он может запрашивать билеты **без исходного билета
пользователя** — то есть от любого имени. Дальше всё зависит от списка
сервисов: `CIFS/host` даёт доступ ко всем файлам, `HOST` — почти всё,
включая создание задач и служб, `HTTP` — доступ к веб-приложениям,
 `ldap` — чтение данных и дамп через DCSync-подобные механизмы.

**Resource-based constrained delegation (RBCD)** переворачивает модель:
список хранится на **целевом** объекте в атрибуте
`msDS-AllowedToActOnBehalfOfOtherIdentity`. Кто имеет право писать этот
атрибут на целевой машине (например, `GenericWrite`/`WriteProperty` на
компьютер), тот может прописать туда свою машинную учётку и получить
доступ к сервисам цели от имени любого пользователя — включая администратора.
Это стандартный путь эскалации «обычный пользователь -> локальный админ
на сервере» при наличии прав на запись атрибута или права создавать
компьютеры (`ms-DS-MachineAccountQuota` = 10 по умолчанию).

## Detection

1. Инвентаризация: `msDS-AllowedToDelegateTo` (constrained) и
   `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) — списки должны быть
   короткими и обоснованными.
2. **Event 5136/5137** — изменение этих атрибутов (особенно на DC и серверах).
3. **Event 4769** с флагом `Forwardable` и ServiceName, не соответствующим
   обычной схеме обращения учётки; билеты, запрошенные «от имени» других.
4. Аномалия: машинная учётка запрашивает сервисные билеты к CIFS/HTTP
   от имени пользователя-администратора.
5. `ms-DS-MachineAccountQuota > 0` у обычных пользователей — предпосылка RBCD.
6. Инструменты аудита: BloodHound (пути к `AllowedToAct`, `WriteAccountRestricted`,
   `AddAllowedToAct`), PingCastle, ADRecon.

## Remediation

- Минимизировать число объектов с делегированием; для каждого — явный
  и минимальный список сервисов (избегать `HOST`, `CIFS` где можно).
- Запретить protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`),
  если не требуется; предпочесть RBCD с точечным списком.
- Убрать у обычных пользователей право писать атрибуты делегирования;
  аудит ACE на компьютерах (`GenericWrite`, `WriteProperty` на
  `msDS-AllowedToActOnBehalfOfOtherIdentity`).
- `ms-DS-MachineAccountQuota = 0` для не-админов; создание компьютеров —
  через отдельный процесс.
- Критичные объекты: `NotDelegated`, Protected Users, tiering.
- LAPS/уникальные локальные админ-пароли: RBCD даёт доступ к сервисам,
  но не должен давать доменные привилегии.
- Мониторинг 5136 на изменения атрибутов делегирования и алерт на новые
  машинные учётки, созданные не-админами (Event 4741).

## Detection rules

```yaml
title: RBCD/constrained delegation — правка msDS-AllowedTo* атрибутов
id: a7b8c9d0-0008-4a7b-9c8d-000000000008
status: experimental
description: >-
  Event 5136 на атрибутах msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
  или msDS-AllowedToDelegateTo (constrained delegation): назначение
  делегирования — ключевой шаг атаки «service for user» к любому сервису.
references:
  - https://attack.mitre.org/techniques/T1474/
  - https://adsecurity.org/?p=1667
logsource:
  product: windows
  service: security
  definition: 'SACL/аудит Directory Service Changes (5136) на объектах computer/user'
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName|contains:
      - 'msDS-AllowedToActOnBehalfOfOtherIdentity'
      - 'msDS-AllowedToDelegateTo'
  filter_schema_admin:
    SubjectUserName:
      - svc_admgmt
  condition: selection and not filter_schema_admin
fields:
  - ObjectDN
  - ObjectClass
  - AttributeLDAPDisplayName
  - AttributeValue
  - SubjectUserName
falsepositives:
  - плановая настройка делегирования администраторами AD (сверяйте с тикетами;
    значение AttributeValue = SID того, кому делегируют — проверяйте его)
level: high
tags:
  - attack.privilege_escalation
  - attack.t1474
  - cwe.284
```
