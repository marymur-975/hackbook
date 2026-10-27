---
id: ad-dcsync-replication-rights
title: "DCSync: права репликации дают дамп всех хешей домена"
type: ad
target: active-directory
category: active-directory
difficulty: advanced
bypass: auth
tags: [dcsync, replication, extended-rights, credential-access, krbtgt]
tested_on: ["Windows Server 2019/2022 DC", "учётка с DS-Replication-Get-Changes"]
success_rate: 0.4
risk: critical
cwe: "CWE-269"
lab: null
last_verified: "2026-10-23"
references:
  - "https://adsecurity.org/"
  - "https://attack.mitre.org/techniques/T1003/006/"
graph:
  - target: "credential-access"
    type: instance_of
  - target: "active-directory"
    type: related_to
  - target: "privilege-escalation"
    type: leads_to
  - target: "persistence"
    type: leads_to
    description: "Хеш krbtgt даёт golden ticket и долгосрочный доступ"
---

# DCSync: права репликации дают дамп всех хешей домена

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# аудит: у кого есть расширенные права репликации
$dse = 'DC=lab,DC=local'
(Get-Acl "AD:\$dse").Access |
  ? { $_.ObjectType -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or   # DS-Replication-Get-Changes
        $_.ObjectType -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |   # ...-Get-Changes-All
  ft IdentityReference, ObjectType, AccessControlType -Auto
```

## Explanation

Контроллеры домена реплицируют между собой изменения каталога, используя
расширенные права:

- `DS-Replication-Get-Changes` (`1131f6aa-…`)
- `DS-Replication-Get-Changes-All` (`1131f6ad-…`) — даёт доступ к
   конфиденциальным атрибутам, включая `unicodePwd` (хеш пароля)
- `DS-Replication-Get-Changes-In-Filtered-Set`

Любая учётка (не только DC), обладающая этими правами на объекте домена,
может запросить репликацию и получить **все хеши всех пользователей**,
включая `krbtgt`. Владение хешем `krbtgt` = возможность выписывать golden
tickets и сохранять доступ даже после смены всех паролей (нужна двойная
смена пароля krbtgt с выжиданием).

Права обычно появляются «случайно»: от установщиков (Exchange, MIM,
резервное копирование), делегирования задач, членства в Domain Admins/
Enterprise Admins, а также через ACE на родительском OU с наследованием.

## Detection

1. Инвентаризация: кто имеет три replication-права (команда выше,
   либо `PingCastle --rules dcsync`).
2. **Event 4662** на объекте домена с `AccessMask`/`Properties`, содержащими
   GUID репликационных прав, и `SubjectUserName` != `$`-учётка DC.
   (Нужен SACL-аудит на объекте домена: `Audit Directory Service Access`.)
3. **Event 4624 type 3** с рабочей станции (не DC) на порт 389/636/3268 DC —
   репликационный трафик приходит только от DC.
4. Сетевой признак: LDAP `GetNCChanges`-запросы (DRSUAPI) от хоста,
   не являющегося контроллером домена.
5. Косвенно: появление golden-ticket-подобных аномалий — TGT с огромным
   сроком жизни, несоответствие PAC (Event 4769 с необычным `Ticket Options`).

## Remediation

- Удалить replication-права у всех, кроме DC и обоснованных сервисов
  (MIM/Exchange — только требуемые subset-права, не `Get-Changes-All`).
- Проверять ACE на объекте домена и на родительских OU (наследуемые права).
- Включить аудит `Directory Service Access` (4662) на объекте домена
  и алертить на replication-GUID от не-DC субъектов.
- Tiering: права репликации — только Tier 0; Protected Users для админов.
- Предполагать компрометацию: если права были доступны злоумышленнику,
  считать украденными все хеши — план восстановления включает двойную смену
  пароля `krbtgt`, ротацию сервисных паролей, отзыв сертификатов.
- LAPS/gMSA, уникальные локальные пароли — чтобы дамп хешей не давал
  горизонтального перемещения.
- Ограничить сетевой доступ к RPC/LDAP DC сегментацией (репликация —
  только между DC).


## Detection rules

```yaml
title: DCSync — доступ к атрибутам репликации не-DC учёткой
id: a1b2c3d4-0007-4a1b-9c1d-000000000007
status: stable
description: >-
  Event 4662 с правами DS-Replication-Get-Changes(-All), где субъект не является
  машинной учёткой контроллера домена. Высокая точность при включённом SACL.
references:
  - https://attack.mitre.org/techniques/T1003/006/
logsource:
  product: windows
  service: security
  definition: 'SACL на объекте домена: Audit Directory Service Access (Success)'
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_dc:
    SubjectUserName|endswith: '$'      # машинные учётки контроллеров домена
  filter_replication_service:
    SubjectUserName:
      - 'svc_mim'                      # легитимные сервисы репликации/бэкапа
      - 'svc_backup'
  condition: selection and not filter_dc and not filter_replication_service
falsepositives:
  - сервисы репликации (MIM, FIM), решения резервного копирования с делегированием
level: critical
tags: [attack.credential_access, attack.t1003.006]
```
