---
id: ad-unconstrained-delegation
title: "Unconstrained delegation: кэш TGT любого подключившегося"
type: ad
target: active-directory
category: active-directory
difficulty: advanced
bypass: auth
tags: [delegation, kerberos, tgt, active-directory, tier0]
tested_on: ["Windows Server 2019", "хост с TRUSTED_FOR_DELEGATION"]
success_rate: 0.4
risk: critical
cwe: "CWE-522"
lab: null
last_verified: "2026-10-23"
references:
  - "https://adsecurity.org/"
  - "https://attack.mitre.org/techniques/T1558/"
graph:
  - target: "delegation"
    type: instance_of
  - target: "kerberos"
    type: related_to
  - target: "credential-access"
    type: leads_to
  - target: "privilege-escalation"
    type: leads_to
  - target: "lateral-movement"
    type: leads_to
---

# Unconstrained delegation: кэш TGT любого подключившегося

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# перечислить объекты с unconstrained delegation
ldapsearch -x -H ldap://dc01.lab.local -b 'DC=lab,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=524288)' dn dNSHostName

# то же для компьютеров и пользователей раздельно
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-ADUser     -Filter {TrustedForDelegation -eq $true}
```

## Explanation

Хост с unconstrained delegation (флаг `TRUSTED_FOR_DELEGATION`, 524288)
имеет право обращаться к **любым** сервисам от имени подключившегося
пользователя. Технически это работает так: при аутентификации хост получает
TGT пользователя внутри сервисного билета и кэширует его в LSASS.

Следствия:

1. Компрометация такого хоста = компрометация всех, кто на него заходил.
2. Если на хост зайдёт администратор домена (или контроллер домена выполнит
    к нему обращение — см. принуждение через printer bug / `SpoolSample`),
    его TGT окажется в памяти, и это путь к полному захвату домена.
3. DC и RODC исторически имеют этот флаг по необходимости — поэтому их
    компрометация и так равна захвату домена; проблема в **рабочих станциях
    и серверах приложений**, где флаг включают «чтобы заработало».

Отдельная опасность: флаг часто ставят на серверы печати, файловые серверы,
веб-приложения с Kerberos-аутентификацией и «интеграции» с Exchange/SharePoint.

## Detection

1. **Инвентаризация**: `TrustedForDelegation -eq $true` у компьютеров и
   пользователей. Список должен содержать только DC и обоснованные исключения.
2. **Event 5136** — изменение атрибута `userAccountControl` (появление флага).
3. **Event 4624 type 3** на таком хосте от привилегированных учётных записей —
   аномалия сама по себе (админ Tier 0 не должен аутентифицироваться на Tier 1/2).
4. Признак принуждения к аутентификации: всплеск обращений к службе печати
   (RPC `SpoolService`) от/к DC, исходящие LDAP/SMB-подключения от DC
   на не-DC хосты.
5. Наличие дампов LSASS-процессов (Sysmon 10 с `GrantedAccess=0x1410/0x1fffff`).

## Remediation

- Убрать `TrustedForDelegation` везде, кроме контроллеров домена;
  заменить на **constrained** (с явным списком сервисов) или
  **resource-based constrained delegation (RBCD)**.
- Отметить критичные объекты как `Account is sensitive and cannot be delegated`
  (`NotDelegated`) — минимум для DC-админов, tier-0 сервисов и самих DC.
- Включить админ-группы в **Protected Users** (запрещает делегирование,
  NTLM и кэширование билетов вне DC).
- Tiering + Authentication Policies/silos: Tier 0 не аутентифицируется
  на Tier 1/2 — принуждение к аутентификации теряет ценность.
- Ограничить службу печати: `RpcAuthnLevelPrivacyEnabled`, отключить
  Spooler на DC и серверах, где он не нужен (закрытие printer bug).
- LSA Protection (RunAsPPL), Credential Guard на всех хостах — TGT
  не извлекается из LSASS.
- Мониторинг 5136 (изменение UAC-флагов) и алерт на появление
  `TrustedForDelegation`.


## Detection rules

```yaml
title: Включено unconstrained delegation у объекта AD
id: a1b2c3d4-0004-4a1b-9c1d-000000000004
status: experimental
description: >-
  Изменение userAccountControl с появлением флага TRUSTED_FOR_DELEGATION (524288)
  на не-DC объекте. Почти всегда конфигурационная ошибка или подготовка атаки.
logsource:
  product: windows
  service: security
  definition: 'Нужен аудит 5136 (изменение объекта каталога) и SACL на OU'
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: userAccountControl
  condition: selection
falsepositives:
  - легитимная настройка DC и RODC
  - миграции ролей
level: high
tags: [attack.credential_access, attack.t1558]
```
