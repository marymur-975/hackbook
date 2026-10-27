---
id: ad-entra-hybrid-prt-sso
title: "Hybrid Entra ID: PRT-куки, device join и условный доступ"
type: ad
target: azure
category: active-directory
difficulty: advanced
bypass: auth
tags: [entra, azure-ad, hybrid, prt, conditional-access, seamless-sso]
tested_on: ["Hybrid Entra Join + Seamless SSO", "AzureAD-joined Windows 11"]
success_rate: 0.35
risk: critical
cwe: "CWE-287"
lab: null
last_verified: "2026-10-23"
references:
  - "https://learn.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token"
  - "https://attack.mitre.org/techniques/T1528/"
graph:
  - target: "cloud"
    type: related_to
  - target: "active-directory"
    type: related_to
  - target: "session-hijacking"
    type: leads_to
  - target: "auth-bypass"
    type: leads_to
  - target: "credential-access"
    type: related_to
---

# Hybrid Entra ID: PRT-куки, device join и условный доступ

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# диагностика на СВОЕЙ машине: есть ли PRT и в каком состоянии
dsregcmd /status | Select-String -Pattern 'AzureAdPrt|SSO State|Workplace Joined'
# в браузере: chrome://settings/cookies -> запрос к login.microsoftonline.com (PRT cookie)
```

## Explanation

В гибридной среде Windows хранит **Primary Refresh Token (PRT)** —
долгоживущий артефакт, привязанный к устройству и пользователю, из которого
браузеры и приложения получают access-токены без повторного ввода пароля.
Ключевые следствия:

1. PRT живёт в LSASS/хранилище устройства: локальный админ на рабочей
    станции может извлечь его и использовать для получения токенов
    к Microsoft 365 (обход условного доступа, если политика не проверяет
    устройство/сеть при refresh).
2. **Seamless SSO** (для гибридных сценариев) использует компьютерный
    ключ для получения Kerberos-билетов; компрометация ключа устройства —
    доступ к облачным ресурсам.
3. `ms-DS-MachineAccountQuota` и право **Join Devices** позволяют обычному
    пользователю зарегистрировать до 10 устройств; зарегистрированное
    устройство может получить условный доступ как «доверенное»
    (исторический вектор обхода политик и получения токенов).
4. Роли Entra ID (`Global Administrator`, `Privileged Role Administrator`,
    `Cloud Application Administrator`) не видны в локальном AD — аудит
    привилегий обязан включать облако.
5. Синхронизация хешей паролей (PHS) означает, что компрометация DC
    раскрывает материал, используемый и в облаке.

Карточка описывает модель и способы защиты; пошаговое извлечение токенов
из чужих систем здесь не приводится.

## Detection

1. Entra (Azure AD) **Sign-in logs**: аномалии — входы с невозможных
   географий, `TokenIssuerType` необычен, refresh-токены с новых устройств,
   входы без MFA для привилегированных ролей.
2. **Audit logs**: добавление устройств, регистрация приложений, выдача
   секретов сервисным принципалам, изменения условного доступа, добавление
   ролей (Privileged Identity Management).
3. Инвентаризация устройств: сколько зарегистрировано обычными пользователями,
   есть ли «неизвестные» устройства с доступом к корпоративным приложениям.
4. Локально: `dsregcmd /status`, наличие `AzureAdPrt = YES` на хостах,
   где PRT не нужен (серверы, kiosks).
5. Мониторинг обращений к `login.microsoftonline.com` с нестандартных
   агентов/скриптов (автоматизированное использование токенов).
6. Защита идентификации (Identity Protection): риск-события
   «token issuer anomaly», «suspicious inbox forwarding», «impossible travel».

## Remediation

- Условный доступ: требовать **управляемое/гибридное устройство** или
  compliant-статус для привилегированных ролей; блокировать legacy-клиенты;
  требовать MFA (preferably phishing-resistant: FIDO2/Windows Hello).
- PRT: включить `Token Protection`/continuous access evaluation,
  ограничить срок жизни refresh-токенов, требовать подтверждение устройства;
  не выдавать PRT на общих/kiosk-машинах.
- `ms-DS-MachineAccountQuota = 0`; право Join Devices — только у IT;
  отдельная политика регистрации устройств + сертификация.
- Привилегии в Entra: PIM (just-in-time, approval), отдельные «облачные»
  админ-учётки, не связанные с локальными; регулярный access review.
- Синхронизация: фильтровать OU, не синхронизировать привилегированные
  локальные учётки; оценить federated vs PHS с учётом модели угроз.
- Аудит облачных логов в SIEM (Sign-in, Audit, RiskyUsers) + алерты на
  изменения политик и выдачу секретов.
- План реагирования: отзыв токенов (`Revoke sessions`), перерегистрация
  устройства, ротация ключей Seamless SSO (с пониманием последствий).

## Detection rules

```yaml
title: Entra hybrid SSO — использование PRT с неуправляемого устройства
id: a7b8c9d0-0011-4a7b-9c8d-000000000011
status: experimental
description: >-
  Sign-in с PRT-based SSO, где устройство не помечено как compliant/managed
  (украденный Primary Refresh Token используется на чужой машине) или источник
  вне корпоративной сети.
references:
  - https://attack.mitre.org/techniques/T1550/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
logsource:
  product: azure
  service: signinlogs
  definition: 'Entra ID Sign-in logs (категория SignInLogs) с device detail'
detection:
  selection:
    operationName: Sign-in
    prt_sso: true
    device_compliant: false
  condition: selection
fields:
  - userPrincipalName
  - appDisplayName
  - source_ip
  - status
falsepositives:
  - BYOD-устройства, легитимно зарегистрированные в Entra (device_compliant=false,
    но device registered) — уточняйте по deviceDetail.trustType и политике
level: high
tags:
  - attack.lateral_movement
  - attack.t1550
  - cwe.287
```
