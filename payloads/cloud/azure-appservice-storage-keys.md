---
id: cloud-azure-appservice-storage-keys
title: "Azure: connection strings в настройках и ключи Storage Account"
type: cloud
target: azure
category: cloud
difficulty: intermediate
bypass: none
tags: [azure, app-service, storage, secrets, key-vault]
tested_on: ["App Service (Linux/Windows)", "Storage Account с Shared Key"]
success_rate: 0.5
risk: high
cwe: "CWE-312"
lab: null
last_verified: "2026-10-23"
references:
  - "https://hackingthe.cloud/"
  - "https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string"
graph:
  - target: "cloud"
    type: instance_of
  - target: "info-disclosure"
    type: leads_to
  - target: "data-exfiltration"
    type: leads_to
  - target: "privilege-escalation"
    type: related_to
---

# Azure: connection strings в настройках и ключи Storage Account

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# аудит конфигурации (нужны права на чтение настроек)
az webapp config appsettings list -g <rg> -n <app> -o table
az webapp config connection-string list -g <rg> -n <app> -o table
az storage account show-connection-string -g <rg> -n <acct> -o json
# кто имеет доступ к секретам Key Vault
az keyvault show-access-policy -n <vault> -o table
```

## Explanation

Классическая цепочка утечки в Azure:

1. `appsettings.json`/переменные окружения App Service содержат
    **connection string с ключом Storage Account** или паролем БД в открытом виде;
2. право `Microsoft.Web/sites/config/read` (часто входит в Contributor)
    позволяет прочитать эти настройки -> ключ Storage -> все данные в контейнерах,
    а ключи Storage дают и запись/удаление;
3. ключи Storage Account — это «общий пароль на всё хранилище»:
    нет аудита по субъектам, нет гранулярных прав, ротация ломает клиентов;
4. SAS-токены с широкими правами и долгим сроком (иногда до 2030+),
    выданные «для интеграции», оказываются в логах и в коде мобильных приложений;
5. секреты в Key Vault доступны слишком широкому кругу
    (`Key Vault Secrets Officer` на весь vault вместо per-secret policy),
    либо vault имеет публичный доступ без private endpoint.

Дополнительно: `az webapp config container set`, FTP-публикация с учётными
данными в настройках, и `WEBSITE_*` переменные, видимые в Kudu/логах.

## Detection

1. Выгрузить appsettings всех приложений и найти literal-секреты
   (`AccountKey=`, `Password=`, `SharedAccessSignature`, `DefaultEndpointsProtocol`).
2. Проверить права: кто может читать `sites/config` (Contributor/Reader + role
   assignments), кто имеет доступ к Key Vault secrets.
3. Storage: включён ли `allowSharedKeyAccess`, есть ли SAS с далёким сроком,
   открыт ли публичный доступ к контейнерам (`allowBlobPublicAccess`).
4. Логи: `StorageRead`/`StorageWrite` с анонимного IP, использование SAS
   из неожиданных источников (Sign-in/Activity logs, Storage analytics).
5. Defender for Cloud: рекомендации по секретам в appsettings,
   публичным контейнерам, нешифрованным хранилищам.
6. Поиск секретов в репозиториях и образах (gitleaks/trufflehog) —
   connection strings чаще всего утекают именно оттуда.

## Remediation

- Managed Identity вместо ключей: App Service -> Storage/SQL/Key Vault
  через identity, без connection strings.
- Отключить Shared Key на Storage Account (`allowSharedKeyAccess=false`),
  если переход завершён; иначе — ротация ключей и минимальный доступ.
- SAS: короткие сроки (часы/дни), минимальные права, привязка к IP/протоколу,
  выдача через сервис с аудитом, never в клиентском коде.
- Секреты только в Key Vault с private endpoint, RBAC (не access policies
  на весь vault), включённым soft delete + purge protection и аудитом
  обращений к секретам.
- `appsettings.json` без секретов; ссылки на Key Vault (`@Microsoft.KeyVault(...)`) 
  + права у identity приложения.
- Ограничить право чтения настроек (`sites/config/read`) — не выдавать
  Contributor разработчикам в prod-подписке.
- Private endpoints для Storage/Key Vault/SQL; запрет публичного доступа.
- Мониторинг: алерты на чтение secrets из Key Vault новыми субъектами,
  на массовые операции Storage.

## Detection rules

```yaml
title: Azure — запрос ключей storage и секретов App Service через ARM
id: f6a7b8c9-0016-4f6a-8b9c-000000000016
status: experimental
description: >-
  Операции LISTKEYS/LISTSECRETS/CONFIG-LIST в Activity Log: кто-то запрашивает
  полный доступ к storage-аккаунту или connection strings App Service в
  открытом виде (az webapp config ... list, show-connection-string).
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://learn.microsoft.com/en-us/azure/app-service/configure-common
logsource:
  product: azure
  service: activitylog
  definition: 'Azure Activity Log (Microsoft.Storage/Microsoft.Web операции)'
detection:
  selection:
    operationName|contains:
      - 'LISTKEYS/ACTION'
      - 'LISTSECRETS'
      - 'CONFIG/LIST/ACTION'
      - 'CONNECTIONSTRINGS'
      - 'LISTFUNCTIONKEYS'
  filter_automation:
    caller|contains: 'automation@'
  condition: selection and not filter_automation
fields:
  - caller
  - operationName
  - resourceGroup
  - status
falsepositives:
  - runbook-автоматизация и backup-сервисы (префикс automation@ в filter) —
    дополняйте список своими managed identity автоматизации
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
  - cwe.522
```
