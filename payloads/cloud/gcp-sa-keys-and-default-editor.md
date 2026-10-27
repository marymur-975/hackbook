---
id: cloud-gcp-sa-keys-and-default-editor
title: "GCP: ключи сервисных аккаунтов и roles/editor у default compute SA"
type: cloud
target: gcp
category: cloud
difficulty: intermediate
bypass: none
tags: [gcp, service-account, iam, workload-identity, keys]
tested_on: ["GCE/GKE, default compute service account", "SA-ключи в JSON"]
success_rate: 0.5
risk: critical
cwe: "CWE-269"
lab: null
last_verified: "2026-10-23"
references:
  - "https://hackingthe.cloud/"
  - "https://cloud.google.com/iam/docs/service-account-overview"
graph:
  - target: "cloud"
    type: instance_of
  - target: "privilege-escalation"
    type: leads_to
  - target: "ci-cd"
    type: related_to
  - target: "ssrf"
    type: related_to
---

# GCP: ключи сервисных аккаунтов и roles/editor у default compute SA

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# аудит: роли проекта и сервисные аккаунты
gcloud projects get-iam-policy <project> --flatten='bindings[].members' \
  --format='table(bindings.role,bindings.members)' | grep -E 'editor|owner|iam\.'
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account=<sa>@<project>.iam.gserviceaccount.com
# кто может получить токен чужого SA
gcloud projects get-iam-policy <project> | grep -A2 getAccessToken
```

## Explanation

Две массовые проблемы GCP:

**1. `roles/editor` у default compute service account.** В проектах,
созданных до изменения дефолтов, каждая ВМ/GKE-узел получает default SA
с `roles/editor` на весь проект. Любой SSRF в приложении, любой RCE в
контейнере или чтение метаданных -> токен с правами редактора проекта:
изменение IAM, доступ к хранилищам, запуск инстансов, чтение секретов.

**2. Ключи сервисных аккаунтов (JSON).** Ключ — это долгосрочный пароль:
он лежит в репозиториях, Docker-образах, переменных CI, бэкапах, логах.
Утечка ключа с ролью выше минимальной = компрометация проекта без единого
взлома. Ключи нельзя отозвать «частично», а ротация обычно не настроена.

Опасные роли/права для эскалации: `resourcemanager.projects.setIamPolicy`,
`iam.serviceAccounts.getAccessToken`, `iam.serviceAccountKeys.create`,
`iam.serviceAccounts.getOIDCIdToken`, `compute.instances.setMetadata`
(инжект SSH-ключа или startup-script), `compute.instances.setServiceAccount`,
`run.services.setIamPolicy`, `storage.objects.get` на бакетах с ключами/tfstate.

## Detection

1. Проверить роли default compute SA: `gcloud compute instances describe`
   -> `serviceAccounts[].scopes` и роль SA в IAM проекта.
2. Инвентаризация ключей: `gcloud iam service-accounts keys list` —
   ключи старше 90 дней, ключи у SA, которым они не нужны.
3. Поиск ключей в артефактах: gitleaks/trufflehog по репозиториям и образам,
   шаблон `"type": "service_account"` и `private_key_id`.
4. Audit Logs: `iam.serviceAccounts.getAccessToken`, `getOIDCIdToken`,
   `setIamPolicy`, `create` ключей; аномалии — вызовы с новых ресурсов/IP.
5. Asset Inventory / Security Command Center: рекомендации
   «SA has overly permissive roles», «SA key not rotated».
6. Проверка метаданных: приложение не должно иметь доступ к 169.254.169.254
   без необходимости (см. `cloud-gcp-metadata-token`).

## Remediation

- Снять `roles/editor` с default SA; создать отдельные SA на workload
  с минимальными ролями (`roles/<service>.<specificRole>`).
- Workload Identity (GKE) / service account attachment вместо ключей;
  для внешних CI — **federated identity** (OIDC GitHub/GitLab -> SA)
  с условием на атрибуты токена, без JSON-ключей.
- Организационная политика: запрет создания ключей SA
  (`constraints/iam.disableServiceAccountKeyCreation`), запрет
  автоматического предоставления default-ролей новым проектам.
- Если ключи необходимы: срок жизни ≤ 90 дней, ротация, хранение в vault,
  аудит использования по `key_id`.
- Ограничить scope'ы ВМ (`cloud-platform` -> конкретные scope),
  включить `Metadata-Flavor` и ограничить доступ к метаданным.
- Мониторинг Audit Logs в SIEM; алерты на `setIamPolicy`, создание ключей,
  доступ к секретным бакетам.

## Detection rules

```yaml
title: GCP — создание ключей сервисных аккаунтов и раздача roles/editor
id: f6a7b8c9-0015-4f6a-8b9c-000000000015
status: experimental
description: >-
  CreateServiceAccountKey (долгосрочные ключи — главный путь утечки в GCP)
  и SetIamPolicy с roles/editor|owner на проект: закрепление широких прав.
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1552/005/
logsource:
  product: gcp
  service: gcp_audit
  definition: 'Cloud Audit Logs: Admin Activity (пишется всегда, не отключается)'
detection:
  key_creation:
    protoPayload.methodName|contains:
      - 'CreateServiceAccountKey'
      - 'iam.serviceAccountKeys.create'
  iam_grant:
    protoPayload.methodName: google.iam.admin.v1.SetIamPolicy
    protoPayload.request.role:
      - roles/editor
      - roles/owner
      - roles/iam.securityAdmin
      - roles/iam.serviceAccountTokenCreator
  condition: key_creation or iam_grant
fields:
  - protoPayload.authenticationInfo.principalEmail
  - protoPayload.methodName
  - protoPayload.resourceName
  - protoPayload.request.role
falsepositives:
  - плановая выдача ролей через IaC — сверяйте с PR/тикетами; для ключей SA
    предпочитайте workload identity federation
level: high
tags:
  - attack.persistence
  - attack.t1098
  - attack.t1552.005
  - cwe.732
```
