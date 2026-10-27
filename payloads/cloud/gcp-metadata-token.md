---
id: cloud-gcp-metadata-token
title: "GCP: token сервисного аккаунта из metadata-сервера"
type: cloud
target: gcp
category: cloud
difficulty: intermediate
bypass: none
tags: [gcp, metadata, service-account, ssrf]
tested_on: ["GCE metadata v1"]
success_rate: 0.5
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

# GCP: token сервисного аккаунта из metadata-сервера

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

## Explanation

GCP требует заголовок `Metadata-Flavor: Google`, что останавливает простейший SSRF
(браузер не может его выставить), но не останавливает инъекцию в код, который
формирует запрос на сервере (SSRF в библиотеке с кастомными заголовками, LFI, RCE).
Ответ — OAuth-токен сервисного аккаунта, действующий ~1 час, с его ролями.
Полезные пути metadata:

- `/computeMetadata/v1/instance/service-accounts/` — список аккаунтов
- `.../default/token`, `.../default/email`, `.../default/scopes`
- `/computeMetadata/v1/project/attributes/` — атрибуты проекта (иногда ssh-keys!)
- `/instance/attributes/user-data`, `/instance/hostname`
- `/instance/service-accounts/<email>/identity?audience=...` — ID-токен
  (используется для доступа к Cloud Run/IAP — обход сетевого периметра)

## Detection

1. Внутри ВМ: запрос с заголовком `Metadata-Flavor: Google` к `metadata.google.internal`.
2. Проверьте, какие роли у default-сервисного аккаунта (`roles/editor` по умолчанию
   на старых проектах — критично).
3. Cloud Audit Logs: `getAccessToken`-подобные вызовы с неожиданных ресурсов.
4. Сканирование: `GSUtil`/`gcloud`-чекеры конфигурации (Forseti, ScoutSuite).

## Remediation

- Не использовать default-сервисный аккаунт: отдельные SA с минимальными ролями.
- Снять `roles/editor`/`roles/owner` с compute-аккаунтов.
- Workload Identity (GKE) вместо ключей; `Metadata-Flavor` обязателен.
- Ограничить доступ к metadata через firewall (private google access) и `ssh-keys`
  в атрибутах проекта не хранить.
- Валидация URL на уровне приложения + egress-фильтрация.
- Организация-политики: запрет публичных SA-ключей, ротация.

## Variants

```
curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/?recursive=true
```

## Detection rules

```yaml
title: GCP — запрос токена сервисного аккаунта из metadata-сервиса
id: f6a7b8c9-0012-4f6a-8b9c-000000000012
status: experimental
description: >-
  Исходящий HTTP к metadata.google.internal (169.254.169.254) по пути
  /computeMetadata/v1/.../token — получение OAuth-токена SA изнутри инстанса.
  В связке с SSRF это утечка токена наружу.
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://cloud.google.com/compute/docs/metadata/overview
logsource:
  category: firewall
  definition: 'egress-лог прокси/файрвола: все исходящие HTTP рабочих нагрузок'
detection:
  selection:
    dst_ip: 169.254.169.254
  metadata_path:
    uri|contains: 'computeMetadata'
  metadata_host:
    http_host: metadata.google.internal
  condition: selection and (metadata_path or metadata_host)
fields:
  - src_ip
  - dst_ip
  - uri
  - http_host
falsepositives:
  - штатные библиотеки GCP берут токены из метаданных постоянно — алерт ценен,
    когда источник (src_ip) не должен этого делать (публичный сервис) или
    запрос идёт после внешнего ввода (SSRF)
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
  - cwe.918
```
