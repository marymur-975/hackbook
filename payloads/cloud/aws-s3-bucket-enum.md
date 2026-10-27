---
id: cloud-aws-s3-bucket-enum
title: "AWS S3: публичные бакеты и перечисление объектов"
type: cloud
target: aws
category: cloud
difficulty: beginner
bypass: none
tags: [aws, s3, misconfiguration, exposure]
tested_on: ["S3 (public ACL / bucket policy)"]
success_rate: 0.5
risk: high
cwe: "CWE-732"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0007/"
  - "https://hackingthe.cloud/"
graph:
  - target: "cloud"
    type: instance_of
  - target: "data-exfiltration"
    type: leads_to
  - target: "info-disclosure"
    type: leads_to
---

# AWS S3: публичные бакеты и перечисление объектов

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
aws s3 ls s3://target-backet --no-sign-request
```

## Explanation

Бакет становится публичным тремя независимыми путями: ACL объекта/бакета,
bucket policy с `Principal: "*"`, и отключённый `BlockPublicAccess`.
Если разрешено действие `s3:ListBucket`, доступен полный перечень объектов;
если `s3:GetObject` — их содержимое. Типовые находки: бэкапы БД, логи,
исходники, `.env`, дампы пользователей, приватные ключи, Terraform-состояние
(внутри — секреты в открытом виде).
Отдельный риск — запись (`s3:PutObject`): подмена артефактов сборки, размещение
вредоносного JS на сайте, ransom-записи.

## Detection

1. `aws s3 ls s3://<name> --no-sign-request` и `aws s3api list-objects-v2 --bucket <name> --no-sign-request`.
2. `curl https://<name>.s3.amazonaws.com/?list-type=2` — XML со списком ключей.
3. `curl -X PUT https://<name>.s3.amazonaws.com/hb-probe.txt -d test` — проверка записи
   (только с разрешения владельца!).
4. Аудит изнутри: `aws s3api get-public-access-block`, `get-bucket-policy`,
   `get-bucket-acl`; инструменты: `Prowler`, `ScoutSuite`, `CloudFox`.

## Remediation

- `BlockPublicAccess` на уровне аккаунта и бакета (включить по умолчанию через SCP).
- Никаких `Principal: "*"` в политиках; при необходимости — условия
  (`aws:SourceVpce`, `aws:PrincipalOrgID`, IP-диапазоны).
- Шифрование SSE-KMS + ключи с политиками, аудит через CloudTrail Data Events.
- Версионирование + Object Lock для защиты от удаления/перезаписи.
- Регулярное сканирование на публичность (Prowler/Config rules) и алерты.
- Не хранить секреты в Terraform state без шифрования бакета и доступа по IAM.

## Detection rules

```yaml
title: Анонимное перечисление S3-бакетов
id: f6a7b8c9-0007-4f6a-8b9c-000000000007
status: experimental
description: >-
  ListObjects/GetBucketLocation/ListBuckets от анонимного принципала
  (userIdentity.type=Anonymous) — разведка публичных бакетов, в т.ч.
  --no-sign-request из awscli.
references:
  - https://attack.mitre.org/techniques/T1580/
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html
logsource:
  product: aws
  service: cloudtrail
  definition: 'CloudTrail data events для S3 (включены отдельно) + server access logging'
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - ListObjects
      - ListObjectsV2
      - GetBucketLocation
      - ListBuckets
      - ListAllMyBuckets
  anonymous:
    userIdentity.type: Anonymous
  condition: selection and anonymous
fields:
  - sourceIPAddress
  - requestParameters.bucketName
  - eventName
falsepositives:
  - легитимные публичные датасеты, которые читают анонимно (статические сайты,
    open data) — исключайте известные бакеты
level: medium
tags:
  - attack.discovery
  - attack.t1580
  - cwe.732
```
