---
id: cloud-aws-s3-object-acl-leak
title: "S3: объектные ACL, забытые бакеты и публичные артефакты сборки"
type: cloud
target: aws
category: cloud
difficulty: beginner
bypass: none
tags: [aws, s3, acl, public-exposure, data-exfiltration]
tested_on: ["S3 (account-level BlockPublicAccess off)", "бакеты статики и артефактов"]
success_rate: 0.45
risk: critical
cwe: "CWE-732"
lab: null
last_verified: "2026-10-23"
references:
  - "https://hackingthe.cloud/"
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
graph:
  - target: "cloud"
    type: instance_of
  - target: "data-exfiltration"
    type: leads_to
  - target: "info-disclosure"
    type: leads_to
  - target: "ci-cd"
    type: related_to
---

# S3: объектные ACL, забытые бакеты и публичные артефакты сборки

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# внешний анонимный доступ (только к СВОИМ/авторизованным бакетам!)
aws s3api list-objects-v2 --bucket <name> --no-sign-request --max-items 5
curl -s 'https://<name>.s3.amazonaws.com/?list-type=2&max-keys=5' | head -c 400
# изнутри аккаунта: аудит публичности
aws s3api get-public-access-block --bucket <name>
aws s3api get-bucket-acl --bucket <name> --query 'Grants[]'
aws s3api get-bucket-policy --bucket <name>
```

## Explanation

Публичность бакета определяется **тремя независимыми** механизмами, и
достаточно одного слабого звена:

1. Account/Bucket-level `BlockPublicAccess` (выключен -> остальное решает);
2. Bucket policy (`Principal: "*"` или широкий `AWS: *`);
3. **Object ACL** — `AllUsers`/`AuthenticatedUsers` на отдельных объектах
   (исторически самый частый источник утечек: бакет закрыт, а файлы внутри — нет).

Что обычно утекает: статика и артефакты сборок (в них — исходники и карты),
бэкапы БД и снапшоты, логи (в них токены и PII), `terraform.tfstate`,
мобильные сборки с API-ключами, медиафайлы с метаданными, `.env`-файлы,
датасеты ML, сканы/документы.

Отдельный риск — **запись** (`s3:PutObject` для всех): подмена артефактов,
которые затем деплоятся (supply chain), размещение вредоносного JS на
сайте, ransom-записи с требованием выкупа.

Смежный класс: «забытые» бакеты после удаления приложения (доменное имя
освобождается, и его может зарегистрировать другой аккаунт — bucket takeover).

## Detection

1. Инвентаризация всех бакетов и их настроек: `BlockPublicAccess`,
   bucket policy, ACL (включая **объектные** ACL — их часто не проверяют),
   шифрование, versioning, logging.
2. Access Analyzer for S3 / AWS Config rules (`s3-bucket-public-read-prohibited`,
   `s3-account-level-public-access-blocks`).
3. Внешняя проверка своих доменов: DNS-записи, ведущие на S3, и ответ
   `NoSuchBucket` = кандидат на takeover.
4. CloudTrail Data Events: аномальные `GetObject` объёмы, `PutObjectAcl`,
   `PutBucketPolicy`, `PutPublicAccessBlock` (выключение защиты!).
5. Сканирование артефактов на секреты (gitleaks/trufflehog по скачанному
   содержимому своих публичных бакетов).
6. Prowler/ScoutSuite — сводный отчёт по публичности.

## Remediation

- `BlockPublicAccess` на **уровне аккаунта** + SCP, запрещающий его выключать
   (организационный уровень).
- Отключить объектные ACL (`ObjectOwnership=BucketOwnerEnforced`) —
   доступ только через политики; это убирает целый класс утечек.
- Bucket policy: никаких `Principal: "*"`; при необходимости — условия
   (`aws:PrincipalOrgID`, `aws:SourceVpce`, IP-диапазоны, `aws:SecureTransport`).
- Шифрование SSE-KMS с ключевой политикой, versioning + Object Lock
   (защита от удаления/перезаписи), server access logging / CloudTrail data events.
- Отдельные бакеты на окружения и назначения; минимум прав у ролей
   (`s3:PutObject` только в конкретный префикс).
- Жизненный цикл: удаление неиспользуемых бакетов только после проверки
   DNS-ссылок (защита от takeover); освобождённые имена мониторить.
- Алерты: включение публичности, массовый `GetObject`, изменения политик.
- Для статики — CloudFront + OAC (Origin Access Control) вместо публичного бакета.

## Detection rules

```yaml
title: S3 — публикация бакета/объектов и анонимное скачивание
id: f6a7b8c9-0008-4f6a-8b9c-000000000008
status: experimental
description: >-
  PutBucketAcl/PutBucketPolicy/PutObjectAcl с публичными грантами либо
  анонимный GetObject — данные стали (или уже стали) доступны интернету.
references:
  - https://attack.mitre.org/techniques/T1530/
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
logsource:
  product: aws
  service: cloudtrail
  definition: 'CloudTrail data events для S3'
detection:
  acl_change:
    eventSource: s3.amazonaws.com
    eventName:
      - PutBucketAcl
      - PutBucketPolicy
      - PutObjectAcl
  anonymous_get:
    eventSource: s3.amazonaws.com
    eventName: GetObject
    userIdentity.type: Anonymous
  condition: acl_change or anonymous_get
fields:
  - sourceIPAddress
  - userIdentity.sessionContext.sessionIssuer.userName
  - requestParameters.bucketName
  - requestParameters.key
falsepositives:
  - плановая публикация статики (CDN-бакеты) — ведите список разрешённых
    бакетов и проверяйте BlockPublicAccess на уровне аккаунта
level: high
tags:
  - attack.collection
  - attack.t1530
  - cwe.732
```
