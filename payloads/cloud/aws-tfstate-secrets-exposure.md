---
id: cloud-aws-tfstate-secrets-exposure
title: "Terraform state: секреты в открытом виде и публичный бакет состояния"
type: cloud
target: aws
category: cloud
difficulty: intermediate
bypass: none
tags: [aws, s3, terraform, iac, secrets, info-disclosure]
tested_on: ["S3 backend + DynamoDB lock", "локальный terraform.tfstate в git"]
success_rate: 0.5
risk: critical
cwe: "CWE-312"
lab: null
last_verified: "2026-10-23"
references:
  - "https://hackingthe.cloud/"
  - "https://developer.hashicorp.com/terraform/language/state/sensitive-data"
graph:
  - target: "cloud"
    type: instance_of
  - target: "info-disclosure"
    type: leads_to
  - target: "data-exfiltration"
    type: leads_to
  - target: "ci-cd"
    type: related_to
---

# Terraform state: секреты в открытом виде и публичный бакет состояния

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# аудит своего бакета состояния (только с разрешения владельца!)
aws s3api get-bucket-versioning --bucket <tfstate-bucket>
aws s3api get-bucket-encryption --bucket <tfstate-bucket>
aws s3api get-public-access-block --bucket <tfstate-bucket>
aws s3api get-bucket-policy --bucket <tfstate-bucket>
# поиск секретов внутри состояния
aws s3 cp s3://<tfstate-bucket>/prod/terraform.tfstate - | \
  grep -aoE '"(password|secret|token|key)"[^,]{0,120}' | head
```

## Explanation

Terraform хранит состояние в JSON, и в нём **в открытом виде** оказываются:
пароли БД, строки подключения, приватные ключи, токены, значения переменных
с `sensitive = true` (флаг скрывает вывод в CLI, но не шифрует state),
data-блоки, прочитанные из Secrets Manager, а также IAM-политики.

Типовые ошибки:

1. `terraform.tfstate` закоммичен в git (и остался в истории даже после удаления);
2. бакет состояния публичен или доступен из другого аккаунта
    (ресурсная политика с `Principal: "*"`);
3. нет шифрования (SSE-KMS) и версионирования — изменение состояния незаметно;
4. права `s3:GetObject` на бакет состояния выданы ролям CI и разработчикам
    шире, чем нужно (доступ к state = доступ ко всем секретам проекта);
5. локальные state-файлы на машинах разработчиков и в артефактах CI;
6. state от чужого окружения (staging) доступен тем же ролям, что prod.

Практический эффект: одна ошибка в правах на бакет состояния раскрывает
секреты всей инфраструктуры — от БД до облачных ключей.

## Detection

1. Инвентаризация бакетов состояния и их политик: `BlockPublicAccess`,
   encryption, versioning, resource policy, ACL.
2. Поиск state-файлов в репозиториях (включая историю):
   `git log --all --diff-filter=A -- '*.tfstate*'`, gitleaks/trufflehog по истории.
3. Поиск секретов внутри state: grep по `password`, `secret`, `token`,
   `private_key`, base64-блокам (инструменты: `tfsec`, `trivy`, `detect-secrets`).
4. CloudTrail: `GetObject` к бакету состояния — кто и как часто читает;
   `PutObject`/`DeleteObject` из неожиданных ролей.
5. Проверка артефактов CI: не сохраняется ли state в кеше/артефактах.
6. IaC-сканирование в CI: checkov/trivy/tfsec правила
   `S3 bucket used for Terraform state` (encryption, versioning, public access).

## Remediation

- Хранить state только в управляемом бэкенде: S3 + SSE-KMS + versioning +
   Object Lock (для критичных), DynamoDB/`s3` lock для блокировок.
- `BlockPublicAccess` на уровне аккаунта, никакой ресурсной политики с `*`.
- Права на бакет состояния — только у pipeline-роли и узкой группы;
   отдельный бакет на окружение (dev/staging/prod).
- Секреты не в переменных Terraform: ссылаться на Secrets Manager/SSM
   по ARN (`data "aws_secretsmanager_secret_version"`) вместо literal-значений;
   если значение всё же попало в state — считать его скомпрометированным и ротировать.
- Никогда не коммитить `*.tfstate*`: `.gitignore` + pre-commit hook + проверка
   истории (git-filter-repo/BFG при нахождении).
- Включить CloudTrail Data Events на бакете состояния; алерт на чтение извне pipeline.
- Регулярный аудит: Prowler/ScoutSuite + поиск секретов в state по расписанию.

## Detection rules

```yaml
title: Чтение terraform.tfstate из S3 — файл с секретами в открытом виде
id: f6a7b8c9-0009-4f6a-8b9c-000000000009
status: experimental
description: >-
  GetObject к ключам *.tfstate/tfstate.backup: состояние Terraform хранит
  секреты (пароли БД, ключи) plain-text. Любой неожиданный читатель —
  потенциальная утечка.
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://developer.hashicorp.com/terraform/language/state/sensitive-data
logsource:
  product: aws
  service: cloudtrail
  definition: 'CloudTrail data events для S3 бакета состояний'
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: GetObject
  tfstate_key:
    requestParameters.key|contains:
      - '.tfstate'
      - 'tfstate.backup'
  filter_ci:
    userIdentity.sessionContext.sessionIssuer.userName|startswith: 'terraform-'
  condition: selection and tfstate_key and not filter_ci
fields:
  - userIdentity.sessionContext.sessionIssuer.userName
  - sourceIPAddress
  - requestParameters.bucketName
  - requestParameters.key
falsepositives:
  - CI-пайплайны terraform (префикс terraform-* в filter_ci) и разработчики
    во время apply — сверяйте с расписанием деплоев
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
  - cwe.312
```
