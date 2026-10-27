---
id: cloud-aws-iam-privilege-escalation
title: "AWS IAM: 12 прав, которые дают эскалацию до администратора"
type: cloud
target: aws
category: cloud
difficulty: advanced
bypass: auth
tags: [aws, iam, privilege-escalation, passrole, policy]
tested_on: ["AWS IAM (роли и политики)", "AWS CLI v2"]
success_rate: 0.6
risk: critical
cwe: "CWE-269"
lab: null
last_verified: "2026-10-23"
references:
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
  - "https://hackingthe.cloud/"
graph:
  - target: "cloud"
    type: instance_of
  - target: "privilege-escalation"
    type: leads_to
  - target: "info-disclosure"
    type: related_to
---

# AWS IAM: 12 прав, которые дают эскалацию до администратора

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# самодиагностика: кто я и что могу
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <role>
aws iam simulate-principal-policy --policy-source-arn <arn> \
  --action-names iam:CreatePolicyVersion iam:PassRole lambda:CreateFunction
# автоматизированный поиск путей эскалации
prowler aws --checks iam_policy_allows_privilege_escalation,iam_role_allow_everyone
```

## Explanation

В AWS эскалация — это не «найти уязвимость», а **найти право, которое
позволяет выдать себе другие права**. Минимальный набор для аудита:

| Право | Как даёт администратора |
|-------|--------------------------|
| `iam:CreatePolicyVersion` | новая версия политики с `*:*` и `SetAsDefault=true` |
| `iam:SetDefaultPolicyVersion` | откат к старой версии, где было больше прав |
| `iam:AttachRolePolicy` / `AttachUserPolicy` | присоединить `AdministratorAccess` |
| `iam:PutRolePolicy` / `PutUserPolicy` | вписать инлайн-политику `*:*` |
| `iam:PassRole` + `lambda:CreateFunction` | передать привилегированную роль в функцию и вызвать её |
| `iam:PassRole` + `ec2:RunInstances` | инстанс с нужной ролью + user-data со скриптом |
| `lambda:UpdateFunctionCode` | подменить код существующей функции с привилегированной ролью |
| `glue:UpdateDevEndpoint`, `cloudformation:CreateStack` | роль передаётся в сервис, который выполняет код |
| `s3:GetObject` на бакет с `terraform.tfstate` | ключи/секреты ко всей инфраструктуре |
| `ssm:StartSession` / `ssm:SendCommand` | доступ к инстансам без SSH-ключей |
| `sts:AssumeRole` на широкий набор ролей | горизонтальное движение по цепочке ролей |
| `ecr:GetAuthorizationToken` + pull | образы с секретами внутри |

Отдельный класс — **ресурсные политики с `Principal: "*"`**
(S3, SQS, KMS, Lambda, Secrets Manager): они дают доступ из другого аккаунта
или анонимно, минуя IAM-политики субъекта.

## Detection

1. Выгрузите все политики и найдите `Action: "*"` / `Resource: "*"`
   вне break-glass ролей: `aws iam list-policies --scope Local`,
   затем `get-policy-version`.
2. Проверьте `PassRole`-границы: есть ли условие на передаваемую роль?
3. Ресурсные политики: `aws s3api get-bucket-policy`, `aws kms get-key-policy`,
   `aws lambda get-policy`, `aws secretsmanager get-resource-policy` —
   искать `Principal: "*"` и широкие `AWS: *`.
4. `simulate-principal-policy` для каждой роли по списку опасных действий.
5. CloudTrail: `CreatePolicyVersion`, `AttachRolePolicy`, `PutRolePolicy`,
   `PassRole`, `RunInstances`, `CreateFunction` — любые вызовы этих действий
   должны быть редкими и объяснимыми.
6. Инструменты: Prowler, ScoutSuite, CloudFox, PMapper (граф путей эскалации),
   IAM Access Analyzer.

## Remediation

- Никаких `*` в `Action`/`Resource`; политики по конкретным ресурсам и действиям.
- `iam:PassRole` ограничить условием `iam:PassedToService` и списком ролей.
- Разделение обязанностей: право менять IAM-политики — только у security-роли
  с MFA (`aws:MultiFactorAuthPresent`) и журналированием.
- SCP на уровне организации: запрет `iam:CreatePolicyVersion`,
  `iam:CreateAccessKey` для не-админов, запрет отключать CloudTrail/GuardDuty.
- Ресурсные политики: `Principal` — конкретные ARN, условия
  (`aws:SourceAccount`, `aws:PrincipalOrgID`, `aws:SourceVpce`).
- Access Analyzer для поиска внешнего доступа; PMapper-граф пересматривать
  ежеквартально.
- Секреты в Secrets Manager/SSM Parameter Store, не в tfstate; бакет состояния
  зашифрован, с версионированием и минимальным доступом.
- Алерты CloudTrail на изменения политик и создание ключей доступа.


## Detection rules

```yaml
title: AWS — изменение IAM-политик как признак эскалации
id: a1b2c3d4-0010-4a1b-9c1d-000000000010
status: experimental
description: >-
  Вызовы IAM API, которые сами по себе выдают дополнительные права.
  Легитимны только в рамках управляемого процесса изменения доступов.
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - CreatePolicyVersion
      - SetDefaultPolicyVersion
      - AttachRolePolicy
      - AttachUserPolicy
      - AttachGroupPolicy
      - PutRolePolicy
      - PutUserPolicy
      - PassRole
      - CreateAccessKey
      - AddUserToGroup
  filter_breakglass:
    userIdentity.sessionContext.sessionIssuer.userName: iam-breakglass
  condition: selection and not filter_breakglass
falsepositives:
  - автоматизация IaC (Terraform/CloudFormation) — вынесите её в отдельную роль и filter
level: high
tags: [attack.privilege_escalation, attack.t1098]
```
