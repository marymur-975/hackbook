---
id: cloud-lambda-env-vars-confused-deputy
title: "Lambda: секреты в переменных окружения и confused deputy в ресурсных политиках"
type: cloud
target: aws
category: cloud
difficulty: intermediate
bypass: none
tags: [aws, lambda, secrets, confused-deputy, resource-policy]
tested_on: ["AWS Lambda (Node/Python)", "ресурсные политики с внешним Principal"]
success_rate: 0.4
risk: high
cwe: "CWE-441"
lab: null
last_verified: "2026-10-23"
references:
  - "https://hackingthe.cloud/"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
graph:
  - target: "cloud"
    type: instance_of
  - target: "info-disclosure"
    type: leads_to
  - target: "auth-bypass"
    type: leads_to
  - target: "ssrf"
    type: related_to
---

# Lambda: секреты в переменных окружения и confused deputy в ресурсных политиках

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# что видит функция изнутри (своя роль, свои переменные)
#   AWS_REGION, AWS_SESSION_TOKEN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY —
#   временные ключи роли исполнения доступны любому коду функции
aws lambda get-function-configuration --function-name <fn> \
  --query 'Environment.Variables'          # часто содержит literal-секреты
aws lambda get-policy --function-name <fn> # кто может её вызывать извне
```

## Explanation

Две независимые проблемы:

**1. Секреты в переменных окружения.** Код функции получает временные ключи
роли исполнения автоматически, а разработчики добавляют туда строки подключения,
API-ключи и токены в открытом виде. Их читают все, у кого есть
`lambda:GetFunctionConfiguration`, они попадают в CloudTrail-ответы,
в дампы окружения при ошибках и в артефакты CI. Отдельный риск — зависимости:
любая библиотека в рантайме может прочитать `os.environ` и отправить наружу.

**2. Confused deputy.** Функция (или сервис) с привилегированной ролью
принимает от внешнего вызывающего параметр (ARN роли, bucket, URL) и
использует **свои** права для доступа к указанному ресурсу. Примеры:
- ресурсная политика Lambda с `Principal: "*"` и параметром, влияющим на то,
  к какому S3-бакету функция обращается;
- `iam:PassRole` без условия `iam:PassedToService`;
- Step Functions/EventBridge с целью, задаваемой из события.
Проверка источника вызова (`aws:SourceAccount`, `aws:SourceArn`,
`aws:PrincipalOrgID`) — единственный надёжный способ закрыть класс.

## Detection

1. Выгрузить переменные окружения всех функций и поискать literal-секреты
   (grep по `password|secret|token|key|dsn|connection`).
2. Проверить права роли исполнения: `lambda:InvokeFunction`, доступ к S3/DynamoDB,
   `sts:AssumeRole` — часто избыточны.
3. Ресурсные политики: `aws lambda get-policy`, `aws s3api get-bucket-policy`,
   `aws sqs get-queue-attributes` — искать `Principal: "*"` и отсутствие
   условий `SourceArn`/`SourceAccount`.
4. CloudTrail: кто вызывает функцию (`Invoke`), откуда (sourceArn),
   и какие вызовы делает сама функция сразу после внешнего события.
5. Анализ кода: функции, принимающие ARN/URL/имя ресурса из события
   и использующие его в SDK-вызове без валидации.
6. Инструменты: Prowler, CloudFox (`--scenario secrets`, `ops`),
   IaC-сканеры на ресурсных политиках.

## Remediation

- Секреты — только в Secrets Manager / SSM Parameter Store (SecureString)
  с доступом через роль исполнения; переменные окружения — для нечувствительной
  конфигурации.
- Шифровать переменные окружения KMS-ключом с отдельными правами на расшифровку
  (ограничивает чтение конфигурации).
- Минимальные права роли функции: конкретные ресурсы и действия, без `*`.
- В ресурсных политиках: точный `Principal` + условия
  `aws:SourceAccount`, `aws:SourceArn`, `aws:PrincipalOrgID`.
- `iam:PassRole` — с условием на сервис и на конкретные роли.
- В коде: whitelist допустимых ARN/бакетов/URL из входящих событий,
  никаких «пользователь указал ресурс — мы к нему сходим своими правами».
- Изоляция зависимостей: pinning версий, проверка пакетов (SCA), минимальный
  набор библиотек, egress-ограничения VPC.
- Алерты: новые `Principal: "*"` в ресурсных политиках, вызовы функций
  из unexpected-источников.

## Detection rules

```yaml
title: Lambda confused deputy — смена конфигурации функции и чужой AssumeRole
id: f6a7b8c9-0011-4f6a-8b9c-000000000011
status: experimental
description: >-
  UpdateFunctionConfiguration/UpdateFunctionCode (секреты в env доступны
  любому коду функции) и sts:AssumeRole сервисной роли из контекста другой
  функции — классический confused deputy с временными ключами роли исполнения.
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
logsource:
  product: aws
  service: cloudtrail
  definition: 'CloudTrail management events Lambda + STS AssumeRole'
detection:
  lambda_change:
    eventSource: lambda.amazonaws.com
    eventName:
      - UpdateFunctionConfiguration
      - UpdateFunctionCode
      - CreateFunction
  cross_role_assume:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
    userIdentity.type: AssumedRole
  lambda_role:
    requestParameters.roleName|contains: 'lambda-'
  condition: lambda_change or (cross_role_assume and lambda_role)
fields:
  - userIdentity.sessionContext.sessionIssuer.userName
  - sourceIPAddress
  - requestParameters.functionName
  - requestParameters.roleName
falsepositives:
  - штатные деплои функций из CI — исключайте роль деплоя, но держите алерт
    на cross_role_assume между разными сервисами
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1552.005
  - cwe.441
```
