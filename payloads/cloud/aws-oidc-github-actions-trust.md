---
id: cloud-aws-oidc-github-actions-trust
title: "AWS: доверие внешним OIDC-провайдерам (GitHub Actions) и перехват роли"
type: cloud
target: aws
category: cloud
difficulty: advanced
bypass: auth
tags: [aws, oidc, github-actions, iam, supply-chain, confused-deputy]
tested_on: ["IAM OIDC identity provider для token.actions.githubusercontent.com"]
success_rate: 0.4
risk: critical
cwe: "CWE-290"
lab: null
last_verified: "2026-10-23"
references:
  - "https://hackingthe.cloud/"
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html"
graph:
  - target: "cloud"
    type: instance_of
  - target: "ci-cd"
    type: related_to
  - target: "auth-bypass"
    type: leads_to
  - target: "privilege-escalation"
    type: leads_to
---

# AWS: доверие внешним OIDC-провайдерам (GitHub Actions) и перехват роли

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# как выглядит политика доверия (audit, не эксплуатация)
aws iam get-role --role-name github-deploy --query 'Role.AssumeRolePolicyDocument'
# ожидаем: Principal.Federated = arn OIDC-провайдера,
# Condition StringEquals/StringLike: token.sub = repo:org/name:ref:refs/heads/main
```

## Explanation

Связка GitHub Actions -> AWS через OIDC удобна (без долгосрочных ключей),
но политика доверия часто настраивается небрежно, и роль может принять
**любой** workflow:

1. Условие `sub` отсутствует вовсе или равно `repo:org/*` — любой репозиторий
    организации (включая публичный форк с PR) получает облачные права.
2. Используется `StringLike` с `repo:org/*:*` — wildcard покрывает ветки
    и события `pull_request` из форков.
3. `aud` не ограничен (`sts.amazonaws.com` по умолчанию, но иногда `*`).
4. Роль имеет больше прав, чем нужно конкретному workflow
    (деплой статики получает `AdministratorAccess`).
5. Роль доступна для `pull_request_target`/`workflow_run` — событий,
    выполняющихся в контексте базового репозитория с секретами
    (см. `ci-cd-github-pull-request-target`).

Результат: злоумышленник открывает PR из форка с изменённым workflow —
и получает временные ключи AWS от вашего аккаунта. Это один из самых
частых реальных инцидентов 2023–2025 гг.

## Detection

1. Перечислить OIDC-провайдеров и роли, которые им доверяют:
   `aws iam list-open-id-connect-providers`, затем для каждой роли
   `get-role` и разбор `Condition`.
2. Проверить наличие и строгость условий: `token.sub` (точный repo+ref+environment),
   `aud`, отсутствие wildcard'ов.
3. Сопоставить права роли с задачами workflow: `list-attached-role-policies`,
   `simulate-principal-policy`.
4. CloudTrail: `AssumeRoleWithWebIdentity` — кто, из какого `sub`, как часто;
   аномалия: роли, принимаемые из репозиториев, которых нет в CMDB.
5. В GitHub: список workflow с `permissions: id-token: write` и события
   `pull_request_target`/`workflow_run`, использующие окружения с секретами.
6. Инструменты: Prowler (правила по OIDC), IaC-сканеры (checkov/trivy/tfsec)
   на условиях trust-политик.

## Remediation

- В trust-политике: `Condition` с **точным** `token.actions.githubusercontent.com:sub`
  (например `repo:org/name:environment:prod`), никаких `repo:org/*`.
- Использовать GitHub **environments** с required reviewers для продакшн-ролей;
  `sub` привязывать к environment, а не к ветке.
- Ограничить `aud` конкретным значением.
- Минимальные права роли: только действия и ресурсы для конкретной задачи;
  отдельные роли на деплой/тесты/артефакты.
- Не выдавать облачные роли workflow, triggered by `pull_request_target`
  или `workflow_run` из недоверенного кода.
- Ограничить, кто может создавать/изменять workflow (branch protection,
  CODEOWNERS на `.github/workflows/`, запрет форков в org для приватных репо).
- Мониторинг `AssumeRoleWithWebIdentity` + алерт на новые `sub`.
- Короткий `MaxSessionDuration` (15–60 мин) для OIDC-ролей.

## Detection rules

```yaml
title: Изменение OIDC-доверия — AssumeRolePolicy и новые OIDC-провайдеры
id: f6a7b8c9-0010-4f6a-8b9c-000000000010
status: experimental
description: >-
  UpdateAssumeRolePolicy для ролей с github-deploy/oidc в имени либо создание
  OIDC-провайдера: расширение федеративного доверия позволяет чужим
  GitHub Actions-воркфлоу принимать роль аккаунта.
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
logsource:
  product: aws
  service: cloudtrail
  definition: 'CloudTrail management events IAM'
detection:
  trust_change:
    eventSource: iam.amazonaws.com
    eventName:
      - UpdateAssumeRolePolicy
      - UpdateAssumeRolePolicyDocument
  oidc_provider:
    eventSource: iam.amazonaws.com
    eventName: CreateOIDCProvider
  filter_ci_admin:
    userIdentity.sessionContext.sessionIssuer.userName: iam-breakglass
  condition: (trust_change or oidc_provider) and not filter_ci_admin
fields:
  - userIdentity.sessionContext.sessionIssuer.userName
  - sourceIPAddress
  - requestParameters.roleName
falsepositives:
  - плановые изменения федераций через IaC (исключайте роли pipeline-админа,
    но проверяйте diff политики — token.sub должен ограничивать репозиторий и ветку)
level: high
tags:
  - attack.persistence
  - attack.t1098
  - cwe.287
```
