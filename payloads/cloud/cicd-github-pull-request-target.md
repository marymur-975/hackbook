---
id: ci-cd-github-pull-request-target
title: "GitHub Actions: pull_request_target и утечка секретов из форка"
type: ci-cd
target: github-actions
category: cloud
difficulty: advanced
bypass: auth
tags: [ci-cd, github-actions, secrets, supply-chain, pwn-request]
tested_on: ["GitHub Actions (hosted runners)", "workflow с pull_request_target + checkout PR-head"]
success_rate: 0.5
risk: critical
cwe: "CWE-94"
lab: null
last_verified: "2026-10-23"
references:
  - "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
  - "https://hackingthe.cloud/"
graph:
  - target: "ci-cd"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "credential-access"
    type: leads_to
  - target: "cloud"
    type: related_to
---

# GitHub Actions: pull_request_target и утечка секретов из форка

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# опасный паттерн (антипример из реальных репозиториев)
on: pull_request_target        # выполняется в контексте BASE с секретами
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # код из форка!
      - run: npm ci && npm test       # выполняет чужой код с доступом к secrets
      - uses: aws-actions/configure-aws-credentials@v4    # выдаёт облачную роль
```

## Explanation

`pull_request_target` задуман как безопасная альтернатива `pull_request`:
workflow берётся из **базовой** ветки, секреты доступны. Но если в таком
workflow дополнительно checkout'ится код PR (`ref: …head.sha`) и затем
выполняется (`npm test`, `make`, `pytest`, `bash ./scripts/*`),
злоумышленник из форка получает выполнение **своего** кода с вашими секретами.
Это и есть «pwn request».

Родственные векторы:

- `workflow_run` с `pull_request`-триггером и checkout артефактов PR;
- небезопасные `${{ github.event.* }}` прямо в `run:` — инъекция команд
  через заголовок PR/имя ветки/комментарий (`$(curl …)`, обратные кавычки);
- сторонние actions без pin'а на SHA (`uses: some/action@main`) —
  компрометация action'а = компрометация всех workflow;
- `GITHUB_TOKEN` с правами `contents: write` + `pull-requests: write`
  (можно изменить код/релизы);
- self-hosted runners на публичных репозиториях: любой PR выполняет код
  на вашей машине (и остаётся там жить);
- OIDC-роли облака, выдаваемые PR-workflow (см. `cloud-aws-oidc-github-actions-trust`).

Отдельный класс — компрометация зависимости/образа, который тянет pipeline
(supply chain): неподписанные артефакты, отсутствие lock-файлов, `latest`-теги.

## Detection

1. Аудит всех workflow: триггеры `pull_request_target`/`workflow_run` +
   `checkout` с `head`-ref + последующий `run` — это красный флаг.
2. Поиск инъекций `${{ github.event.* }}` внутри `run:` блоков
   (инструменты: `actionlint`, `zizmor`, Semgrep-правила для GitHub Actions).
3. Инвентаризация `uses:` — есть ли pin на полный SHA коммита, а не на ветку/тег.
4. Права `GITHUB_TOKEN`: `permissions:` на уровне workflow/job;
   настройка org «Read repository contents by default».
5. Self-hosted runners: используются ли в публичных репозиториях,
   включён ли ephemeral-режим, есть ли fork-PR на них.
6. Логи: запуск job'ов с секретами для событий из форков;
   CloudTrail — `AssumeRoleWithWebIdentity` из неожиданных репозиториев.
7. Проверка org-настроек: разрешены ли fork-PR на self-hosted runners,
   требуется ли approval для first-time contributors.

## Remediation

- Не делать checkout кода PR в `pull_request_target`. Если нужно —
  разделять: один job без секретов собирает артефакты, второй (с секретами)
  работает только с **артефактами**, не выполняя код PR.
- Никогда не подставлять `${{ github.event.* }}` в `run:` — передавать
  через `env:` (`env: TITLE: ${{ github.event.pull_request.title }}`).
- Pin сторонних actions на полный SHA коммита; Dependabot/Renovate
  для обновлений с ревью.
- `permissions:` — минимальные (`contents: read` по умолчанию);
  org-level «Read repository contents and packages permissions».
- Запретить self-hosted runners для публичных репо; только ephemeral
  (`--ephemeral`) и с `ACTIONS_RUNNER_REQUIRE_JOB_INTEGRITY`.
- Требовать approval для workflow от first-time contributors
  и для изменений в `.github/workflows/` (CODEOWNERS + branch protection).
- OIDC-роли облака: точный `sub` (`repo:org/name:environment:prod`),
  никаких wildcard; отдельные роли для PR-сборок без облачных прав.
- SLSA/provenance, подпись артефактов (cosign), проверка подписей
  образов в admission-контроллере кластера.
- Секреты: scoped на environment с required reviewers, ротация,
  аудит обращений; минимальный срок жизни OIDC-сессий.


## Detection rules

```yaml
title: GitHub Actions — выполнение кода PR с доступом к секретам
id: a1b2c3d4-0011-4a1b-9c1d-000000000011
status: experimental
description: >-
  Эвристическое правило для аудита конфигурации CI: сочетание триггера
  pull_request_target/workflow_run с checkout кода head-ветки и последующим
  выполнением команд. Требует анализа workflow-файлов, а не рантайм-логов.
logsource:
  category: ci_cd
  product: github_actions
detection:
  selection_trigger:
    trigger:
      - pull_request_target
      - workflow_run
  selection_checkout:
    step_uses|contains: actions/checkout
    step_with_ref|contains:
      - github.event.pull_request.head.sha
      - github.head_ref
      - github.event.workflow_run.head_sha
  selection_secrets:
    job_needs_secrets: true
  condition: selection_trigger and selection_checkout and selection_secrets
falsepositives:
  - доверенные внутренние репозитории с обязательным ревью (риск ниже, но не нулевой)
level: high
tags: [attack.execution, attack.t1053]
```
