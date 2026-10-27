---
id: ci-cd-gitlab-runner-token-abuse
title: "CI/CD: токены раннеров, переменные пайплайнов и артефакты"
type: ci-cd
target: gitlab
category: cloud
difficulty: intermediate
bypass: auth
tags: [ci-cd, gitlab, runner, secrets, artifacts, supply-chain]
tested_on: ["GitLab CI (shared и dedicated runners)", "GitLab 16.x"]
success_rate: 0.45
risk: high
cwe: "CWE-522"
lab: null
last_verified: "2026-10-23"
references:
  - "https://hackingthe.cloud/"
  - "https://docs.gitlab.com/ee/ci/security/"
graph:
  - target: "ci-cd"
    type: instance_of
  - target: "credential-access"
    type: leads_to
  - target: "container-escape"
    type: related_to
  - target: "cloud"
    type: related_to
---

# CI/CD: токены раннеров, переменные пайплайнов и артефакты

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# что видно изнутри job'а (аудит на СВОЁМ проекте)
env | grep -E 'CI_|GITLAB|TOKEN|SECRET|KEY' | sed 's/=.*/=<redacted>/'
# переменные проекта/группы и их флаги (protected/masked)
glab variable list 2>/dev/null || echo 'нужен доступ к API'
# артефакты и кеш: что уезжает между job'ами
ls -la .gitlab-ci.yml artifacts/ 2>/dev/null
```

## Explanation

CI-система — концентратор секретов: переменные пайплайнов, токены раннеров,
cloud-credentials, доступ к реестрам и кластерам. Типовые проблемы:

1. **Переменные без `protected`** — доступны в job'ах из MR/веток,
   которые может создать любой разработчик (или форк). Плюс `masked`
   скрывает значение в логе, но не мешает отправить его наружу.
2. **Токены раннеров в открытом виде**: registration token в `.gitlab-ci.yml`,
   `/etc/gitlab-runner/config.toml`, в логах и бэкапах; shared runner,
   доступный всем проектам группы, выполняет чужой код рядом с вашим.
3. **Docker-in-Docker / монтирование сокета** в job'ах сборки —
   выход на хост раннера (см. `cloud-docker-socket-escape`).
4. **Артефакты и кеш** содержат секреты: `.env`, `kubeconfig`,
   `terraform.tfstate`, npm/pip-кеш с токенами; хранятся долго и читаются
   широким кругом.
5. **`CI_JOB_TOKEN`** по умолчанию может обращаться к API других проектов —
   при слабых настройках это горизонтальное перемещение по GitLab.
6. **Инъекция в `script:`** через переменные MR (заголовок, имя ветки,
   комментарий) — тот же класс, что и в GitHub Actions.
7. **Внешние зависимости и образы без pin'а**: `image: node:latest`,
   `before_script: curl … | bash` — компрометация upstream'а.
8. **Manual/job-триггеры без защиты**: `when: manual` на деплой, доступный
   любому с ролью Developer.

## Detection

1. Аудит `.gitlab-ci.yml` во всех проектах: `protected`/`masked` у переменных,
   `rules:` для MR-пайплайнов, наличие `curl | bash`, `latest`-тегов,
   DinD/сокета, `CI_JOB_TOKEN`-доступов.
2. Инвентаризация раннеров: shared/specific, теги, привилегированный режим,
   какие проекты могут их использовать.
3. Проверка артефактов и кеша на секреты (gitleaks/trufflehog по архивам).
4. GitLab audit events: изменения переменных, добавление раннеров,
   изменения ролей, доступ к API через `CI_JOB_TOKEN`.
5. Поиск токенов в репозиториях и образах: `glpat-`, `GR1348941`,
   `runner registration token`, `kubeconfig`.
6. Аномалии в логах job'ов: исходящие запросы на неизвестные хосты
   (эксфильтрация переменных).

## Remediation

- Все секреты — `protected` + `masked` + file-тип; выдавать только
   защищённым веткам/тегам; лучше — внешний vault (HashiCorp Vault,
   cloud secret manager) с короткоживущими учётными данными.
- Пайплайны из MR/форков выполнять **без секретов** и на изолированных
   ephemeral-раннерах.
- Раннеры: dedicated на проект/группу, `privileged = false`, без docker.sock;
  для сборки образов — kaniko/buildkit rootless; rotation токенов,
  новые authentication-токены вместо registration tokens.
- Ограничить `CI_JOB_TOKEN`: allowlist проектов, минимум прав.
- Артефакты: не хранить секреты, короткий `expire_in`, отдельное хранилище
  с аудитом; кеш — только нечувствительные зависимости.
- Pin образов и зависимостей по SHA/digest, lock-файлы, SCA в пайплайне.
- Запрет `curl … | bash` в CI (политика + линтер `gitlab-ci-linter`/`actionlint`-аналоги).
- Ревью изменений CI-конфигурации обязательно (CODEOWNERS на `.gitlab-ci.yml`).
- Мониторинг: алерты на новые переменные, добавление раннеров, исходящий трафик job'ов.

## Detection rules

```yaml
title: GitLab — регистрация чужого раннера и разведка API job-токеном
id: f6a7b8c9-0017-4f6a-8b9c-000000000017
status: experimental
description: >-
  Новый раннер регистрируется украденным токеном (часто с внешнего IP), затем
  CI_JOB_TOKEN используется для перечисления проектов/переменных через /api/v4.
references:
  - https://attack.mitre.org/techniques/T1078/
  - https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html
logsource:
  category: cicd
  definition: 'GitLab audit events + журнал API (json logs) + события раннеров'
detection:
  runner_reg:
    event_type: runner_registration
  job_token_recon:
    auth_kind: ci_job_token
    api_path|contains:
      - '/api/v4/projects'
      - '/api/v4/groups'
      - '/variables'
  condition: runner_reg or job_token_recon
fields:
  - source_ip
  - project_path
  - runner_token_prefix
  - api_path
falsepositives:
  - легитимная регистрация раннеров админами (сверяйте source_ip с реестром
    инфраструктуры); job_token_recon ограничьте эндпоинтами, которые джобы
    реально используют
level: high
tags:
  - attack.initial_access
  - attack.t1078
  - cwe.798
```
