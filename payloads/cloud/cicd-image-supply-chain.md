---
id: ci-cd-image-supply-chain
title: "Supply chain: неподписанные образы, `latest`-теги и зависимости без lock"
type: ci-cd
target: generic
category: cloud
difficulty: intermediate
bypass: none
tags: [supply-chain, container, signing, sbom, dependencies]
tested_on: ["Docker/OCI-реестры", "cosign/notary", "npm/pip/gradle lock-файлы"]
success_rate: 0.5
risk: high
cwe: "CWE-829"
lab: null
last_verified: "2026-10-23"
references:
  - "https://slsa.dev/spec/v1.0/about"
  - "https://hackingthe.cloud/"
graph:
  - target: "ci-cd"
    type: instance_of
  - target: "container-escape"
    type: related_to
  - target: "cloud"
    type: related_to
  - target: "persistence"
    type: leads_to
    description: "Подменённый артефакт переживает перезапуски и обновления"
---

# Supply chain: неподписанные образы, `latest`-теги и зависимости без lock

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# аудит: подписан ли образ и каков его digest
docker inspect <image> --format '{{.RepoDigests}} {{.Config.Labels}}'
cosign verify --certificate-identity-regexp 'https://github.com/<org>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <registry>/<image>@sha256:<digest>
# зависимости: есть ли lock-файлы и pin по digest
grep -rn 'image: .*:latest\|@[a-z]' docker-compose*.yml k8s/*.yaml 2>/dev/null | head
```

## Explanation

Цепочка поставки — самый «тихий» вектор: взламывать не нужно ничего,
достаточно подменить то, что вы и так устанавливаете. Контрольные точки:

| Этап | Риск | Мера |
|------|------|------|
| Зависимости (npm/pip/maven/go) | подмена пакета, typosquatting, угон аккаунта мейнтейнера | lock-файлы, приватный прокси-реестр с кешем, проверка имён |
| Базовые образы | `:latest` меняется, компрометация Docker Hub-аккаунта | pin по digest, доверенный реестр, сканирование |
| Сборка | чужой код в pipeline, отсутствие изоляции | изолированные раннеры, SLSA-уровни, минимальные права |
| Артефакт | подмена образа после сборки | подпись (cosign/sigstore), provenance-аттестат |
| Реестр | публичный доступ на push, отсутствие RBAC | RBAC, immutable-теги, сканирование при push |
| Деплой | кластер принимает любой образ | admission-контроль подписей (Kyverno/Connaisseur/policy-controller) |
| Runtime | неизвестный процесс в контейнере | SBOM + runtime-алерты |

Отдельный класс — **typosquatting и dependency confusion**:
пакет с именем внутренней библиотеки публикуется в публичном реестре
с большей версией, и менеджер пакетов предпочитает его (npm/pip/NuGet).
Лечится scope'ами, приватными реестрами с приоритетом и pin'ом версий.

## Detection

1. Инвентаризация: какие образы деплоятся (теги vs digest), подписаны ли,
   есть ли provenance/SBOM.
2. Поиск `:latest` и неподписанных образов в манифестах (`k8s/`, Helm-чарты,
   compose-файлы) — регулярным линтером в CI.
3. Проверка lock-файлов: существуют ли, соответствуют ли `package.json`/
   `requirements.txt`, есть ли расхождения.
4. Поиск внутренних имён пакетов в публичных реестрах (dependency confusion).
5. Логи реестра: push из неожиданных учётных записей/IP, изменение существующих
   тегов (mutable tags).
6. Admission-логи кластера: попытки запустить неподписанный образ.
7. Инструменты: `cosign verify`, `trivy image --scanners vuln,secret,misconfig`,
   `syft`/`grype` (SBOM), `slsa-verifier`, `in-toto`.

## Remediation

- Pin по **digest** (`image@sha256:…`) во всех манифестах; запрет `:latest`
  политикой admission-контроллера.
- Подпись образов (cosign keyless + OIDC), проверка подписи и provenance
  при деплое (Kyverno `verifyImages`, Sigstore policy-controller, Connaisseur).
- Immutable-теги в реестре, RBAC на push, отдельный реестр-прокси для внешних
  образов (кеш + контроль).
- Lock-файлы обязательны; приватные индексы/scope для внутренних пакетов;
  `--index-url`/`.npmrc` с приоритетом приватного реестра (защита от confusion).
- SBOM на каждый артефакт (CycloneDX/SPDX) + сканирование уязвимостей и секретов
  в CI, блокировка критичных.
- Изолированные ephemeral-раннеры для сборки, минимальные права `GITHUB_TOKEN`/
  `CI_JOB_TOKEN`, pin сторонних actions по SHA.
- SLSA build levels как целевая модель; хранение артефактов сборки и логов
  для расследования.
- Процесс: при компрометации upstream — быстрый отзыв (immutable-теги + digest
  делают отзыв предсказуемым) и ротация секретов, попавших в образы.

## Detection rules

```yaml
title: Supply chain образов — неподписанные push/pull и mutable-теги
id: f6a7b8c9-0018-4f6a-8b9c-000000000018
status: experimental
description: >-
  Операции с образами без проверки подписи (signed=false, digest_verified=false)
  и push c mutable-тегом (latest): подмена образа на пути к проду остаётся
  незамеченной.
references:
  - https://attack.mitre.org/techniques/T1195/001/
  - https://docs.sigstore.dev/cosign/overview/
logsource:
  category: cicd
  definition: 'журнал реестра образов (registry events) + admission-контроль (cosign/policy-controller)'
detection:
  unsigned:
    signed: false
  unverified_digest:
    digest_verified: false
  condition: unsigned or unverified_digest
fields:
  - event_type
  - registry
  - image
  - tag
falsepositives:
  - dev-окружения без подписей — включайте правило для прод-реестров,
    а для dev держите отдельный baseline
level: medium
tags:
  - attack.persistence
  - attack.t1195.001
  - cwe.494
```
