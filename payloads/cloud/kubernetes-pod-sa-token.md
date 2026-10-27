---
id: cloud-kubernetes-pod-sa-token
title: "Kubernetes: токен ServiceAccount из пода и эскалация"
type: cloud
target: kubernetes
category: cloud
difficulty: intermediate
bypass: none
tags: [kubernetes, k8s, serviceaccount, privilege-escalation]
tested_on: ["k8s 1.24+ (bound SA tokens)"]
success_rate: 0.5
risk: high
cwe: "CWE-522"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0007/"
  - "https://hackingthe.cloud/"
graph:
  - target: "cloud"
    type: instance_of
  - target: "privilege-escalation"
    type: leads_to
  - target: "credential-access"
    type: related_to
---

# Kubernetes: токен ServiceAccount из пода и эскалация

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## Explanation

В каждом поде по умолчанию смонтирован токен ServiceAccount. После RCE в контейнере
это первый артефакт: токен даёт доступ к API server с правами этого SA.
Дальше — стандартная разведка прав: что можно читать/создавать.
Опасные возможности:

- `get/list secrets` в своём namespace -> чужие креды, docker-registry keys
- `create pods/exec` -> выполнение команд в других подах
- `create pods` с `hostPath`/`hostNetwork`/privileged -> выход на узел (node takeover)
- `create clusterrolebindings` -> cluster-admin
- доступ к CA-сертификату и `namespace` файлу рядом с токеном

С k8s 1.24 токены bound (короткоживущие, привязаны к поду/объекту), что ограничивает
их переиспользование, но внутри кластера они по-прежнему работают.

## Detection

1. Внутри пода: прочитать токен, затем `kubectl auth can-i --list --token <t>`.
2. Проверьте, какие SA имеют `secrets` и `pods/exec` (RBAC-аудит: `rbac-lookup`,
   `kubiscan`, `peirates`).
3. В audit-логах: обращения к `/api/v1/namespaces/*/secrets` с SA workload'ов.
4. Ищите поды с `hostPath: /`, `privileged: true`, `hostPID` — это готовые пути на узел.

## Remediation

- `automountServiceAccountToken: false` по умолчанию; монтировать только там, где нужно.
- Отдельный SA на workload, минимальный RBAC; запрет `secrets` вне своего namespace.
- Bound SA tokens (k8s >= 1.24), короткий TTL, `audiences` под задачу.
- Admission-контроль (OPA/Kyverno): запрет privileged, hostPath, hostNetwork.
- NetworkPolicy: pod -> API server только для нужных SA.
- Аудит и алерты на попытки чтения secrets и создания pods/exec.

## Detection rules

```yaml
title: Злоупотребление SA-токеном пода — exec, секреты и чужие ресурсы
id: f6a7b8c9-0005-4f6a-8b9c-000000000005
status: experimental
description: >-
  Сервисный аккаунт пода (system:serviceaccount:...) совершает действия за
  пределами своей роли: exec в другие поды, list/get secrets, создание подов.
  Токен из /var/run/secrets/... — первая цель атакующего после RCE в контейнере.
references:
  - https://attack.mitre.org/techniques/T1552/001/
  - https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
logsource:
  product: kubernetes
  service: audit
  definition: 'Kubernetes Audit Log'
detection:
  selection:
    user_username|startswith: 'system:serviceaccount:'
  suspicious_ops:
    objectRef_subresource: exec
  suspicious_resources:
    objectRef_resource:
      - secrets
      - pods
      - serviceaccounts
  filter_infra:
    user_username|contains:
      - 'prometheus'
      - 'monitoring'
      - 'system:node'
      - 'kube-proxy'
  condition: selection and (suspicious_ops or suspicious_resources) and not filter_infra
fields:
  - user_username
  - verb
  - objectRef_resource
  - objectRef_subresource
  - objectRef_namespace
falsepositives:
  - CI-деплоеры, легитимно создающие поды в своём неймспейсе — сужайте
    suspicious_resources по objectRef_namespace и дополняйте filter_infra
level: high
tags:
  - attack.credential_access
  - attack.t1552.001
  - cwe.269
```
