---
id: cloud-kubernetes-rbac-overpermissive
title: "Kubernetes RBAC: избыточные права ServiceAccount и доступ к secrets"
type: cloud
target: kubernetes
category: cloud
difficulty: intermediate
bypass: auth
tags: [kubernetes, rbac, serviceaccount, secrets, privilege-escalation]
tested_on: ["k8s 1.27–1.30 (kind/minikube)", "ClusterRole с wildcard"]
success_rate: 0.6
risk: critical
cwe: "CWE-732"
lab: null
last_verified: "2026-10-23"
references:
  - "https://kubernetes.io/docs/concepts/security/"
  - "https://hackingthe.cloud/"
graph:
  - target: "cloud"
    type: instance_of
  - target: "privilege-escalation"
    type: leads_to
  - target: "credential-access"
    type: leads_to
  - target: "container-escape"
    type: related_to
---

# Kubernetes RBAC: избыточные права ServiceAccount и доступ к secrets

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# из пода: что разрешено моему SA
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl auth can-i --list --token "$TOKEN" -n "$NS"
kubectl auth can-i get secrets --all-namespaces --token "$TOKEN"
kubectl auth can-i create pods/exec -n kube-system --token "$TOKEN"
kubectl auth can-i create clusterrolebindings --token "$TOKEN"
# аудит кластера: роли с wildcard и доступом к secrets
kubectl get clusterroles -o json | \
  jq -r '.items[] | select(.rules[]? | (.resources[]?|test("secrets|\\*"))) | .metadata.name'
```

## Explanation

После RCE в контейнере первый артефакт — токен ServiceAccount. Дальше всё
определяется RBAC. Опасные комбинации:

| Право | Что даёт |
|-------|----------|
| `get/list/watch secrets` (особенно `--all-namespaces`) | чужие креды, TLS-ключи, registry-секреты, токены |
| `create pods/exec` | выполнение команд в любом поде namespace (в т.ч. чужие секреты в env) |
| `create/update pods` | под с `hostPath: /`, `hostNetwork`, `privileged` -> выход на узел |
| `create/update daemonsets` | код на всех узлах кластера |
| `bind`/`escalate`/`impersonate` verbs | выдать себе права, выдать себя за другого |
| `create clusterrolebindings` | cluster-admin напрямую |
| `update serviceaccounts` + `create token` | долгосрочные токены чужих SA |
| `patch nodes/proxy`, `nodes/status` | доступ к kubelet API -> exec в подах |
| `create/patch webhookconfigurations` | перехват всех запросов admission (MITM кластера) |

Отдельная проблема — **wildcard**: `resources: ['*']`, `verbs: ['*']`,
`apiGroups: ['*']` в ClusterRole, привязанной к SA приложения.
И агрегированные ClusterRole (label `rbac.authorization.k8s.io/aggregate-to-*`).

## Detection

1. Аудит всех ClusterRole/Role: поиск wildcard, `secrets`, `pods/exec`,
   `escalate`, `bind`, `impersonate`, `webhookconfigurations`.
   Инструменты: `rbac-lookup`, `rbac-police`, `kubestriker`, `k9s` + jq.
2. Аудит привязок: какие SA/пользователи привязаны к cluster-admin
   и к ролям с `secrets` (включая system-роли).
3. Для каждого SA приложения: `kubectl auth can-i --list --as=system:serviceaccount:ns:sa`.
4. Audit-лог кластера: обращения к `/api/v1/secrets`, `pods/exec`,
   создание pods с `hostPath`/`privileged`, изменения RBAC-объектов.
5. Проверка `automountServiceAccountToken`: смонтирован ли токен там,
   где он не нужен.
6. Поиск SA с правами на `nodes/proxy` и доступ к kubelet (обход API server).

## Remediation

- `automountServiceAccountToken: false` по умолчанию; монтировать токен
  только подам, которым нужен API.
- Отдельный SA на workload; RBAC по принципу минимальных прав:
  конкретные `apiGroups`/`resources`/`verbs`, никаких wildcard.
- Запретить `secrets` вне своего namespace; для общих секретов —
  External Secrets Operator/Vault Agent с точечными правами.
- Admission-контроль (Kyverno/OPA Gatekeeper/Pod Security Admission `restricted`):
  запрет privileged, hostPath, hostNetwork/hostPID, `capabilities` сверх нужного,
  требование runAsNonRoot, readOnlyRootFilesystem.
- NetworkPolicy deny-all по умолчанию; доступ к API server только нужным SA.
- Шифрование секретов в etcd (`EncryptionConfiguration`), доступ к etcd только
  у control plane (mTLS).
- Audit policy с уровнем `RequestResponse` для RBAC и secrets; аудит-логи в SIEM.
- Регулярный ревью RBAC (ежеквартально) и при каждом изменении Helm-чартов;
  IaC-сканирование (trivy/checkov/kubescape) в CI.

## Detection rules

```yaml
title: Опасные RBAC-binding'и — cluster-admin и wildcard-права
id: f6a7b8c9-0006-4f6a-8b9c-000000000006
status: experimental
description: >-
  Создание clusterrolebinding/rolebinding с cluster-admin, субъектом
  system:unauthenticated/default SA или wildcard-правами ("*") — закрепление
  избыточных прав, типичный след компрометации или «временного» фикса.
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
logsource:
  product: kubernetes
  service: audit
  definition: 'Kubernetes Audit Log с requestObject для rbac.authorization.k8s.io'
detection:
  binding_op:
    verb:
      - create
      - update
      - patch
    objectRef_resource:
      - clusterrolebindings
      - rolebindings
      - clusterroles
  dangerous_ref:
    requestObject|contains:
      - 'cluster-admin'
      - '"*"'
      - 'system:unauthenticated'
      - '"name":"default"'
  condition: binding_op and dangerous_ref
fields:
  - user_username
  - objectRef_resource
  - objectRef_name
  - requestObject
falsepositives:
  - установка кластерных аддонов (ingress, CNI) — сверяйте с деплой-пайплайном
    и исключайте известные service-аккаунты установки
level: high
tags:
  - attack.persistence
  - attack.t1098
  - cwe.732
```
