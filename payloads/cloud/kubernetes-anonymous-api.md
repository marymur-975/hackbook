---
id: cloud-kubernetes-anonymous-api
title: "Kubernetes: анонимный доступ к API и kubelet"
type: cloud
target: kubernetes
category: cloud
difficulty: intermediate
bypass: auth
tags: [kubernetes, k8s, anonymous, kubelet]
tested_on: ["kubeadm-кластер (anonymous-auth=true)", "kubelet 10250"]
success_rate: 0.4
risk: high
cwe: "CWE-306"
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
  - target: "rce"
    type: leads_to
    description: "kubelet /run даёт выполнение команд в подах"
---

# Kubernetes: анонимный доступ к API и kubelet

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
curl -k https://10.10.10.5:6443/api/v1/namespaces/default/pods
```

## Explanation

Две типовые точки входа:

1. API server с `--anonymous-auth=true` и RBAC, выдающим `system:unauthenticated`
    права (например, `system:public-info-viewer` или, хуже, широкие роли).
    Тогда доступны `/version`, `/api`, иногда списки pods/secrets.
2. Kubelet API (порт 10250) без аутентификации/авторизации — выполнение команд
    в любом поде кластера: `POST /run/<ns>/<pod>/<container>` с `cmd=id`.
    Это прямой путь к компрометации всех workload'ов и их секретов.

Отдельно: `etcd` (2379) без TLS/аутентификации содержит ВСЕ секреты кластера,
а dashboard (30228/8001) с `--enable-skip-login` даёт полный доступ.

## Detection

1. `curl -k https://<api>:6443/version` и `/api/v1/namespaces` — без токена.
2. `curl -k https://<node>:10250/pods` — список подов без авторизации.
3. `kubectl auth can-i --list --as=system:anonymous`.
4. Сканеры: `kube-hunter`, `peirates`, `kubestriker`, `trivy`.
5. Признаки в аудите кластера: `system:anonymous` в `user.username`.

## Remediation

- `--anonymous-auth=false` на API server (или жёсткий RBAC для unauthenticated).
- Kubelet: `--anonymous-auth=false`, `--authorization-mode=Webhook`, TLS-клиентские
  сертификаты; 10250 только из control plane.
- etcd: mTLS + RBAC, никогда не наружу; шифрование секретов (`EncryptionConfiguration`).
- RBAC: запрет `get/list` на `secrets` широким ролям; отдельные SA на workload.
- NetworkPolicy (deny-all по умолчанию), Pod Security Standards `restricted`.
- Аудит-логи кластера + алерты на `system:anonymous` и доступ к secrets.

## Variants

```
curl -k https://10.10.10.5:10250/pods
```

```
curl -k https://10.10.10.5:6443/api/v1/secrets
```

## Detection rules

```yaml
title: Kubernetes API — успешные анонимные запросы
id: f6a7b8c9-0001-4f6a-8b9c-000000000001
status: experimental
description: >-
  Запросы от system:anonymous/system:unauthenticated, завершившиеся успехом
  (200/201/101): кластер отдаёт данные неаутентифицированным клиентам —
  анонимный доступ включён и подкреплён RBAC-binding'ами.
references:
  - https://attack.mitre.org/techniques/T1613/
  - https://kubernetes.io/docs/reference/access-authn-authz/authentication/
logsource:
  product: kubernetes
  service: audit
  definition: 'Kubernetes Audit Log (policy: Metadata и выше для всех verb)'
detection:
  selection:
    user_username: system:anonymous
  success:
    responseStatus_code:
      - 200
      - 201
      - 101
  condition: selection and success
fields:
  - user_username
  - verb
  - requestURI
  - objectRef_resource
  - sourceIPs
falsepositives:
  - health-check probe'ы балансировщика к /healthz /livez /readyz — выносите
    эти requestURI в исключения
level: critical
tags:
  - attack.discovery
  - attack.t1613
  - cwe.306
```
