---
id: cloud-kubernetes-api-anonymous-rbac
title: "Kubernetes: анонимный доступ к API и слабый RBAC на системных ролях"
type: cloud
target: kubernetes
category: cloud
difficulty: intermediate
bypass: auth
tags: [kubernetes, api-server, anonymous, rbac, exposure]
tested_on: ["kubeadm-кластер 1.27–1.30", "managed-кластеры (EKS/GKE/AKS)"]
success_rate: 0.35
risk: critical
cwe: "CWE-306"
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
  - target: "info-disclosure"
    type: leads_to
  - target: "network"
    type: related_to
---

# Kubernetes: анонимный доступ к API и слабый RBAC на системных ролях

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# диагностика СВОЕГО кластера (без токена)
curl -sk https://<api>:6443/version
curl -sk https://<api>:6443/api/v1/namespaces | head -c 300
curl -sk https://<api>:6443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews -X POST \
  -H 'Content-Type: application/json' \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'
# kubelet без авторизации
curl -sk https://<node>:10250/pods | head -c 200
```

## Explanation

Три независимые точки входа в кластер:

1. **API server**: `--anonymous-auth=true` (по умолчанию) создаёт субъекта
    `system:anonymous` в группе `system:unauthenticated`. Сам по себе он
    почти ничего не может (`system:public-info-viewer` -> `/version`,
    `/healthz`), но любая ClusterRoleBinding на `system:unauthenticated`
    или `system:authenticated` с широкими правами открывает данные.
2. **kubelet 10250**: при `--anonymous-auth=true` и
    `--authorization-mode=AlwaysAllow` любой клиент в сети узла выполняет
    команды в подах (`/run/<ns>/<pod>/<container>`), читает логи и метрики.
3. **etcd 2379/2380**: без mTLS — дамп всего кластера (см. отдельную карточку).

Слабый RBAC усугубляет картину: ClusterRoleBinding на
`system:authenticated` (то есть **любой** аутентифицированный, включая
SA любого пода) с правами `list secrets`/`create pods`; агрегированные роли;
`cluster-admin`, выданный сервису мониторинга; права `bind`/`escalate`.

В managed-кластерах анонимный доступ к API обычно закрыт, но kubelet и
внутренние сервисы остаются зоной риска.

## Detection

1. Проверить `/version` без токена (должен отвечать — это нормально),
   затем `/api/v1/namespaces` (не должен).
2. `kubectl get clusterrolebindings -o json | jq` — поиск субъектов
   `system:unauthenticated`, `system:authenticated` и ролей с
   `secrets`, `pods/exec`, `escalate`, `bind`, `impersonate`.
3. kubelet: `curl -sk https://<node>:10250/pods` без сертификата;
   проверка флагов в `/var/lib/kubelet/config.yaml`
   (`anonymousAuth`, `authorization.mode`).
4. `kubescape`/`kube-bench`/`kubestriker` — готовые наборы проверок
   по CIS Benchmark.
5. Audit-лог кластера: запросы от `system:anonymous`, массовые `list secrets`.
6. Сетевая доступность 6443/10250/2379 из пользовательских сегментов.

## Remediation

- `--anonymous-auth=false` на API server (или жёсткий RBAC для unauthenticated).
- kubelet: `anonymousAuth: false`, `authorization.mode: Webhook`,
   `authentication.x509.clientCAFile` + TLS; 10250 доступен только control plane.
- etcd: mTLS, сеть control plane, шифрование секретов.
- RBAC: никаких ClusterRoleBinding на `system:authenticated`/`unauthenticated`;
   минимум прав на SA; запрет `escalate`/`bind`/`impersonate` у приложений.
- NetworkPolicy deny-all + разрешающие правила; сегментация узлов.
- Audit policy включён и уходит в SIEM; алерт на `system:anonymous` и на
   `list/get secrets`.
- Регулярный прогон CIS Benchmark (kube-bench/kubescape) в CI.
- Managed-кластеры: приватные эндпоинты API, authorized networks/whitelist IP,
   отключение публичного доступа.

## Detection rules

```yaml
title: Kubernetes API — анонимная разведка, включая отклонённые запросы
id: f6a7b8c9-0002-4f6a-8b9c-000000000002
status: experimental
description: >-
  Любая активность system:anonymous, в том числе 401/403 и selfsubjectrulesreviews:
  сканирование внешнего API-сервера (6443) и перечисление доступных прав.
references:
  - https://attack.mitre.org/techniques/T1595/
  - https://attack.mitre.org/techniques/T1613/
logsource:
  product: kubernetes
  service: audit
  definition: 'Kubernetes Audit Log, включая стадии отказа в доступе'
detection:
  selection:
    user_username: system:anonymous
  filter_healthz:
    requestURI:
      - /healthz
      - /livez
      - /readyz
      - /version
  condition: selection and not filter_healthz
fields:
  - user_username
  - verb
  - requestURI
  - responseStatus_code
  - sourceIPs
falsepositives:
  - probe'ы и мониторинг без токена — исключайте их URI и внутренние sourceIPs
level: high
tags:
  - attack.discovery
  - attack.t1595
  - attack.t1613
  - cwe.306
```
