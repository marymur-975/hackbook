---
id: cloud-kubernetes-etcd-no-encryption
title: "Kubernetes: etcd без шифрования и анонимный доступ к кластерным секретам"
type: cloud
target: kubernetes
category: cloud
difficulty: intermediate
bypass: auth
tags: [kubernetes, etcd, secrets, encryption, audit]
tested_on: ["kubeadm-кластер 1.27", "etcd 3.5 (mTLS и без)"]
success_rate: 0.45
risk: critical
cwe: "CWE-311"
lab: null
last_verified: "2026-10-23"
references:
  - "https://kubernetes.io/docs/concepts/security/"
  - "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"
graph:
  - target: "cloud"
    type: instance_of
  - target: "info-disclosure"
    type: leads_to
  - target: "credential-access"
    type: leads_to
  - target: "network"
    type: related_to
---

# Kubernetes: etcd без шифрования и анонимный доступ к кластерным секретам

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# диагностика СВОЕГО кластера: зашифрованы ли секреты в etcd
kubectl get --raw /api/v1/namespaces/default/secrets | head -c 200
# на control-plane-узле (только с разрешением!):
ETCDCTL_API=3 etcdctl --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/<name> | head -c 100 | xxd | head
# наличие конфигурации шифрования
grep -R 'encryption-provider-config' /etc/kubernetes/manifests/ 2>/dev/null
```

## Explanation

Все секреты кластера (пароли, токены, TLS-ключи, registry-cred'ы) лежат
в etcd. По умолчанию они хранятся в **base64, а не в шифрованном виде**:
любой, кто получил доступ к etcd (чтение диска, снапшот, резервная копия,
открытый порт 2379/2380, скомпрометированный control-plane-узел),
читает их напрямую.

Смежные проблемы:

1. etcd опубликован наружу или доступен без mTLS (порт 2379) — полный дамп
    кластера без единой учётки Kubernetes.
2. `--anonymous-auth=true` на API server + RBAC, дающий
    `system:unauthenticated` доступ к `secrets` (или широким `list`-правам).
3. Audit policy отсутствует или на уровне `None` — компрометация невидима.
4. Снапшоты etcd в бэкапах лежат рядом с бэкапами БД, доступ к которым шире.
5. `EncryptionConfiguration` включает только `secrets`, забывая `configmaps`
    (в них тоже кладут строки подключения).

Шифрование etcd не защищает от атакующего, который уже имеет доступ к
API server с правами на `get secrets` (для этого нужен RBAC-аудит),
но закрывает путь «прочитал диск/бэкап — получил всё».

## Detection

1. Проверить `kube-apiserver.yaml` на наличие `--encryption-provider-config`
   и содержимое `EncryptionConfiguration` (провайдер `aescbc`/`secretbox`/KMS).
2. Проверить доступность etcd: `ss -lntp | grep 2379`, доступ извне control-plane,
   требуется ли клиентский сертификат (`ETCDCTL_API=3 etcdctl endpoint health`).
3. `kube-bench` (разделы 1.1.19–1.1.34, 2.1) и `kubescape control` —
   готовые правила по etcd/шифрованию/анонимному доступу.
4. Проверить `--anonymous-auth` и RBAC для `system:unauthenticated` /
   `system:public-info-viewer`.
5. Audit policy: есть ли `/etc/kubernetes/audit/policy.yaml` и уровень
   `RequestResponse` для secrets/RBAC; куда уходят логи.
6. В бэкапах: наличие снапшотов etcd без шифрования и с широким доступом.

## Remediation

- Включить шифрование секретов: `EncryptionConfiguration` с провайдером KMS
   (предпочтительно, AWS KMS/GCP KMS/Azure KV/Vault) или `secretbox`/`aescbc`;
   затем `kubectl get secrets -A -o json | kubectl replace -f -`
   для перезаписи существующих значений.
- Шифровать не только `secrets`, но и `configmaps` (если там бывают секреты).
- etcd: только mTLS, только control-plane-сеть, никаких публичных 2379/2380;
   отдельные сертификаты для client/peer.
- `--anonymous-auth=false` (или минимум RBAC для unauthenticated);
   kubelet — `--anonymous-auth=false` + `--authorization-mode=Webhook`.
- Audit policy с уровнями `Metadata`/`RequestResponse` для secrets, RBAC,
   exec; логи в SIEM с защитой от изменения.
- Резервные копии etcd шифровать и хранить отдельно, доступ по принципу
   минимальных прав; регулярно проверять восстановление.
- Ротация ключей шифрования и сертификатов; мониторинг истекающих сроков.

## Detection rules

```yaml
title: Доступ к секретам кластера — API list/get secrets и прямое чтение etcd
id: f6a7b8c9-0003-4f6a-8b9c-000000000003
status: experimental
description: >-
  Массовое чтение secrets через API (list) или прямой доступ к etcd по
  URI /v2/keys/registry/secrets. При отсутствии EncryptionConfiguration
  секреты в etcd лежат открытым текстом — любой доступ к диску/порту 2379
  равносилен компрометации.
references:
  - https://attack.mitre.org/techniques/T1552/007/
  - https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/
logsource:
  product: kubernetes
  service: audit
  definition: 'Kubernetes Audit Log + access-лог etcd'
detection:
  api_secrets_list:
    verb:
      - list
      - watch
    objectRef_resource: secrets
  api_secret_get:
    verb: get
    objectRef_resource: secrets
  etcd_direct:
    requestURI|contains:
      - '/v2/keys/registry/secrets'
      - '/v3/kv/range'
  filter_controller:
    user_username|startswith: 'system:kube-'
  condition: (api_secrets_list or api_secret_get or etcd_direct) and not filter_controller
fields:
  - user_username
  - verb
  - objectRef_namespace
  - objectRef_name
  - requestURI
falsepositives:
  - контроллеры и операторы, легитимно читающие свои секреты — отфильтрованы
    по system:kube-*; дополните список своими сервисными аккаунтами-контроллерами
level: high
tags:
  - attack.credential_access
  - attack.t1552.007
  - cwe.311
```
