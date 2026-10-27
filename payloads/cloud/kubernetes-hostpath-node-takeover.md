---
id: cloud-kubernetes-hostpath-node-takeover
title: "Kubernetes: hostPath, privileged и cgroup release_agent — выход на узел"
type: cloud
target: kubernetes
category: cloud
difficulty: advanced
bypass: none
tags: [kubernetes, container-escape, hostpath, privileged, cgroup]
tested_on: ["k8s 1.27 (kind)", "containerd/runc", " privileged pod + hostPID"]
success_rate: 0.6
risk: critical
cwe: "CWE-250"
lab: null
last_verified: "2026-10-23"
references:
  - "https://kubernetes.io/docs/concepts/security/"
  - "https://hackingthe.cloud/"
graph:
  - target: "container-escape"
    type: instance_of
  - target: "privilege-escalation"
    type: leads_to
  - target: "cloud"
    type: related_to
  - target: "rce"
    type: leads_to
---

# Kubernetes: hostPath, privileged и cgroup release_agent — выход на узел

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# признаки «опасного» пода (аудит, не эксплуатация)
kubectl get pods -A -o json | jq -r '
  .items[] | select(
    (.spec.containers[]?.securityContext?.privileged == true) or
    (.spec.containers[]?.securityContext?.capabilities?.add // [] | index("SYS_ADMIN")) or
    (.spec.volumes[]?.hostPath != null) or
    (.spec.hostPID == true) or (.spec.hostNetwork == true)
  ) | "\(.metadata.namespace)/\(.metadata.name)"'
```

## Explanation

Контейнер — это не граница безопасности по умолчанию. Стандартные пути на узел:

1. **`hostPath: /`** (или `/etc`, `/var/lib/kubelet`, `/var/run/docker.sock`)
   -> чтение и запись файлов узла, включая `authorized_keys`, kubeconfig,
   секреты других подов (`/var/lib/kubelet/pods/*/volumes`), systemd-юниты.
2. **`privileged: true`** или `CAP_SYS_ADMIN` -> монтирование ФС узла,
   доступ к устройствам (`/dev/sda1`), cgroup-манипуляции.
3. **cgroup `release_agent`** (классический escape без сокета): создать
   cgroup, записать путь к агенту на ФС узла, вызвать уведомление —
   команда выполнится от имени узла.
4. **`hostPID: true` + `CAP_SYS_PTRACE`** -> внедрение в процессы узла,
   чтение памяти kubelet/контейнер-рантайма.
5. **`hostNetwork: true`** -> доступ к loopback-сервисам узла
   (kubelet 10250, etcd, метрики, IMDS в облаке).
6. **`/var/run/docker.sock` или `containerd.sock`** -> создание контейнера
   с монтированием корня узла (см. `cloud-docker-socket-escape`).
7. **Уязвимости рантайма/ядра**: runc CVE (например, перезапись бинарника runc),
   DirtyPipe/DirtyCOW, gVisor-обходы.

Выход на узел обычно означает доступ к **kubelet-учётным данным** и токенам
всех подов этого узла, а далее — к кластеру.

## Detection

1. Аудит спецификаций: `privileged`, `hostPath`, `hostPID/hostNetwork/hostIPC`,
   `capabilities.add` (`SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`),
   `securityContext` пустой, `runAsUser: 0`.
   Инструменты: `kubescape`, `kube-bench`, `trivy config`, `polaris`.
2. Admission-логи: попытки создать под с запрещёнными полями
   (если политика есть — они должны блокироваться).
3. Audit-лог кластера: создание pods/daemonsets с `hostPath` от
   неожиданных SA; изменения PodSecurityPolicy/PSA-меток namespace.
4. На узле: процессы контейнеров с монтированием `/`, появление новых
   cgroup с `release_agent`, обращения к `/var/run/*.sock` из контейнера.
5. Falco/Tetragon-правила: `Launch Privileged Container`,
   `Mount Launched in Container`, `Contact K8S API Server From Container`,
   `Write below root`.
6. Runtime-аномалии: дочерние процессы контейнера, обращающиеся к
   `/proc/1/root`, `nsenter`, `chroot /host`.

## Remediation

- Pod Security Admission в режиме `restricted` на все namespaces
  (запрещает privileged, hostPath, опасные capabilities, требует runAsNonRoot).
- Kyverno/OPA: политики запрета `hostPath`, `privileged`, `hostPID/Network`,
  монтирования docker.sock; исключение — только для системных компонентов
  с отдельным namespace и ревью.
- `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
  `capabilities: drop: [ALL]` + точечное добавление.
- Seccomp `RuntimeDefault` (или строже), AppArmor/SELinux профили.
- User namespaces (rootless containerd/CRI-O, `userns-remap`),
  gVisor/Kata для недоверенных workload'ов.
- Не монтировать сокеты рантайма; для сборки образов — kaniko/buildkit
  без привилегий или отдельный билд-кластер.
- NetworkPolicy deny-all + egress-ограничения; узлы без доступа в интернет.
- Runtime-защита (Falco/Tetragon) с алертами на escape-поведение.
- Своевременные обновления ядра и рантайма (runc/containerd).

## Detection rules

```yaml
title: Privileged-под с hostPath / — захват узла через монтирование корня
id: f6a7b8c9-0004-4f6a-8b9c-000000000004
status: experimental
description: >-
  В spec создаваемого пода встречаются securityContext.privileged=true,
  hostPath с path "/" или монтирование /host — из такого контейнера узел
  берётся за секунды (chroot /host, запись в /etc, кража kubelet-сертификатов).
references:
  - https://attack.mitre.org/techniques/T1610/
  - https://kubernetes.io/docs/concepts/security/pod-security-standards/
logsource:
  product: kubernetes
  service: audit
  definition: 'Kubernetes Audit Log с requestObject (policy-уровень Request)'
detection:
  pod_create:
    verb: create
    objectRef_resource:
      - pods
      - deployments
      - daemonsets
      - statefulsets
  dangerous_spec:
    requestObject|contains:
      - '"hostPath"'
      - '"privileged":true'
      - '"path":"/"'
      - 'mountPath":"/host'
      - 'hostPID":true'
      - 'hostNetwork":true'
  condition: pod_create and dangerous_spec
fields:
  - user_username
  - objectRef_namespace
  - objectRef_name
  - requestObject
falsepositives:
  - инфраструктурные агенты (мониторинг узлов, CNI, CSI) — ведите allowlist
    неймспейсов и Pod Security Admission вместо исключений в правиле
level: critical
tags:
  - attack.privilege_escalation
  - attack.t1610
  - cwe.250
```
