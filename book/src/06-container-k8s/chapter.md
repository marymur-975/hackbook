---
title: "Контейнеры и Kubernetes: Атаки и защита"
chapter: 6
difficulty: intermediate
tags: [container, k8s, cloud]
prerequisites: ["Linux Basics", "Network Basics"]
related_payloads: ["payloads/container/k8s-rbac-escape.md"]
lab: "labs/container-labs"
---

# Контейнеры и Kubernetes

## Теория

Контейнеры (Docker) и оркестраторы (Kubernetes) стали стандартом де-факто для развертывания приложений. Однако неправильная настройка RBAC, манифестов и доступов к Docker-сокету часто приводит к полному захвату кластера.

Основные проблемы безопасности в K8s:

- Слишком широкие права у ServiceAccount (например, `cluster-admin` по умолчанию).
- Возможность монтирования `hostPath` (доступ к файловой системе хоста).
- Запуск контейнеров с флагом `--privileged`.

## Векторы атак

В этой главе мы рассмотрим базовый сценарий: получение доступа к поду и попытку выхода за его пределы (Container Escape), а также эскалацию привилегий через неправильно настроенный RBAC.

Ниже приведена карточка с конкретным payload'ом для проверки прав и создания опасной привязки ролей:

{{ include "payloads/container/k8s-rbac-escape.md" }}

## Защита

Для защиты необходимо:

1. Использовать **Pod Security Standards (PSS)** для ограничения возможностей подов.
2. Ограничивать монтирование `hostPath` и запрещать запуск привилегированных контейнеров.
3. Применять принцип наименьших привилегий (Least Privilege) для всех ServiceAccount.
4. Включить аудит логов Kubernetes (Audit Logging) и мониторить подозрительные события (например, создание `ClusterRoleBinding`).
