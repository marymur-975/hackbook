---
title: "Атаки на Kubernetes"
chapter: 6.1
difficulty: advanced
tags: [kubernetes, k8s, cloud, rbac]
---

# Атаки на Kubernetes

## Анонимный доступ к API

Неправильно настроенный API-сервер Kubernetes может разрешать анонимные запросы. Это позволяет злоумышленнику перечислить поды, секреты и даже выполнить команды в контейнерах:

{{ include "payloads/cloud/kubernetes-anonymous-api.md" }}

## Кража токена ServiceAccount

Если злоумышленник получил доступ внутрь пода, он может прочитать токен ServiceAccount (обычно лежит в `/var/run/secrets/kubernetes.io/serviceaccount/token`) и использовать его для эскалации привилегий:

{{ include "payloads/cloud/kubernetes-pod-sa-token.md" }}

## Эскалация через RBAC

Даже с обычным токеном ServiceAccount можно получить роль `cluster-admin`, если в кластере разрешено создание `ClusterRoleBinding`:

{{ include "payloads/container/k8s-rbac-escape.md" }}
