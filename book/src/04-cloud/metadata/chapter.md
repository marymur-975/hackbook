---
title: "Облачные метаданные и SSRF"
chapter: 4.1
difficulty: intermediate
tags: [cloud, aws, gcp, ssrf]
---

# Облачные метаданные и SSRF

## AWS IMDSv1

Самый частый вектор атаки в облаке — это доступ к сервису метаданных (IMDS) через SSRF. Если инстанс использует IMDSv1, временные ключи роли можно получить без токена:

{{ include "payloads/cloud/aws-imdsv1-role-credentials.md" }}

## GCP Metadata

В Google Cloud аналогичный сервис доступен по адресу `metadata.google.internal`. Токен сервисного аккаунта можно получить обычным GET-запросом:

{{ include "payloads/cloud/gcp-metadata-token.md" }}

## Azure Managed Identity

В Azure через IMDS можно получить токен управляемой идентичности (Managed Identity):

{{ include "payloads/cloud/azure-imds-managed-identity.md" }}
