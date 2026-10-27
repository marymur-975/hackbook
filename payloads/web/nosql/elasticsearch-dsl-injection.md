---
id: nosql-elasticsearch-dsl-injection
title: "Elasticsearch: инъекция в Query DSL и прямой доступ к API"
type: nosql
target: elasticsearch
category: web
difficulty: intermediate
bypass: none
tags: [nosql, elasticsearch, dsl, noauth]
tested_on: ["Elasticsearch 7.x (без X-Pack security)", "OpenSearch 2.x"]
success_rate: 0.5
risk: high
cwe: "CWE-943"
lab: null
last_verified: "2026-10-23"
graph:
  - target: "nosql"
    type: instance_of
  - target: "data-exfiltration"
    type: leads_to
  - target: "network"
    type: related_to
---

# Elasticsearch: инъекция в Query DSL и прямой доступ к API

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"query": {"match_all": {}}, "size": 10000}
```

## Explanation

Две разные проблемы, которые часто путают:

1. **Открытый API** (порт 9200 без X-Pack security / OpenSearch без auth):
   любой клиент читает все индексы через `_search`, `_cat/indices`, `_mapping`,
   а также **пишет** и удаляет (`_delete_by_query`, `_bulk`). Это не инъекция,
   а отсутствие аутентификации — но по последствиям сопоставимо с дампом БД.
2. **Инъекция в Query DSL**: приложение подставляет пользовательскую строку
   в JSON-запрос (поиск, фильтры, сортировка). Тогда можно расширить выборку
   (`match_all`), прочитать чужие индексы (`*`), изменить сортировку
   (script-based sort -> выполнение painless-скрипта) и вытащить поля,
   которые бэкенд не возвращает.

Painless-скрипты в `script_fields`/`script_score` позволяют читать `_source`
и выполнять арифметику — при открытом кластере это полный доступ к данным.

## Detection

1. `curl http://<host>:9200/` — вернул версию и имя кластера без учётки?
2. `curl http://<host>:9200/_cat/indices?v` — список индексов и размеры.
3. Для инъекции DSL: подставьте `"` в поисковую строку и посмотрите на ошибку
   парсинга JSON (`json_parse_exception`, `parsing_exception` с указанием позиции).
4. Попробуйте `*` в имени индекса и `match_all` в теле запроса.
5. В логах Elasticsearch: запросы к `_search` от анонимных клиентов,
   `_delete_by_query`, создание индексов.

## Remediation

- Включить X-Pack Security / OpenSearch Security: TLS, RBAC, API-ключи.
- `http.bind_host: 127.0.0.1` или доступ только из app-сегмента (SG/NetworkPolicy).
- Приложение ходит под ролью с доступом к конкретным индексам
  (`index_privileges: read` на `app-*`).
- Query DSL собирается из объектов, а не конкатенацией строк;
  пользовательский ввод — только в значения leaf-запросов.
- Запретить painless-скрипты из пользовательского ввода
  (`script.allowed_types: stored`, `script.allowed_contexts` ограничить).
- `action.destructive_requires_name: true`, snapshot-бэкапы.

## Variants

```
{"query": {"match_all": {}}, "_source": ["*"], "size": 1000}
```

```
{"sort": [{"_script": {"script": "doc[\"secret\"].value"}}]}
```

```
GET /_cat/indices?v
```

## Detection rules

```yaml
title: Elasticsearch — DSL-инъекция и открытые служебные эндпоинты
id: e5f6a7b8-0077-4e5f-9a7b-000000000077
status: experimental
description: >-
  Пользователь управляет JSON-запросом к ES: match_all с большим size,
  script_fields, wildcard. Отдельный риск — выставленные наружу /_search,
  /_cat/indices, /_aliases без аутентификации.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://attack.mitre.org/techniques/T1213/
logsource:
  category: webserver
  definition: 'access-лог + логи приложения с телом запроса к поиску'
detection:
  selection_body:
    request_body|contains:
      - '"match_all"'
      - '"size": 10000'
      - '"script_fields"'
      - '"script":'
      - '"wildcard"'
  selection_endpoint:
    cs-uri-stem|contains:
      - '/_search'
      - '/_cat/indices'
      - '/_cat/aliases'
      - '/_aliases'
      - '/_cluster/health'
      - '/_nodes'
  condition: selection_body or selection_endpoint
fields:
  - c-ip
  - cs-uri-stem
  - sc-status
  - request_body
falsepositives:
  - внутренние Kibana/мониторинг, легитимно опрашивающие _cluster/health
    (исключайте по c-ip)
level: medium
tags:
  - attack.collection
  - attack.t1190
  - attack.t1213
  - cwe.943
```
