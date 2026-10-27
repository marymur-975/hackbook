---
id: ldap-anonymous-bind
title: "LDAP: anonymous bind и перечисление каталога"
type: network
target: ldap
category: network
difficulty: beginner
bypass: auth
tags: [ldap, active-directory, enumeration, anonymous]
tested_on: ["OpenLDAP 2.5", "Windows Server 2019 AD LDS"]
success_rate: 0.5
risk: medium
cwe: "CWE-287"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0007/"
graph:
  - target: "network"
    type: instance_of
  - target: "active-directory"
    type: related_to
  - target: "enumeration"
    type: leads_to
---

# LDAP: anonymous bind и перечисление каталога

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
ldapsearch -x -H ldap://10.10.10.5 -b "DC=lab,DC=local" -s sub "(objectclass=*)"
```

## Explanation

Анонимное подключение к LDAP позволяет читать часть каталога без учётных данных.
В Active Directory анонимный доступ по умолчанию ограничен, но часто включён
на прикладных каталогах (OpenLDAP, AD LDS, GitLab/Nextcloud-интеграции) или
разрешён для конкретного base DN. Что можно получить: структуру OU, имена пользователей
и групп, `memberOf`, описания, иногда `userPassword` в открытом виде (устаревшие схемы).
`-x` — simple bind, `-s sub` — поиск по поддереву.

## Detection

1. `nmap -p 389,636 --script ldap-search,ldap-rootdse <host>`.
2. `ldapsearch -x -H ldap://<host> -s base -b '' '+'` — reading RootDSE без учётки.
3. Признак: ответ с атрибутами вместо `operations error` / `Inappropriate authentication`.
4. Проверьте и LDAPS (636), и глобальный каталог (3268/3269).

## Remediation

- Отключить anonymous bind (`olcDisallowed: bind_anon` в OpenLDAP, запрет в AD).
- Требовать TLS (LDAPS/StartTLS) и отклонять простой bind в открытом виде.
- Минимальные права на чтение каталога: RBAC по OU, никаких «всем всё».
- Аудит LDAP-запросов (Windows: event 2889 — незащищённые bind'ы).
- Не хранить секреты в атрибутах каталога.

## Variants

```
ldapsearch -x -H ldap://10.10.10.5 -s base -b '' '+' '*'
```

```
ldapsearch -x -H ldap://10.10.10.5 -b '' '(objectClass=*)' namingContexts
```

## Detection rules

```yaml
title: LDAP anonymous bind и перечисление каталога без аутентификации
id: a7b8c9d0-0003-4a7b-9c8d-000000000003
status: experimental
description: >-
  BIND с пустым dn (anonymous) в журнале slapd/OpenLDAP, за которым обычно
  следует SRCH по всему дереву с filter=(objectclass=*). На AD-стороне
  аналог — событие 2889 (unsigned/anonymous binds).
references:
  - https://attack.mitre.org/techniques/T1087/
logsource:
  product: linux
  service: ldap
  definition: 'журнал slapd (loglevel 256 stats) или AD LDAP-диагностика (event 2889)'
detection:
  anonymous_bind:
    service: slapd
    message|contains:
      - 'BIND dn=""'
      - '(anonymous)'
      - 'ANONYMOUS'
  full_tree_search:
    service: slapd
    message|contains:
      - 'filter="(objectclass=*)"'
      - 'scope=2 filter'
  condition: anonymous_bind or full_tree_search
fields:
  - source_ip
  - message
falsepositives:
  - health-check'и балансировщиков, читающие rootDSE анонимно (одиночные
    запросы без SRCH по дереву)
level: high
tags:
  - attack.discovery
  - attack.t1087
  - cwe.306
```
