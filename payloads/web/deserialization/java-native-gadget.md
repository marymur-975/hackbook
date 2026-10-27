---
id: deserialization-java-native-gadget
title: "Java: небезопасная десериализация и gadget-цепочки"
type: deserialization
target: java
category: web
difficulty: expert
bypass: none
tags: [deserialization, java, gadget-chain, rce]
tested_on: ["Java 8/11 + commons-collections на classpath", "ObjectInputStream"]
success_rate: 0.3
risk: critical
cwe: "CWE-502"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/deserialization"
  - "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
graph:
  - target: "deserialization"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "file-upload"
    type: related_to
---

# Java: небезопасная десериализация и gadget-цепочки

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA…   # base64 сериализованного объекта (magic AC ED 00 05)
```

## Explanation

`ObjectInputStream.readObject()` восстанавливает объект из потока и при этом
**вызывает его методы** (`readObject`, `readResolve`, `hashCode`, `equals`,
`compareTo`, финализаторы). Если на classpath есть библиотека с «полезной»
реализацией этих методов (commons-collections `InvokerTransformer`,
Spring, Groovy, BeanUtils, JNDI-обвязки), цепочка вызовов приводит
к выполнению произвольного кода — это и есть gadget chain.

Точки входа: cookie `rememberMe`/`session`, заголовки (`X-Serialized`),
поля JSON/XML, загруженные файлы, JMS/RMI-сообщения, параметры Vaadin/JSF
(ViewState), кеш-сериализация.

Признаки Java-сериализации в трафике: байты `AC ED 00 05` (hex) или
`rO0AB…` (base64), префиксы в cookie, длинные base64-значения в скрытых полях.

Готовые цепочки эксплуатации (ysoserial-гаджеты, шеллкод, обфускация) в проекте
не публикуются: карточка описывает **механизм**, признаки и способы защиты.
Для практики используйте лабораторию с известным уязвимым приложением и
публичный инструментарий в изолированной сети.

## Detection

1. Ищите в трафике `AC ED 00 05` / `rO0AB`, `ViewState`, `JSESSIONID`-подобные
   поля с длинным base64.
2. Отправьте заведомо повреждённый сериализованный объект: ошибка
   `StreamCorruptedException`, `InvalidClassException`, `ClassNotFoundException`
   в ответе/логе подтверждает десериализацию.
3. Безопасное подтверждение эксплуатации: gadget, который делает DNS-запрос
   на ваш collaborator (URLDNS-цепочка не выполняет код, только резолвит имя) —
   стандартная диагностика.
4. Инвентаризация зависимостей: commons-collections 3.x, commons-beanutils,
   groovy, spring-core старых версий на classpath.
5. В логах: стектрейсы `ObjectInputStream.readObject`, `Transformer`,
   `Proxy`, неожиданные JNDI-запросы.

## Remediation

- Не десериализовать данные из недоверенных источников — главное правило.
- Перейти на текстовые форматы с явной схемой (JSON + Jackson с
  `activateDefaultTyping` выключен, protobuf).
- Если Java-сериализация неизбежна: `ObjectInputFilter` (JEP 290) с whitelist
  классов, `ValidatingObjectInputStream` (Apache Commons IO).
- Подписывать данные (HMAC/JWS) и проверять подпись до десериализации;
  ключ — не в приложении.
- Убрать с classpath известные gadget-библиотеки или обновить их
  (commons-collections ≥ 3.2.2 с отключённым `InvokerTransformer`).
- RASP/SCA в CI (Dependency-Track, OWASP dependency-check, Snyk).
- SecurityManager-подобные ограничения устарели — полагайтесь на sandbox
  процесса и минимальные права.

## Variants

```
ViewState (JSF/ASP.NET-подобные)
```

```
rememberMe cookie (Shiro)
```

```
RMI/JMX-эндпоинты
```

```
XStream XML
```

## Detection rules

```yaml
title: Java-десериализация — нативный поток (rO0AB/aced0005) во входящих данных
id: e5f6a7b8-0111-4e5f-9a7b-000000000111
status: experimental
description: >-
  Тело запроса начинается с сигнатуры Java-сериализации AC ED 00 05 — в base64
  (rO0AB) или hex (aced0005). Подтверждение эксплуатации: срабатывание
  JEP 290 deserialization filter (InvalidClassException: filter status).
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://www.oracle.com/java/technologies/javase/serializationfiltering.html
logsource:
  category: application
  definition: 'логи приложения/WAF с телом запроса и stack trace ошибок'
detection:
  selection_body:
    request_body|contains:
      - 'rO0AB'
      - 'aced0005'
      - 'ACED0005'
      - 'AC ED 00 05'
  selection_error:
    error_message|contains:
      - 'InvalidClassException'
      - 'filter status: REJECTED'
      - 'ObjectInputStream'
      - 'StreamCorruptedException'
  condition: selection_body or selection_error
fields:
  - source_ip
  - request_path
  - request_content_type
  - error_message
falsepositives:
  - легитимный RMI/JMX-трафик между своими сервисами (внутренние каналы —
    исключайте по source_ip, но мигрируйте на JSON/protobuf)
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.502
```
