---
id: lfi-double-encoding-bypass
title: "LFI: двойное URL-кодирование и обход нормализации"
type: lfi
target: generic
category: web
difficulty: intermediate
bypass: waf
tags: [lfi, encoding, waf-bypass]
tested_on: ["PHP + Apache", "IIS", "Tomcat"]
success_rate: 0.45
risk: medium
cwe: "CWE-22"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Path_Traversal"
graph:
  - target: "lfi-rfi"
    type: instance_of
  - target: "waf-bypass"
    type: technique_of
---

# LFI: двойное URL-кодирование и обход нормализации

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
%252e%252e%252f%252e%252e%252fetc/passwd
```

## Explanation

Если приложение декодирует параметр дважды (или фильтр декодирует один раз,
а сервер — второй), то `%252e` превращается в `%2e`, а затем в `.`.
Так обходят проверку на `../`. Похожий класс проблем — различие нормализации
между WAF, веб-сервером и приложением: `..;/` (Tomcat), `.%2f`, `\..\`,
unicode-представления `%c0%ae%c0%ae/` (некорректный UTF-8, исторически IIS).

## Detection

Сравните ответы на `../`, `%2e%2e%2f`, `%252e%252e%252f`, `..;/`, `....//`.
Разное поведение = рассинхрон нормализации между компонентами.

## Remediation

- Декодировать один раз и в одном месте (никогда не «ещё раз» в приложении).
- Проверять путь ПОСЛЕ полной нормализации (`realpath`) и до открытия файла.
- Whitelist вместо blacklist.
- Единая версия веб-сервера/контейнера с исправленными багами нормализации.

## Variants

```
..%2f
```

```
%2e%2e/
```

```
....//
```

```
..;/
```

```
..%c0%af
```
