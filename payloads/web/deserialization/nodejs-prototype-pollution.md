---
id: deserialization-nodejs-prototype-pollution
title: "Node.js: prototype pollution как «десериализация» состояния"
type: deserialization
target: javascript
category: web
difficulty: advanced
bypass: none
tags: [prototype-pollution, nodejs, client-side, rce]
tested_on: ["Node 18/20", "lodash merge/defaultsDeep исторические", "jQuery extend"]
success_rate: 0.4
risk: high
cwe: "CWE-1321"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/prototype-pollution"
graph:
  - target: "deserialization"
    type: related_to
  - target: "client-side"
    type: category_of
  - target: "rce"
    type: leads_to
  - target: "auth-bypass"
    type: leads_to
---

# Node.js: prototype pollution как «десериализация» состояния

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"__proto__": {"isAdmin": true}}
```

## Explanation

В JavaScript объекты наследуют свойства от `Object.prototype`. Если код
рекурсивно копирует пользовательский JSON в объект (`lodash.merge`,
`Object.assign` с глубокой рекурсией, `qs`-парсер с `allowPrototypes`,
`jQuery.extend(true, …)`), ключ `__proto__` (или `constructor.prototype`)
позволяет **добавить свойство всем объектам** в процессе.

Последствия:

- обход проверок: `if (user.isAdmin)` становится истинным;
- загрязнение параметров запросов (`req.query` наследует ваши значения);
- client-side: изменение поведения фреймворка, XSS через загрязнённые атрибуты;
- server-side RCE: если загрязнённое значение попадает в `child_process.exec`
   (через опции вроде `shell`, `env`, `NODE_OPTIONS`) или в шаблонизатор;
- отказ обслуживания: бесконечные циклы, падение при обращении к загрязнённым полям.

Класс называют «десериализацией состояния», потому что механизм тот же:
недоверенные данные изменяют внутреннее представление объектов.

## Detection

1. Отправьте `{"__proto__": {"polluted": "HBMARK"}}` в JSON-теле и проверьте,
   появилось ли свойство в другом объекте (например, в ответе API или в `req.query`).
2. Варианты ключей: `__proto__`, `constructor.prototype`, `prototype`;
   варианты входа: JSON-тело, query-строка (`?__proto__[x]=1`), multipart,
   заголовки, загруженные конфиги.
3. Клиентская сторона: проверьте, принимает ли `JSON.parse`-результат
   участие в глубоком merge (Burp «Prototype Pollution»-расширение).
4. SAST/taint: рекурсивные merge-функции с внешними данными.
5. Признак в логах: `TypeError` на неожиданных свойствах, `isAdmin` у гостей.

## Remediation

- Не использовать рекурсивный merge с недоверенными данными;
  `Object.assign({}, defaults, input)` с явным whitelist полей.
- Заморозить прототип: `Object.freeze(Object.prototype)` (аккуратно:
  ломает часть библиотек) или `Object.create(null)` для словарей.
- Валидация схемы JSON (zod/ajv/joi) с запретом `__proto__`, `constructor`,
  `prototype`; `JSON.parse` с revoker'ом опасных ключей.
- Обновить lodash (≥4.17.12), jQuery (≥3.5), qs (с `allowPrototypes: false`),
  express-расширения.
- Не передавать пользовательские объекты в `child_process`, шаблонизаторы
  и `eval`-подобные API.
- `--disable-proto=throw` в Node для жёсткого запрета `__proto__`.

## Variants

```
{"constructor": {"prototype": {"isAdmin": true}}}
```

```
?__proto__[admin]=1
```

```
{"__proto__": {"shell": "/proc/self/exe", "NODE_OPTIONS": "--inspect"}}
```

## Detection rules

```yaml
title: Prototype pollution — __proto__/constructor.prototype в JSON и query
id: e5f6a7b8-0112-4e5f-9a7b-000000000112
status: experimental
description: >-
  Пользовательские данные содержат ключи __proto__ или constructor.prototype —
  попытка загрязнить Object.prototype (isAdmin=true, shell, NODE_OPTIONS).
  Встречается и в JSON-теле, и в query-параметрах (filter[__proto__][...]).
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/prototype-pollution
logsource:
  category: application
  definition: 'логи приложения с телом запроса + access-лог с query-строкой'
detection:
  selection_body:
    request_body|contains:
      - '"__proto__"'
      - '__proto__'
      - 'constructor":{"prototype"'
      - 'constructor": {"prototype"'
  selection_query:
    cs-uri-query|contains:
      - '__proto__'
      - 'constructor[prototype'
      - '%5f%5fproto%5f%5f'
  condition: selection_body or selection_query
fields:
  - source_ip
  - request_path
  - request_body
  - cs-uri-query
falsepositives:
  - JSON-схемы и конфиги, легитимно содержащие ключ __proto__ (крайне редко —
    сверяйте с кодом)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.1321
```
