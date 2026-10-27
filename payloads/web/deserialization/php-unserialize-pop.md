---
id: deserialization-php-unserialize-pop
title: "PHP: unserialize() и POP-цепочки"
type: deserialization
target: php
category: web
difficulty: advanced
bypass: none
tags: [deserialization, php, pop-chain, rce]
tested_on: ["PHP 7.4/8.x с уязвимыми классами приложения"]
success_rate: 0.35
risk: critical
cwe: "CWE-502"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"
graph:
  - target: "deserialization"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "privilege-escalation"
    type: leads_to
    description: "Подделка роли в сериализованном cookie без RCE"
---

# PHP: unserialize() и POP-цепочки

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
O:4:"User":2:{s:4:"role";s:5:"admin";s:2:"id";i:1;}
```

## Explanation

`unserialize()` восстанавливает объект и вызывает магические методы
при уничтожении/использовании: `__wakeup`, `__destruct`, `__toString`,
`__call`, `__get`, `__set`. Если в приложении (или в подключённой библиотеке)
есть класс, чей магический метод делает что-то опасное (пишет файл,
выполняет `system()`, удаляет данные, делает SQL-запрос), цепочка таких
классов (POP-chain) даёт выполнение кода.

Отдельный подкласс — **подделка состояния объекта**: если приложение хранит
в сериализованном cookie роль/права/баланс (`O:4:"User":…{s:4:"role";s:5:"admin";}`),
достаточно изменить поле — RCE не требуется, чтобы повысить привилегии.

Признаки: cookie/параметры, начинающиеся с `O:`, `a:`, `s:`, `b:`, `i:`,
в base64 — `Tz…`, `YTo…`. Формат PHP-сериализации легко читается и правится вручную.

Готовые цепочки эксплуатации (ysoserial-гаджеты, шеллкод, обфускация) в проекте
не публикуются: карточка описывает **механизм**, признаки и способы защиты.
Для практики используйте лабораторию с известным уязвимым приложением и
публичный инструментарий в изолированной сети.

## Detection

1. Найдите значения вида `O:<len>:"<Class>":<n>:{...}` (или base64 `Tzo`).
2. Измените поле (например, `role`) и посмотрите, применилось ли изменение —
   это уже критическая находка без всякого RCE.
3. Отправьте синтаксически неверную строку: warning `unserialize(): Error at offset…`
   в ответе/логе подтверждает точку входа.
4. Поиск gadget'ов в коде приложения: `__destruct`, `__wakeup`, `__toString`
   с файловыми/командными операциями (phpggc — публичная база цепочек).
5. В логах: `unserialize()` с пользовательскими данными, PHP warnings.

## Remediation

- Не использовать `unserialize()` для пользовательских данных; заменить на
  `json_decode()` с валидацией схемы.
- Если сериализация нужна — подписывать данные (HMAC) и проверять подпись,
  использовать `unserialize($data, ['allowed_classes' => false])`
  или конкретный whitelist классов.
- Не хранить привилегии/баланс/идентификаторы в клиентских cookie;
  состояние — на сервере (сессия, БД).
- Статический анализ (Psalm/PHPStan с правилами taint, RIPS) на `unserialize`.
- Удалить/обновить библиотеки с известными POP-цепочками (Laravel, Monolog,
  WordPress-плагины старых версий).

## Variants

```
a:1:{i:0;O:…}
```

```
base64: Tzo0OiJVc2VyIj…
```

```
C:11:"ArrayObject":… (Serializable)
```

## Detection rules

```yaml
title: PHP-десериализация — сериализованные объекты (O:N:) во входящих данных
id: e5f6a7b8-0113-4e5f-9a7b-000000000113
status: experimental
description: >-
  В параметрах/cookie встречается PHP-сериализация (O:4:"User":2:{...}) или
  её base64-форма, а приложение логирует ошибки unserialize() — признак POP-
  атаки через магические методы (__wakeup/__destruct).
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://www.php.net/manual/ru/function.unserialize.php
logsource:
  category: application
  definition: 'логи приложения с телом запроса, cookie и ошибками unserialize'
detection:
  selection_body:
    request_body|contains:
      - 'O:4:"'
      - 'O:8:"'
      - 's:4:"role"'
      - 'a:2:{'
      - '__wakeup'
  selection_error:
    error_message|contains:
      - 'unserialize()'
      - 'Uncaught Exception: Serialization'
      - '__destruct'
  condition: selection_body or selection_error
fields:
  - source_ip
  - request_path
  - request_body
  - error_message
falsepositives:
  - WordPress-плагины, передающие сериализованные массивы в своих AJAX-ручках
    (исключайте известные эндпоинты по request_path)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.502
```
