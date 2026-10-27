---
id: detection-xxe-doctype-in-request
title: "Детект XXE: DOCTYPE и внешние сущности во входящем XML"
type: xxe
target: xml
category: web
difficulty: beginner
bypass: none
tags: [detection, sigma, xxe, xml, waf-logs]
tested_on: ["application logs", "WAF logs", "vuln-hub /lookup"]
success_rate: 0.8
risk: low
cwe: "CWE-611"
lab: "labs/web-labs/vuln-hub"
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
---

# Детект XXE: DOCTYPE и внешние сущности во входящем XML

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# воспроизведение (локальная лаборатория)
python3 tools/lib/http_fetch.py http://localhost:8090/lookup 6 POST \
  '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><root>&x;</root>'
```

## Explanation

XXE — один из самых «дёшево детектируемых» классов: легитимный XML
в современных API практически никогда не содержит `<!DOCTYPE`.
Наличие DOCTYPE во входящем документе уже является аномалией, а комбинация
с `SYSTEM`/`PUBLIC` и ссылками на `file://`, `http://`, `php://`, `jar://`,
`netdoc://` — почти гарантированная атака.

Где смотреть:

* тело запроса (если логируется) или WAF-логи;
* загружаемые файлы: SVG, DOCX/XLSX/PPTX (это ZIP с XML внутри),
   XML-импорты конфигурации, SOAP;
* ошибки парсера в логах приложения: `external entity`, `failed to load
   external entity`, `URI malformed`, `DOCTYPE is not allowed` —
   последняя означает, что защита сработала, но попытка была;
* исходящие соединения от сервера приложений к внешним `.dtd`
   (blind XXE / OOB-эксфильтрация).

Важно: детект по DOCTYPE ловит и попытки, и успешные атаки, поэтому
правило можно держать на уровне `high` с минимальным тюнингом.

## Detection

Проверка на фикстурах не требуется (правило тривиальное), но обязательно
проверьте его на трафике лаборатории:

```bash
python3 tools/lib/http_fetch.py http://localhost:8090/lookup 6 POST '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
python3 tools/lib/http_fetch.py http://localhost:8090/logs
```

Дополнительно мониторьте исходящие DNS/HTTP-запросы от сервера приложений
к доменам, которых нет в whitelist — это признак успешного blind XXE.

## Remediation

- Отключить DTD и внешние сущности в парсере (единственная настоящая защита;
  настройки по языкам — в карточках `payloads/web/xxe/`).
- Отклонять на gateway любой входящий XML с `<!DOCTYPE` (если DTD не нужен
  бизнес-логике).
- Валидация по XSD/JSON Schema вместо DTD.
- Egress-фильтрация для серверов приложений: блокирует OOB-эксфильтрацию.
- Для загружаемых Office/SVG: распаковка и санитизация XML в изолированном
  воркере.
- Логировать факт отклонения DOCTYPE: это индикатор разведки, даже если
  атака не удалась.


## Detection rules

```yaml
title: Входящий XML с DOCTYPE или внешней сущностью (XXE-попытка)
id: b2c3d4e5-0005-4b2c-8d3e-000000000105
status: stable
description: >-
  Тело запроса или загружаемый XML-документ содержит объявление DOCTYPE,
  ENTITY SYSTEM/PUBLIC либо ссылки на file://, php://, jar://, netdoc://.
references:
  - https://attack.mitre.org/techniques/T1190/
  - payloads/web/xxe/basic-external-entity.md
logsource:
  category: application
  product: xml_parser
  definition: 'логи WAF или приложения, содержащие тело запроса/ошибки парсера'
detection:
  doctype:
    request_body|contains:
      - '<!DOCTYPE'
      - '<!ENTITY'
      - 'SYSTEM "'
      - 'PUBLIC "'
  external_scheme:
    request_body|contains:
      - 'file:///'
      - 'php://'
      - 'jar://'
      - 'netdoc://'
      - 'gopher://'
      - 'http://169.254.169.254'
  parser_error:
    error_message|contains:
      - 'external entity'
      - 'failed to load external entity'
      - 'DOCTYPE is not allowed'
      - 'URI malformed'
      - 'EntityDeclHandler'
  condition: doctype or external_scheme or parser_error
fields:
  - source_ip
  - request_path
  - request_content_type
  - error_message
falsepositives:
  - легитимные XML-импорты с DTD (редко; зафиксируйте список эндпоинтов)
  - внутренние SOAP-сервисы со схемами, использующими сущности
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.611
```
