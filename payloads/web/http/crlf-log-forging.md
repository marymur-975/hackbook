---
id: http-crlf-log-forging
title: "Лог-форжинг и инъекция в структурированные логи"
type: http
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [log-injection, crlf, siem, audit]
tested_on: ["nginx access log", "Java log4j-style appenders", "SIEM-парсеры"]
success_rate: 0.6
risk: medium
cwe: "CWE-117"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "headers"
    type: related_to
  - target: "log-injection"
    type: instance_of
  - target: "xss"
    type: leads_to
  - target: "rce"
    type: leads_to
    description: "Log4Shell: lookup в логируемом значении давал RCE"
---

# Лог-форжинг и инъекция в структурированные логи

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
GET / HTTP/1.1\r\nUser-Agent: legit\r\nX-Fake: 1.2.3.4 200 1234 "-" "admin SUCCESS"
```

## Explanation

Логи — это данные, которые кто-то позже парсит. Если пользовательское значение
(заголовок, параметр, имя пользователя, имя файла) попадает в лог без нормализации,
возможны:

- **подделка строк лога**: вставка CRLF создаёт «успешный вход admin с IP 1.2.3.4»,
  которого не было, — ломает расследование инцидента;
- **сокрытие следов**: затирание/смещение собственных записей;
- **инъекция в SIEM/CSV/JSON**: значения с `"`, `\n`, `}` ломают парсер
  и позволяют подменить поля (например, `severity`);
- **CSV-инъекция** при экспорте отчётов: `=cmd|'/c calc'!A1` выполняется в Excel;
- **XSS в веб-интерфейсе логов** (blind XSS у администратора);
- **вторичная инъекция**: лог читается скриптом, который подставляет значения
  в shell/SQL (log -> command injection).

Отдельный исторический класс — Log4Shell (CVE-2021-44228): lookup `${jndi:ldap://…}`
в логируемом значении приводил к RCE. Формально это RCE, но точка входа — именно лог.

## Detection

1. Отправьте запрос с уникальным маркером и CRLF в `User-Agent`/`Referer`/параметре.
2. Найдите маркер в логах веб-сервера, приложения, SIEM.
3. Проверьте: видны ли сырые CR/LF, создаётся ли новая «строка» лога,
   экранируются ли кавычки в JSON-логах.
4. Отдельно проверьте экспорт отчётов в CSV/XLSX на формулы (`=`, `+`, `-`, `@`).
5. Для Java-стека: версия log4j-core < 2.17 и включённые lookups = критично.

## Remediation

- Нормализация перед записью: удалять/экранировать CR, LF и управляющие символы,
  ограничивать длину поля.
- Структурированное логирование (JSON) через библиотеку, а не конкатенация строк;
  значения — как отдельные поля с экранированием.
- Веб-интерфейс логов: экранирование HTML + CSP (см. карточку
  `headers-user-agent-log-injection`).
- Экспорт в CSV: префикс `'` для ячеек, начинающихся с `= + - @`.
- Log4j ≥ 2.17.1, `log4j2.formatMsgNoLookups=true`, отключение JNDI-lookups.
- Логи — только для чтения приложением (отдельный пользователь, WORM-хранилище),
  целостность защищена подписью/хеш-цепочкой.

## Variants

```
%0d%0afake log line
```

```
admin\" OR 1=1--
```

```
=HYPERLINK("http://attacker.tld")
```

## Detection rules

```yaml
title: Log forging — CRLF внутри лог-записи приложения
id: e5f6a7b8-0082-4e5f-9a7b-000000000082
status: experimental
description: >-
  Поле message лог-события содержит переводы строк (CRLF) или их URL-кодировку
  (%0d%0a) — пользовательские данные попали в журнал неэкранированными и
  атакующий подделывает «успешные» записи (login SUCCESS user=admin).
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://owasp.org/www-community/attacks/Log_Injection
logsource:
  category: application
  definition: 'структурированные логи приложения: каждое событие — одна запись с полем message'
detection:
  selection:
    message|contains:
      - "\r\n"
      - "\n"
      - '%0d%0a'
      - '%0D%0A'
  condition: selection
fields:
  - source_ip
  - event_action
  - message
falsepositives:
  - легитимные многострочные сообщения (stack trace) — исключайте event_action
    с отладочными трейсами по месту сбора
level: medium
tags:
  - attack.defense_evasion
  - attack.t1190
  - cwe.117
```
