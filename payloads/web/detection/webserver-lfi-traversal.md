---
id: detection-webserver-lfi-traversal
title: "Детект path traversal и LFI по access-логам"
type: lfi
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [detection, sigma, lfi, path-traversal, webserver-logs]
tested_on: ["nginx/Apache access log", "vuln-hub /read", "фикстуры detections/tests"]
success_rate: 0.75
risk: low
cwe: "CWE-22"
lab: "labs/web-labs/vuln-hub"
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
---

# Детект path traversal и LFI по access-логам

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# воспроизведение (локальная лаборатория)
python3 tools/lib/http_fetch.py "http://localhost:8090/read?file=../../../../etc/passwd" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/read?file=%2e%2e%2f%2e%2e%2fetc/passwd" 6 GET
```

## Explanation

Traversal оставляет в логе узнаваемый след, но в трёх формах, и правило
должно покрывать все:

1. **литерал**: `../`, `..\`, `./../`;
2. **одинарное кодирование**: `%2e%2e%2f`, `%2e%2e/`, `..%2f`, `%2e%2e%5c`;
3. **двойное кодирование**: `%252e%252e%252f` (когда приложение декодирует дважды);
4. **альтернативные разделители**: `..;/` (Tomcat), `..%c0%af` (некорректный UTF-8),
    `%uff0e%uff0e%u2215`, `....//` (после вырезания `../` фильтром).

Дополнительный сильный признак — целевые пути в параметре:
`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `/proc/self/fd/`,
`/var/log/apache2/access.log`, `win.ini`, `boot.ini`, `web.config`,
`php://filter`, `php://input`, `data://`, `file://`.

Ложные срабатывания редки: легитимные приложения почти никогда не принимают
`../` в параметрах. Поэтому правило можно делать строгим и высоким по уровню.

Правила рассчитаны на access-лог в ECS/W3C-подобных полях (`cs-uri-stem`, `cs-uri-query`, `sc-status`, `c-ip`, `cs-user-agent`). В своём SIEM замените имена полей на фактические — логика не изменится.

## Detection

```bash
python tools/rules-tester.py --rule traversal --verbose
```

В живых логах дополнительно ищите: запросы к `/read`, `/download`, `/file`,
`/view`, `/include` с параметрами `file`, `path`, `page`, `doc`, `template`;
статусы 200 при обращении к системным путям (признак успешного чтения);
последовательности запросов с увеличивающейся глубиной `../` (подбор уровня).

## Remediation

- Whitelist имён файлов вместо путей; нормализация (`realpath`) и проверка
  префикса разрешённого каталога.
- Декодировать один раз и в одном месте (см. `lfi-double-encoding-bypass`).
- Логировать полную query-строку и нормализованный путь, который приложение
  реально открыло: расхождение — готовый индикатор атаки.
- WAF-правила на все четыре формы кодирования; не полагаться только на WAF.
- `open_basedir`/chroot/контейнер: минимизация доступных путей.
- Алерт на любое совпадение правила: FP здесь редки, а событие критично.


## Detection rules

```yaml
title: Path traversal / LFI в параметрах запроса
id: b2c3d4e5-0002-4b2c-8d3e-000000000102
status: stable
description: >-
  Последовательности ../ в литеральном, одно- и двойном URL-кодировании, а также
  обращения к системным файлам и stream wrappers в параметрах запроса.
references:
  - https://attack.mitre.org/techniques/T1083/
  - payloads/web/lfi-rfi/traversal-etc-passwd.md
logsource:
  category: webserver
  definition: 'access-лог с полной query-строкой'
detection:
  traversal:
    cs-uri-query|contains:
      - '../'
      - '..\'
      - '%2e%2e%2f'
      - '%2e%2e/'
      - '..%2f'
      - '%252e%252e'
      - '..;/'
      - '....//'
      - '%c0%ae%c0%ae'
      - '%uff0e%uff0e'
  system_files:
    cs-uri-query|contains:
      - '/etc/passwd'
      - '/etc/shadow'
      - '/proc/self/'
      - '/var/log/'
      - 'win.ini'
      - 'boot.ini'
      - 'web.config'
      - 'php://filter'
      - 'php://input'
      - 'data://'
      - 'file:///'
  condition: traversal or system_files
fields:
  - c-ip
  - cs-uri-stem
  - cs-uri-query
  - sc-status
falsepositives:
  - редкие легитимные ссылки с ../ в query (проверьте свои приложения и вынесите в исключения)
level: high
tags:
  - attack.initial_access
  - attack.t1083
  - cwe.22
```
