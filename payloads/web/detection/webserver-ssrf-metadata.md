---
id: detection-webserver-ssrf-metadata
title: "Детект SSRF: обращения к метаданным и внутренним адресам"
type: ssrf
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [detection, sigma, ssrf, imds, proxy-logs]
tested_on: ["application logs", "egress proxy logs", "VPC Flow Logs"]
success_rate: 0.7
risk: low
cwe: "CWE-918"
lab: "labs/web-labs/vuln-hub"
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
---

# Детект SSRF: обращения к метаданным и внутренним адресам

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# воспроизведение (локальная лаборатория)
python3 tools/lib/http_fetch.py "http://localhost:8090/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/fetch?url=file%3A%2F%2F%2Fetc%2Fhostname" 6 GET
```

## Explanation

SSRF детектируется в двух местах, и оба нужны:

**1. Логи приложения / access-лог.** В параметре URL появляются:
   `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`,
   `169.254.170.2` (ECS task metadata), `127.0.0.1`, `localhost`, `[::1]`,
   `0.0.0.0`, RFC1918-адреса, `2130706433`/`0x7f000001`/`127.1`,
   `*.nip.io`, `localtest.me`, схемы `file://`, `gopher://`, `dict://`,
   `ftp://`, `ldap://`.

**2. Сетевые логи (egress proxy, VPC Flow Logs, DNS).** Даже если приложение
   не логирует параметр, исходящее соединение к link-local или внутреннему
   сервису от веб-хоста — аномалия. Особенно ценно: запрос веб-сервера
   к `169.254.169.254` и DNS-запросы к новым внешним доменам (OOB-канал).

Отдельный признак — **последовательность**: сначала запрос к вашему
контролируемому хосту (разведка), затем к внутренним адресам
(сканирование сети изнутри).

Правила рассчитаны на access-лог в ECS/W3C-подобных полях (`cs-uri-stem`, `cs-uri-query`, `sc-status`, `c-ip`, `cs-user-agent`). В своём SIEM замените имена полей на фактические — логика не изменится.

## Detection

```bash
python tools/rules-tester.py --rule ssrf --verbose
```

В облаке: CloudTrail/VPC Flow Logs на обращения к 169.254.169.254 от роли
инстанса с нетипичного ресурса; в Kubernetes — NetworkPolicy-логи и запросы
подов к metadata-сервису. В DNS-логах ищите всплеск NXDOMAIN и длинные
поддомены (OOB-эксфильтрация).

## Remediation

- Whitelist схем (`https` только) и доменов; резолв DNS до проверки
  и проверка всех IP (включая IPv6).
- Egress-фильтрация: веб-слой не ходит в link-local и RFC1918 без нужды;
  IMDSv2 + hop limit 1.
- Изолированный воркер для fetch-задач (отдельный namespace/VPC без доступа
  к внутренней сети).
- Логировать нормализованный URL и разрешённый IP: расхождение — индикатор
  rebinding.
- Алерт на любое правило: legit-поводов для запроса к метаданным из
  пользовательского параметра практически нет.


## Detection rules

```yaml
title: SSRF — обращение к метаданным или внутренним адресам через параметр URL
id: b2c3d4e5-0003-4b2c-8d3e-000000000103
status: test
description: >-
  В query-строке появляются link-local/loopback/приватные адреса, облачные
  metadata-эндпоинты или небезопасные URI-схемы.
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - payloads/web/ssrf/cloud-metadata-169254.md
logsource:
  category: webserver
  definition: 'access-лог приложения, принимающего URL в параметре'
detection:
  metadata:
    cs-uri-query|contains:
      - '169.254.169.254'
      - 'metadata.google.internal'
      - '100.100.100.200'
      - '169.254.170.2'
      - 'latest/meta-data'
      - 'computeMetadata'
  internal:
    cs-uri-query|contains:
      - '127.0.0.1'
      - 'localhost'
      - '[::1]'
      - '0.0.0.0'
      - '10.0.'
      - '192.168.'
      - '172.16.'
      - '2130706433'
      - '0x7f000001'
      - '127.1'
      - 'nip.io'
      - 'localtest.me'
  scheme:
    cs-uri-query|contains:
      - 'file://'
      - 'gopher://'
      - 'dict://'
      - 'ldap://'
      - 'ftp://'
  condition: metadata or internal or scheme
fields:
  - c-ip
  - cs-uri-stem
  - cs-uri-query
  - sc-status
falsepositives:
  - легитимные интеграции, которые по замыслу ходят во внутреннюю сеть (выносите в исключения по cs-uri-stem)
level: high
tags:
  - attack.initial_access
  - attack.t1552.005
  - cwe.918
```
