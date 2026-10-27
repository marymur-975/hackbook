---
id: detection-webserver-sqli-signatures
title: "Детект SQLi по access-логам: синтаксис, UNION, слепые каналы"
type: sqli
target: generic
category: web
difficulty: intermediate
bypass: none
tags: [detection, sigma, sqli, webserver-logs, siem]
tested_on: ["nginx/Apache access log", "лог vuln-hub (/logs)", "фикстуры detections/tests"]
success_rate: 0.7
risk: low
cwe: "CWE-89"
lab: "labs/web-labs/vuln-hub"
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
---

# Детект SQLi по access-логам: синтаксис, UNION, слепые каналы

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# воспроизведение трафика для проверки правила (только локальная лаборатория)
python3 tools/payload-tester.sh --lab vuln-hub --type sqli
python3 tools/lib/http_fetch.py "http://localhost:8090/items?id=-1%20UNION%20SELECT%201,2,3--%20" 6 GET
python3 tools/lib/http_fetch.py http://localhost:8090/logs
```

## Explanation

SQL-инъекция оставляет в access-логе три класса следов, и надёжное правило
строится на их комбинации, а не на одной сигнатуре:

1. **Синтаксические маркеры** в query-строке: `UNION SELECT`, `--`, `#`,
    `/*`, `OR 1=1`, `AND 1=1`, `SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY`,
    `pg_sleep`, `information_schema`, `sqlite_master`, `sysobjects`,
    `EXTRACTVALUE`, `UPDATEXML`, `xp_cmdshell`.
2. **Аномалии ответа**: статус 500 при обычном 200 для того же пути,
    резкое изменение длины ответа, текст ошибки СУБД в теле
    (если тело логируется).
3. **Поведенческий паттерн**: десятки запросов к одному эндпоинту
    с минимально различающимися параметрами (перебор `AND 1=1`/`AND 1=2`,
    посимвольное чтение), одинаковый User-Agent (sqlmap, sqlninja),
    высокая частота с одного IP.

Правило только на сигнатурах даёт ложные срабатывания на поисковых строках
и CMS-параметрах; правило только на статусе 500 — шумит на обычных багах.
Практичный подход: сигнатура **плюс** подтверждение (500/изменение длины
или повторный запрос с инвертированным условием).

Правила рассчитаны на access-лог в ECS/W3C-подобных полях (`cs-uri-stem`, `cs-uri-query`, `sc-status`, `c-ip`, `cs-user-agent`). В своём SIEM замените имена полей на фактические — логика не изменится.

## Detection

Проверка правила на синтетических фикстурах проекта:

```bash
python detections/tests/generate_fixtures.py
python tools/rules-tester.py --rule sqli --verbose
```

Что смотреть в живых логах: доля 500-х по эндпоинтам, уникальные query-паттерны,
User-Agent со словами `sqlmap`/`sql`, запросы к одному пути с частотой > 5/с
от одного IP. Отдельный признак — появление `information_schema` или
`sqlite_master` в query у обычных пользователей: легитимного повода почти нет.

## Remediation

- Детект не заменяет параметризацию: правило снижает время обнаружения,
  но не устраняет уязвимость.
- Логируйте полную query-строку (без неё детект невозможен) и длину ответа.
- Нормализуйте логи перед анализом: URL-decode, приведение регистра.
- Rate limiting и WAF — как слой снижения шума, с алертами на блокировки.
- Храните access-логи отдельно от приложения (атакующий с RCE чистит локальные).
- Регулярно прогоняйте правила на трафике лабораторий: `payload-tester.sh`
  генерирует воспроизводимый «атакующий» трафик для проверки.


## Detection rules

```yaml
title: SQL-инъекция в query-строке с подтверждением по статусу ответа
id: b2c3d4e5-0001-4b2c-8d3e-000000000101
status: test
description: >-
  Сочетание синтаксических маркеров SQL-инъекции в query-строке и признака
  срабатывания (5xx или аномально длинный/короткий ответ). Комбинация снижает
  число ложных срабатываний на поисковых строках.
references:
  - https://attack.mitre.org/techniques/T1190/
  - payloads/web/sqli/mysql-union-select-enumeration.md
logsource:
  category: webserver
  definition: 'access-лог с полной query-строкой и кодом ответа'
detection:
  keywords:
    cs-uri-query|contains:
      - 'union select'
      - 'union all select'
      - 'information_schema'
      - 'sqlite_master'
      - 'sysobjects'
      - 'pg_sleep'
      - 'waitfor delay'
      - 'extractvalue'
      - 'updatexml'
      - 'xp_cmdshell'
      - ' or 1=1'
      - ' and 1=1'
      - "' or '1'='1"
      - 'benchmark('
      - 'sleep('
  confirmation:
    sc-status|gte: 500
  scanner_ua:
    cs-user-agent|contains:
      - 'sqlmap'
      - 'sqlninja'
      - 'nosqli'
  condition: keywords and (confirmation or scanner_ua)
fields:
  - c-ip
  - cs-uri-stem
  - cs-uri-query
  - sc-status
  - cs-user-agent
falsepositives:
  - поисковые запросы пользователей, содержащие слова select/union
  - CMS-параметры сортировки (ORDER BY) — выносите в исключения по cs-uri-stem
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.89
```
