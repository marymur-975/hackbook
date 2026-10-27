---
id: redis-unauthenticated
title: "Redis/Memcached без аутентификации: чтение данных и запись в ФС"
type: network
target: redis
category: network
difficulty: intermediate
bypass: auth
tags: [redis, memcached, noauth, rce]
tested_on: ["Redis 6/7 (без requirepass)", "Memcached 1.6"]
success_rate: 0.6
risk: high
cwe: "CWE-306"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0007/"
graph:
  - target: "network"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "data-exfiltration"
    type: leads_to
  - target: "dos"
    type: related_to
---

# Redis/Memcached без аутентификации: чтение данных и запись в ФС

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
redis-cli -h 10.10.10.5 INFO keyspace
```

## Explanation

Redis и Memcached по умолчанию слушают без аутентификации. Если порт открыт за пределы
localhost, любой клиент читает и меняет все данные: кеш сессий, токены, очереди задач,
персональные данные.

Отдельный вектор — выполнение кода через Redis:
- `CONFIG SET dir /var/www/html` + `CONFIG SET dbfilename shell.php` + `SAVE`
  -> запись файла в веб-корень;
- `CONFIG SET dir /root/.ssh` + ключ в значение -> доступ по SSH;
- запись в cron (`/var/spool/cron/crontabs/<user>`);
- загрузка модуля Redis (`.so`) -> полноценный RCE.

Memcached дополнительно использовался для UDP-усиления DDoS (порт 11211, фактор x51000),
поэтому открытый 11211 — ещё и риск для terceros.

## Detection

1. `redis-cli -h <host> INFO` — если ответил без `NOAUTH`, аутентификации нет.
2. `nmap -p 6379,11211 --script redis-info,memcached-info <host>`.
3. Для Memcached: `echo -e 'stats\r\nquit\r' | nc <host> 11211`.
4. Обязательно проверьте UDP/11211 снаружи (усиление).
5. В логах Redis: команды `CONFIG SET`, `MODULE LOAD`, `SAVE`.

## Remediation

- `requirepass` / ACL Redis 6+ (отдельные пользователи с минимальными командами).
- `bind 127.0.0.1` + firewall/security group: никаких публичных 6379/11211/27017.
- `protected-mode yes`, `rename-command CONFIG/FLUSHALL/MODULE ''`.
- Redis под отдельным пользователем без записи в веб-корень, read-only ФС,
  контейнер без cron и ssh.
- TLS (`tls-port`) и аутентификация клиента.
- Мониторинг `CONFIG SET` и появления новых файлов в веб-каталоге.

## Variants

```
memcached: stats
```

```
redis-cli -h 10.10.10.5 CONFIG GET dir
```

## Detection rules

```yaml
title: Redis без аутентификации — команды от внешнего клиента и CONFIG SET
id: a7b8c9d0-0004-4a7b-9c8d-000000000004
status: experimental
description: >-
  Команды к Redis без AUTH от не-локальных клиентов; особо опасны CONFIG SET
  dir/dbfile (запись cron/ssh-ключей), SLAVEOF/REPLICAOF (RCE через репликацию)
  и MODULE LOAD.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://redis.io/docs/latest/operate/oss_and_stack/management/security/
logsource:
  product: linux
  service: redis
  definition: 'журнал redis-server (loglevel notice+) или сетевой лог порта 6379'
detection:
  selection:
    service: redis
    message|contains:
      - 'without AUTH'
      - 'no AUTH'
      - 'NOAUTH'
      - 'CONFIG SET'
      - 'SLAVEOF'
      - 'REPLICAOF'
      - 'MODULE LOAD'
      - 'FLUSHALL'
  condition: selection
fields:
  - source_ip
  - message
falsepositives:
  - внутренние сентинелы и реплики (SLAVEOF от известных master) — исключайте
    по source_ip, но AUTH остаётся обязательным
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.306
```
