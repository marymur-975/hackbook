---
id: dns-zone-transfer
title: "DNS: AXFR — полная передача зоны"
type: network
target: dns
category: network
difficulty: beginner
bypass: none
tags: [dns, zone-transfer, enumeration, recon]
tested_on: ["BIND 9", "PowerDNS", "Windows DNS"]
success_rate: 0.35
risk: medium
cwe: "CWE-200"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0007/"
graph:
  - target: "network"
    type: instance_of
  - target: "enumeration"
    type: leads_to
  - target: "active-directory"
    type: related_to
---

# DNS: AXFR — полная передача зоны

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
dig AXFR lab.local @10.10.10.5
```

## Explanation

Передача зоны (AXFR) предназначена для репликации между DNS-серверами, но при
отсутствии ACL любой клиент может запросить ВСЕ записи домена. Это мгновенная
карта инфраструктуры: внутренние имена, IP серверов, SRV-записи домена
(`_ldap._tcp`, `_kerberos`), почтовые хосты, тестовые стенды.
Для Active Directory особенно ценны SRV-записи и `_msdcs` — по ним видны контроллеры
домена и их роли. IXFR (инкрементальная передача) даёт то же при наличии SOA-серий.

## Detection

1. `dig AXFR <zone> @<ns>` и `host -l <zone> <ns>`.
2. `nmap --script dns-zone-transfer -p 53 <host>`.
3. Косвенные признаки: сервер отвечает на ANY-запросы и отдаёт полные записи;
   в логах — запросы типа AXFR с внешних IP.
4. Проверьте также UDP/53 (AXFR только TCP, но разведка — UDP).

## Remediation

- ACL на передачу зоны: `allow-transfer { <ip вторичных NS>; };` (BIND),
  явный список вторичных серверов.
- TSIG-подпись зон для репликации.
- Разделение представлений: внутренний вид (split DNS) и внешний — разные зоны/вьюхи.
- Мониторинг/блокировка AXFR извне на perimeter-файрволе.
- Минимизация записей в публичной зоне.

## Variants

```
host -l lab.local 10.10.10.5
```

```
dig IXFR=1 lab.local @10.10.10.5
```

```
nmap --script dns-zone-transfer -p 53 10.10.10.5
```

## Detection rules

```yaml
title: Передача зоны DNS (AXFR/IXFR) посторонним клиентом
id: a7b8c9d0-0001-4a7b-9c8d-000000000001
status: experimental
description: >-
  В журнале BIND (или другого authoritative-сервера) появляются записи
  AXFR started/ended — клиент запросил полную копию зоны. Вне списка
  вторичных NS это всегда аномалия: зона содержит внутреннюю топологию.
references:
  - https://attack.mitre.org/techniques/T1590/
logsource:
  category: dns
  definition: 'журнал authoritative DNS-сервера (query log / xfer log)'
detection:
  selection:
    service: bind
    message|contains:
      - 'AXFR'
      - 'IXFR'
      - 'zone transfer'
      - 'transfer of'
  condition: selection
fields:
  - source_ip
  - message
falsepositives:
  - штатные вторичные NS и скрытые master-передачи — ведите allowlist IP
    (allow-transfer) и исключайте их в фильтре
level: high
tags:
  - attack.discovery
  - attack.t1590
  - cwe.16
```
