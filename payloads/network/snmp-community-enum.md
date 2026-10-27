---
id: snmp-community-enum
title: "SNMP: чтение MIB с community-строкой public"
type: network
target: snmp
category: network
difficulty: beginner
bypass: auth
tags: [snmp, network, enumeration, defaults]
tested_on: ["net-snmp 5.9", "типовые сетевые устройства"]
success_rate: 0.6
risk: medium
cwe: "CWE-798"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0007/"
graph:
  - target: "network"
    type: instance_of
  - target: "enumeration"
    type: leads_to
  - target: "default-credentials"
    type: related_to
---

# SNMP: чтение MIB с community-строкой public

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
snmpwalk -v2c -c public 10.10.10.1 1.3.6.1.2.1.1
```

## Explanation

SNMPv1/v2c аутентифицируется «community-строкой», передаваемой открытым текстом;
значение по умолчанию `public` (чтение) и `private` (запись) до сих пор встречается
на маршрутизаторах, принтерах, IPMI и Windows-хостах с включённой службой SNMP.
Полезные ветки MIB:

| OID | Что даёт |
|-----|----------|
| `1.3.6.1.2.1.1` | sysDescr, uptime, контакты — fingerprinting |
| `1.3.6.1.2.1.4.22` | ARP-таблица (внутренние хосты) |
| `1.3.6.1.2.1.2.2` | интерфейсы, трафик |
| `1.3.6.1.2.1.25.4.2` | запущенные процессы |
| `1.3.6.1.4.1.77.1.2.25` | пользователи (Windows) |
| `1.3.6.1.2.1.6.13` | TCP-соединения |

С `private` возможна запись конфигурации (изменение маршрутов, перезагрузка устройства).

## Detection

1. `onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <subnet>` — быстрый перебор community.
2. `nmap -sU -p161 --script snmp-brute,snmp-info <host>`.
3. Перехват: community видна в открытом виде в UDP/161 (Wireshark-фильтр `snmp`).

## Remediation

- Переход на SNMPv3: authPriv (SHA + AES), уникальные учётки на устройство.
- Если v2c неизбежен — длинные случайные community, ACL по IP-адресу источника, только чтение.
- Не публиковать SNMP наружу; блокировать UDP/161 на границе сегментов.
- Инвентаризация: отключить службу там, где мониторинг не используется.
- Мониторинг запросов с community `public`/`private`.

## Variants

```
snmpwalk -v2c -c private 10.10.10.1 1.3.6.1.2.1.25.4.2
```

```
snmp-check -c public 10.10.10.1
```

## Detection rules

```yaml
title: SNMP-перебор community-строк и запросы с public/private
id: a7b8c9d0-0007-4a7b-9c8d-000000000007
status: experimental
description: >-
  Журнал snmpd фиксирует запросы с дефолтными community (public/private)
  или серии «bad community string» — enumeration оборудования (snmpwalk)
  и подбор сообщества.
references:
  - https://attack.mitre.org/techniques/T1595/
logsource:
  product: linux
  service: snmp
  definition: 'syslog snmpd (или сетевого устройства) с сообщениями об аутентификации'
detection:
  selection:
    service: snmpd
    message|contains:
      - 'community=public'
      - 'community=private'
      - 'bad community'
      - 'community string'
      - 'authentication failure'
  condition: selection
fields:
  - source_ip
  - message
falsepositives:
  - мониторинг, до сих пор ходящий с public (это само по себе находка —
    переведите на SNMPv3 USM)
level: medium
tags:
  - attack.discovery
  - attack.t1595
  - cwe.798
```
