---
id: linux-enumeration-checklist
title: "Linux: систематическая разведка для эскалации привилегий"
type: privesc
target: linux
category: web
difficulty: beginner
bypass: none
tags: [privesc, linux, enumeration, methodology, recon]
tested_on: ["Debian 12", "Ubuntu 22.04", "Alpine (контейнеры)"]
success_rate: 0.9
risk: low
cwe: "CWE-200"
lab: null
last_verified: "2026-10-23"
references:
  - "https://book.hacktricks.xyz/privilege-escalation/privilege-escalation"
  - "https://github.com/rebootuser/LinEnum"
  - "https://github.com/carlospolop/PEASS-ng"
---

# Linux: систематическая разведка для эскалации привилегий

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1. кто я и где я
id; sudo -l; groups; uname -a; cat /etc/os-release
echo $PATH; env | sort; cat /proc/self/environ 2>/dev/null

# 2. точки закрепления и истории
ls -la ~; cat ~/.bash_history ~/.ssh/known_hosts 2>/dev/null
crontab -l; ls -la /etc/cron.* /var/spool/cron 2>/dev/null
systemctl list-timers --all; cat ~/.ssh/authorized_keys

# 3. записываемое и нестандартное
find / -perm -4000 -type f 2>/dev/null | sort          # SUID
find / -perm -2000 -type f 2>/dev/null | sort          # SGID
getcap -r / 2>/dev/null | grep -v '^/proc'             # capabilities
find /etc /opt /usr/local -writable -type f 2>/dev/null | head -40
find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev)' | head -30

# 4. сервисы и сеть (что слушает локально)
ss -tulpn 2>/dev/null || netstat -tulpn
ps auxf | head -40

# 5. секреты в файлах и истории
grep -rInE 'password|passwd|secret|api[_-]?key|token' /etc /opt /home 2>/dev/null | head -30
ls -la /var/www /srv /opt 2>/dev/null
cat /etc/fstab; showmount -e localhost 2>/dev/null; mount | grep nfs

# 6. контейнер ли это
cat /proc/1/cgroup; ls -la /.dockerenv 2>/dev/null; capsh --print 2>/dev/null | head

# автоматизация (только на своём стенде)
# ./linpeas.sh -a > /tmp/linpeas.txt   # PEASS-ng
# ./LinEnum.sh                          # Rebootuser
```

## Explanation

Разведка — 80% успеха эскалации: большинство систем ломаются не из-за
эксплойта ядра, а из-за конфигурации, которую просто не посмотрели.
Порядок выше намеренно идёт от дешёвого к дорогому:

1. **Идентичность и права** (`id`, `sudo -l`, `groups`): иногда ответ
    уже здесь — разрешённая команда под sudo или членство в `docker`/`lxd`/`adm`.
2. **История и закрепление**: `.bash_history` часто содержит пароли
    и команды; cron/systemd-timers — готовые векторы.
3. **Привилегированные бинарники и capabilities**: SUID/SGID и `getcap`
    (последний легко пропустить).
4. **Записываемые пути**: скрипты, конфиги, каталоги в PATH привилегированных
    служб.
5. **Локальные сервисы**: БД/кэш без аутентификации на 127.0.0.1
    (Redis, Mongo, Docker socket), админ-панели.
6. **Секреты в файлах**: конфиги приложений, `.env`, бэкапы.
7. **Окружение**: контейнер или ВМ — набор техник сильно отличается
    (docker.sock, capabilities контейнера, монтированные секреты Kubernetes).

Группы, дающие эскалацию «из коробки»: `docker`, `lxd`, `disk`, `adm`,
 `video`, `shadow`, `wheel`, `sudo`, `kmem`. Например, `docker` позволяет
смонтировать корень хоста в контейнер и получить root.

## Detection

* Алерт на массовый `find /` от непривилегированного пользователя
  (паттерн перечисления).
* Детект известных инструментов перечисления: `linpeas`, `LinEnum`,
  `linux-smart-enumeration`, `unix-privesc-check`, `pspy`
  (имена процессов, строки в `/tmp`).
* Чтение `/etc/shadow`, `getcap -r /`, `showmount -e` непривилегированным
  пользователем — индикаторы разведки.
* Всплеск обращений к файлам в `/etc` и `/opt` от одной сессии.
* HIDS-правила на запуск скриптов из `/tmp`, `/dev/shm`, `/var/tmp`.
* Логи sudo/audit должны сохраняться вне хоста, иначе атакующий их чистит.

## Remediation

- Уменьшение поверхности: минимум SUID, никаких capabilities сверх нужного,
  sudo-правила с точными аргументами.
- Разделение обязанностей и минимум локальных пользователей на серверах
  (вход по SSH-ключам, запрет общих учёток).
- Чистка истории и секретов: никаких паролей в `.bash_history`, `.env`
  в репозиториях, конфигах и бэкапах (секреты — в vault).
- Монтирование разделов с `noexec,nosuid,nodev` для пользовательских данных.
- Контроль групп: `docker`/`lxd` равнозначны root — выдавать осознанно.
- HIDS/EDR на всех хостах с правилами на перечисление.
- Регулярный аудит конфигурации (hardening-бейзлайны CIS/STIG, автоматическая
  проверка drift).


## Detection rules

```yaml
title: Массовое перечисление системы пользователем (recon перед эскалацией)
id: c3d4e5f6-0006-4c3d-9e4f-000000000206
status: experimental
description: >-
  Комбинация команд разведки прав и конфигурации от одного пользователя
  за короткий промежуток времени, либо запуск известных инструментов перечисления.
references:
  - https://attack.mitre.org/techniques/T1082/
  - https://attack.mitre.org/techniques/T1083/
logsource:
  product: linux
  service: auditd
  definition: 'аудит execve для пользовательских сессий'
detection:
  tools:
    CommandLine|contains:
      - 'linpeas'
      - 'LinEnum'
      - 'linux-smart-enumeration'
      - 'unix-privesc-check'
      - 'pspy'
      - 'getcap -r'
      - 'showmount -e'
      - 'find / -perm -4000'
      - 'find / -perm -2000'
  sensitive_read:
    CommandLine|contains:
      - '/etc/shadow'
      - '/etc/sudoers'
      - 'id_rsa'
      - '.bash_history'
  recon_volume:
    EventType: EXECVE
    auid|gte: 1000
  timeframe: 10m
  condition: tools or sensitive_read or (recon_volume | count() by auid > 200)
fields:
  - CommandLine
  - User
  - ParentImage
falsepositives:
  - администраторы и инвентаризационные агенты (выносите по User/ParentImage)
  - CI-агенты и системы мониторинга безопасности
level: medium
tags:
  - attack.discovery
  - attack.t1082
  - attack.t1083
```
