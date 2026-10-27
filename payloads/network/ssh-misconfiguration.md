---
id: ssh-misconfiguration
title: "SSH: опасные настройки sshd_config и перехват агента/known_hosts"
type: network
target: ssh
category: web
difficulty: intermediate
bypass: none
tags: [network, ssh, hardening, agent-forwarding, authorized-keys, lateral-movement]
tested_on: ["OpenSSH 9.x (Debian 12, собственная ВМ)"]
success_rate: 0.7
risk: high
cwe: "CWE-287"
lab: "labs/setup/docker-compose.yml"
last_verified: "2026-10-23"
references:
  - "https://man.openbsd.org/sshd_config"
---

# SSH: опасные настройки sshd_config и перехват агента/known_hosts

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) аудит конфигурации сервера (своя система)
sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|passwordauth|permitemptypasswords|\
allowusers|allowgroups|denyusers|maxauthtries|pubkeyauth|kbdinteractive|\
allowagentforwarding|allowtcpforwarding|x11forwarding|permitopen|port|banner'

# 2) опасные значения (что искать)
# permitrootlogin yes            -> прямой вход root по паролю
# passwordauthentication yes     -> перебор паролей возможен
# permitemptypasswords yes       -> критично
# kbdinteractiveauthentication yes + UsePAM -> обходные пути аутентификации
# maxauthtries 6+                -> широкий перебор в одном соединении
# permituserenvironment yes      -> пользователь задаёт переменные окружения
# allowagentforwarding yes       -> угон SSH-агента (см. ниже)
# allowtcpforwarding yes         -> туннелирование внутрь сети (pivot)
# x11forwarding yes              -> перехват X-сессий
# permitopen any / без ограничений -> произвольные форварды
# gatewayports yes               -> проброс портов наружу
# authorizedkeyscommand без проверки -> выполнение произвольной команды

# 3) authorized_keys: опасные опции и чужие ключи
for f in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
  [ -f "$f" ] && { echo "== $f"; ls -la "$f"; awk '{print NR": "$1" "$2" "$3}' "$f" | cut -c1-160; done; done
# ищем: command=, no-pty, environment=, permitopen=, from= (или их отсутствие)
# права: 0600 (файл), 0700 (~/.ssh), владелец — сам пользователь

# 4) SSH-агент: перехват через сокет (только учебный стенд!)
#    SSH_AUTH_SOCK указывает на сокет агента; владелец сокета может
#    использовать ключи без знания парольной фразы
echo $SSH_AUTH_SOCK; ls -la ${SSH_AUTH_SOCK%/*} 2>/dev/null
ssh-add -l                      # какие ключи загружены
# если агент проброшен (AllowAgentForwarding) на недоверенный хост,
# root на том хосте получает доступ к ключам пользователя

# 5) known_hosts и MITM
wc -l ~/.ssh/known_hosts; ssh-keygen -F <host>
# StrictHostKeyChecking no + UserKnownHostsFile=/dev/null = принимаем любой ключ

# 6) перебор учётных данных — ТОЛЬКО на своей изолированной ВМ
# hydra -l user -P wordlists/passwords/top-10k.txt ssh://127.0.0.1:2222 -t 4

# 7) проверка версии и алгоритмов
ssh -Q cipher; ssh -Q mac; ssh -Q kex
nmap --script ssh2-enum-algos,ssh-auth-methods,ssh-run -p 22 127.0.0.1  # свой хост
```

## Explanation

SSH-конфигурация — частый источник проблем, потому что «работает»
она и при опасных настройках. Основные классы:

1. **Аутентификация**: `PermitRootLogin yes` (особенно с паролем),
    `PasswordAuthentication yes` без fail2ban/rate limiting,
    `PermitEmptyPasswords`, `KbdInteractiveAuthentication` как обход,
    высокий `MaxAuthTries`, отсутствие `AllowUsers`/`AllowGroups`.
2. **Проброс (forwarding)**: `AllowAgentForwarding`, `AllowTcpForwarding`,
    `X11Forwarding`, `GatewayPorts`, `PermitOpen any`. Они превращают
    скомпрометированный хост в плацдарм: агент даёт доступ к вашим ключам,
    TCP-форвард — туннель во внутреннюю сеть, X11 — перехват ввода и экрана.
3. **authorized_keys**: чужие ключи (закрепление), отсутствие ограничивающих
    опций (`from=`, `command=`, `no-port-forwarding`, `no-pty`),
    права 0644/0777 (в зависимости от `StrictModes` это может позволять
    вход), ключи в общих учётках.
4. **Проверка ключа хоста**: `StrictHostKeyChecking no` и
    `UserKnownHostsFile=/dev/null` в конфигурации клиентов/автоматизации
    — MITM становится тривиальным.
5. **Устаревшая криптография**: CBC-режимы, `diffie-hellman-group1-sha1`,
    HMAC-MD5/SHA1, DSA-ключи.
6. **`PermitUserEnvironment`**, `AuthorizedKeysCommand` без проверки —
    выполнение кода на этапе аутентификации.

**SSH-агент** заслуживает отдельного внимания: если вы подключаетесь
с пробросом агента к хосту, на котором есть root, он может использовать
сокет агента для аутентификации вашими ключами на любых других системах
(парольная фраза не нужна). Правило: не пробрасывать агент на
недоверенные хосты; для автоматизации — отдельные ключи с ограничениями.

## Detection

* Логи аутентификации (`/var/log/auth.log`, journal): всплеск
  `Failed password`, `Invalid user`, `maximum authentication attempts
  exceeded` — перебор.
* Алерт на успешный вход root по паролю (`Accepted password for root`).
* Алерт на вход с новых IP/геозон для привилегированных учёток.
* Детект использования агента: процессы, обращающиеся к сокету
  `SSH_AUTH_SOCK` не от своего пользователя; `ssh-add -l` в подозрительном
  контексте.
* Детект туннелирования: новые исходящие соединения от sshd-процесса,
  `-L`/`-R`/`-D` в командной строке, проброс нестандартных портов.
* Контроль целостности `/etc/ssh/sshd_config` и `authorized_keys`
  (aide/osquery): добавление ключа — всегда алерт.
* Инвентаризация ключей: соответствие `authorized_keys` CMDB.
* Анализ `sshd -T` в baseline и drift-детект.
* Honeypot-учётки: любой вход — критичный инцидент.

## Remediation

- Аутентификация только по ключам: `PasswordAuthentication no`,
  `KbdInteractiveAuthentication no`, `PermitEmptyPasswords no`,
  `PermitRootLogin no` (или `prohibit-password` + отдельный ключ),
  `MaxAuthTries 3`, `LoginGraceTime 30`.
- Ограничение доступа: `AllowGroups ssh-users`, `Match`-блоки для
  отдельных групп (например, sftp-only с `ForceCommand internal-sftp`,
  `ChrootDirectory`, `PermitOpen none`).
- Отключить проброс по умолчанию: `AllowAgentForwarding no`,
  `AllowTcpForwarding no`, `X11Forwarding no`, `GatewayPorts no`,
  `PermitOpen none`; включать точечно через `Match`.
- Криптография: современные KEX (`curve25519-sha256`,
  `diffie-hellman-group16-sha512`), шифры `chacha20-poly1305@openssh.com`,
  `aes256-gcm@openssh.com`, MAC `hmac-sha2-512-etm@openssh.com`;
  ключи ed25519/RSA-4096.
- Ключи: `authorized_keys` с ограничениями (`from=`, `command=`,
  `no-port-forwarding`, `no-agent-forwarding`, `no-pty`), права 0600,
  каталог 0700, `StrictModes yes`; ротация и инвентаризация;
  certificate-based auth (SSH CA) вместо долгоживущих ключей.
- Клиенты: `StrictHostKeyChecking accept-new` (не `no`), хранение
  `known_hosts`, проверка отпечатка при первом подключении.
- Сетевой уровень: доступ к 22/tcp только из VPN/джамп-хостов,
  fail2ban/RateLimit, нестандартный порт как снижение шума (не защита).
- 2FA для привилегированного доступа; запись сессий (bastion/Teleport).
- Регулярные обновления OpenSSH и мониторинг advisories.


## Detection rules

```yaml
title: "Аномальная SSH-активность: перебор, вход root по паролю, туннелирование"
id: d4e5f6a7-0002-4d4e-8f5a-000000000302
status: test
description: >-
  Комбинация признаков атак на SSH: массовые неудачные аутентификации,
  успешный вход root по паролю, запуск ssh с флагами проброса, добавление
  ключей в authorized_keys.
references:
  - https://attack.mitre.org/techniques/T1021/004/
  - https://attack.mitre.org/techniques/T1098/004/
logsource:
  product: linux
  service: auth
  definition: 'журнал аутентификации (auth.log / journalctl -u sshd)'
detection:
  brute_force:
    process: sshd
    message|contains:
      - 'Failed password'
      - 'Invalid user'
      - 'maximum authentication attempts exceeded'
  root_password_login:
    process: sshd
    message|contains: 'Accepted password for root'
  new_key:
    process: sshd
    message|contains: 'Authentication succeeded (publickey)'
  ssh_forward:
    EventType: EXECVE
    Image|endswith: '/ssh'
    CommandLine|contains:
      - ' -L'
      - ' -R'
      - ' -D'
      - 'ProxyCommand'
  authorized_keys_write:
    EventType: PATH
    Name|endswith: '/.ssh/authorized_keys'
    auid|gte: 1000
  timeframe: 10m
  condition: root_password_login or authorized_keys_write or ssh_forward or (brute_force | count() by source_ip > 20)
fields:
  - source_ip
  - user
  - message
  - CommandLine
falsepositives:
  - легитимные туннели разработчиков (сужайте по учётке и целевому хосту)
  - ротация ключей автоматизацией (выделенная учётка и расписание)
level: high
tags:
  - attack.lateral_movement
  - attack.credential_access
  - attack.t1021.004
  - attack.t1098.004
```
