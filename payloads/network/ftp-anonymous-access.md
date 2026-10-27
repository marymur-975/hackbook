---
id: ftp-anonymous-access
title: "FTP: анонимный вход и запись в каталог"
type: network
target: ftp
category: network
difficulty: beginner
bypass: auth
tags: [ftp, anonymous, defaults, file-upload]
tested_on: ["vsftpd 3.x", "ProFTPD", "IIS FTP"]
success_rate: 0.5
risk: medium
cwe: "CWE-287"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/tactics/TA0007/"
graph:
  - target: "network"
    type: instance_of
  - target: "default-credentials"
    type: related_to
  - target: "rce"
    type: leads_to
    description: "Запись в веб-корень через анонимный FTP"
---

# FTP: анонимный вход и запись в каталог

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
ftp 10.10.10.5
user: anonymous
pass: anonymous@
```

## Explanation

Анонимный FTP (`anonymous` / `ftp` с любым паролем) исторически использовался для
публичной раздачи файлов и до сих пор встречается на сетевых устройствах, принтерах,
в legacy-системах и «забытых» серверах. Опасны два случая:

1. Чтение — утечка резервных копий, конфигов, исходников.
2. Запись (`upload`) в каталог, который раздаётся веб-сервером, — прямой путь
   к размещению вредоносного контента или webshell.

Дополнительно FTP передаёт учётные данные и данные открытым текстом — перехват
тривиален в общей сети.

## Detection

1. `nmap --script ftp-anon,ftp-vsftpd-backdoor -p21 <host>`.
2. `curl ftp://<host>/` и `curl -T file ftp://<host>/incoming/`.
3. Проверьте права каталогов: `dir`, `ls -l` через ftp-клиент.
4. Ищите FTP-трафик в pcap: `ftp.request.command == USER`.

## Remediation

- Отключить анонимный доступ; заменить FTP на SFTP/FTPS.
- Если анонимный доступ нужен — только чтение, chroot, отдельный каталог
  вне веб-корня, права 0555.
- Мониторинг записи в анонимные каталоги + антивирусное сканирование.
- Блокировать 21/tcp на границе, инвентаризировать все FTP-сервисы.

## Variants

```
curl ftp://anonymous:anonymous@10.10.10.5/
```

```
nmap --script ftp-anon -p21 10.10.10.0/24
```

## Detection rules

```yaml
title: Анонимный вход на FTP-сервер
id: a7b8c9d0-0002-4a7b-9c8d-000000000002
status: experimental
description: >-
  Успешный вход user=anonymous / USER anonymous в журнале FTP-демона.
  Анонимный FTP наружу — канал утечки; внутрь — точка закрепления
  (запись в /incoming).
references:
  - https://attack.mitre.org/techniques/T1078/
logsource:
  product: linux
  service: ftp
  definition: 'журнал vsftpd/proftpd с записями об аутентификации'
detection:
  selection:
    service: vsftpd
    message|contains:
      - 'user=anonymous'
      - 'USER anonymous'
      - 'anon-password'
      - 'Anonymous access granted'
  condition: selection
fields:
  - source_ip
  - message
falsepositives:
  - легитимные публичные FTP-зеркала (их мало; выносите по source_ip и каталогу)
level: medium
tags:
  - attack.initial_access
  - attack.t1078
  - cwe.306
```
