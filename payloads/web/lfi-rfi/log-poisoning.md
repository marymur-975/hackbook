---
id: lfi-log-poisoning
title: "LFI -> RCE: отравление логов (User-Agent)"
type: lfi
target: linux
category: web
difficulty: advanced
bypass: none
tags: [lfi, log-poisoning, rce, user-agent]
tested_on: ["Apache2 + PHP", "nginx + PHP-FPM"]
success_rate: 0.4
risk: high
cwe: "CWE-94"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-community/attacks/Path_Traversal"
graph:
  - target: "lfi-rfi"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "privilege-escalation"
    type: related_to
---

# LFI -> RCE: отравление логов (User-Agent)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
<?php system($_GET['cmd']); ?>
```

## Explanation

Двухшаговая техника: (1) отправить запрос с PHP-кодом в заголовке `User-Agent` —
веб-сервер запишет его в access log; (2) подключить лог через LFI:
`?page=../../../../var/log/apache2/access.log`. При include PHP исполнит код из лога,
и параметр `cmd` станет точкой выполнения команд.
Аналогично работают: SSH-логи (`/var/log/auth.log` с именем пользователя),
почтовые логи, файлы сессий PHP (`/var/lib/php/sessions/sess_<ID>`).

## Detection

1. Найдите LFI и список читаемых логов (`/proc/self/environ`, access/error log,
   `auth.log`, `mail.log`).
2. Отправьте метку в User-Agent и попробуйте прочитать лог.
3. Если метка видна — путь к RCE открыт (проверяйте только в лабе).

## Remediation

- Устранить LFI (whitelist путей).
- Логи вне досягаемости веб-процесса: отдельный volume, права 0640 root:adm.
- `open_basedir`; веб-сервер и PHP-FPM под разными пользователями.
- Не логировать сырые заголовки без нормализации/экранирования.
- Read-only ФС для контейнера приложения.

## Variants

```
/var/log/nginx/access.log
```

```
/var/log/apache2/error.log
```

```
/proc/self/environ
```
