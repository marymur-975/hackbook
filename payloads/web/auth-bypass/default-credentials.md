---
id: auth-bypass-default-credentials
title: "Учётные данные по умолчанию в сервисах и админ-панелях"
type: auth-bypass
target: generic
category: web
difficulty: beginner
bypass: auth
tags: [auth-bypass, defaults, bruteforce]
tested_on: ["различные веб-панели, СУБД, сетевые устройства"]
success_rate: 0.5
risk: high
cwe: "CWE-1392"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "auth-bypass"
    type: instance_of
  - target: "bruteforce"
    type: related_to
  - target: "admin-panel"
    type: leads_to
---

# Учётные данные по умолчанию в сервисах и админ-панелях

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
admin:admin
```

## Explanation

Значительная доля реальных инцидентов начинается не с эксплойта, а с учётных данных
по умолчанию: админ-панели, СУБД, брокеры сообщений, CI/CD, системы мониторинга,
IPMI/BMC, сетевые устройства. Проверяются и «документированные» пары из вендорских
руководств, и дефолтные токены (`changeme`, `password`, пустой пароль),
и сервисные учётки (`sa`, `postgres`, `elastic`).
Списки для проверки: `wordlists/passwords/`, `wordlists/usernames/admin.txt`.

## Detection

1. Составьте инвентарь сервисов (порты, панели, версии).
2. Проверьте документацию вендора на дефолтные учётки именно этой версии.
3. Пробуйте по одной паре на учётку (избегайте блокировок), фиксируйте коды ответов.
Инструменты: `hydra`, `medusa`, `nmap`-скрипты (`http-default-accounts`), `ncrack`.

## Remediation

- Принудительная смена пароля при первом входе; запрет пустых паролей.
- Удаление/блокировка встроенных учёток (`admin`, `sa`, `guest`, `test`).
- MFA для всех административных интерфейсов; доступ только из VPN/сегмента.
- Мониторинг неудачных входов + rate limiting + блокировка по geo/IP.
- Инвентаризация дефолтных учёток как часть hardening-чеклиста.

## Variants

```
admin:password
```

```
root:toor
```

```
sa:<empty>
```

```
elastic:changeme
```

```
admin:admin123
```
