---
id: headers-user-agent-log-injection
title: "User-Agent/Referer: инъекция в логи и хранимые векторы"
type: header
target: http
category: web
difficulty: beginner
bypass: none
tags: [headers, log-injection, blind-xss, user-agent]
tested_on: ["Apache access log", "nginx", "SIEM-пайплайны"]
success_rate: 0.6
risk: medium
cwe: "CWE-117"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "headers"
    type: instance_of
  - target: "xss"
    type: leads_to
    description: "Blind XSS в интерфейсе просмотра логов"
  - target: "lfi-rfi"
    type: related_to
  - target: "admin-panel"
    type: leads_to
---

# User-Agent/Referer: инъекция в логи и хранимые векторы

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
Mozilla/5.0 HB-CANARY-12345
```

## Explanation

Заголовки `User-Agent`, `Referer`, `X-Forwarded-For` пишутся в логи без экранирования.
Последствия:

- log forging: поддельные строки лога (вставка CRLF), заметание следов
- blind XSS: нагрузка исполняется, когда аналитик/админ открывает логи в веб-интерфейсе
  (SIEM, Grafana, Kibana, самописные админки)
- инъекция в SQL/NoSQL, если логи парсятся и складываются в БД
- отравление аналитики и WAF-отчётов, обход детектирования по сигнатурам UA
- путь к RCE: лог + LFI (см. payload `lfi-log-poisoning`)

Это «тихий» вектор: он почти никогда не проверяется при тестировании приложения,
потому что цель — не само приложение, а его обслуга.

## Detection

1. Отправьте запрос с уникальной меткой в `User-Agent`.
2. Найдите её в логах веб-сервера, SIEM, админ-панели, отчётах.
3. Проверьте экранирование: видны ли raw-символы `<`, `\n`, кавычки.
4. Оцените, исполняется ли HTML в интерфейсе просмотра логов (blind XSS).

## Remediation

- Экранировать/нормализовать заголовки перед записью в лог (убрать CR/LF, ограничить длину).
- Хранить логи в структурированном виде (JSON) и рендерить в UI с экранированием.
- CSP для внутренних панелей мониторинга; не исполнять HTML из логов.
- Отдельный пользователь/контейнер для лог-пайплайна, read-only доступ.
- Ограничить длину и charset `User-Agent` на gateway.

## Variants

```
Referer: http://attacker.tld/HB
```

```
X-Forwarded-For: 1.2.3.4\r\nfake line
```
