---
id: headers-crlf-injection
title: "CRLF-инъекция в заголовки и ответ"
type: header
target: http
category: web
difficulty: intermediate
bypass: none
tags: [crlf, header-injection, response-splitting, xss]
tested_on: ["Python http.server (legacy)", "Node http (legacy)", "nginx (unescaped)"]
success_rate: 0.3
risk: high
cwe: "CWE-113"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "headers"
    type: instance_of
  - target: "xss"
    type: leads_to
  - target: "open-redirect"
    type: leads_to
  - target: "session-hijacking"
    type: leads_to
---

# CRLF-инъекция в заголовки и ответ

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
%0d%0aSet-Cookie:admin=1
```

## Explanation

Если значение, содержащее `%0d%0a` (CRLF), попадает в заголовок ответа без нормализации,
атакующий добавляет собственные заголовки или даже целиком новое тело ответа
(response splitting). Последствия: установка cookie (фиксация/перехват сессии),
инъекция `Location:` (open redirect), внедрение HTML/JS (XSS), отравление кеша.
Современные HTTP-библиотеки (Node >= 8, Python >= 3.6, nginx) отклоняют CRLF
в заголовках, поэтому вектор встречается в самописных серверах, старых фреймворках
и в логике редиректов/куки.

## Detection

1. Найдите параметры, отражаемые в заголовках ответа (`Location`, `Set-Cookie`,
   кастомные).
2. Подставьте `%0d%0aX-Injected:yes` и поищите заголовок в ответе.
3. Проверьте также `\r\n`, `%E5%98%8D%E5%98%8A` (обход в некоторых реализациях),
   и отражение в `Location` при редиректах.
Инструменты: Burp Intruder + CRLF-словарь, `smuggler`.

## Remediation

- Никогда не вставлять пользовательские данные в заголовки без валидации.
- Отклонять значения, содержащие CR/LF и управляющие символы (whitelist `^[A-Za-z0-9._/-]+$`).
- Использовать современные HTTP-библиотеки (они блокируют CRLF на уровне API).
- Для редиректов — whitelist целевых путей, относительные URL вместо абсолютных.

## Variants

```
%0d%0aX-Injected: yes
```

```
%0d%0a%0d%0a<script>alert(1)</script>
```

```
\r\nSet-Cookie: a=1
```
