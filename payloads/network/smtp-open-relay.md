---
id: smtp-open-relay
title: "SMTP: open relay и злоупотребление внутренней почтовой инфраструктурой"
type: network
target: smtp
category: web
difficulty: beginner
bypass: none
tags: [network, smtp, open-relay, phishing, mail-security]
tested_on: ["Postfix (собственная ВМ)", "лабораторный профиль labs/setup"]
success_rate: 0.8
risk: high
cwe: "CWE-284"
lab: "labs/setup/docker-compose.yml"
last_verified: "2026-10-23"
references:
  - "https://www.postfix.org/RESTRICTION_CLASS_README.html"
---

# SMTP: open relay и злоупотребление внутренней почтовой инфраструктурой

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) проверка: принимает ли сервер письма для внешнего получателя
#    от неаутентифицированного клиента (только с разрешения владельца!)
python3 - <<'PY'
import smtplib, sys
host, port = 'mail.example.lab', 25
try:
    with smtplib.SMTP(host, port, timeout=10) as s:
        s.ehlo('probe.lab')
        code, _ = s.mail('probe@probe.lab')
        print('MAIL FROM:', code)
        code, _ = s.rcpt('external@example.com')
        print('RCPT TO (внешний):', code, '-> 250 = open relay')
        s.quit()
except Exception as e:
    print('ошибка:', e.__class__.__name__, e)
PY

# 2) что ещё раскрывает баннер и EHLO
python3 - <<'PY'
import socket
s = socket.create_connection(('mail.example.lab', 25), timeout=8)
print(s.recv(1024).decode(errors='replace'))
s.sendall(b'EHLO probe.lab\r\n'); print(s.recv(4096).decode(errors='replace'))
s.sendall(b'QUIT\r\n'); s.close()
PY

# 3) локальная проверка конфигурации Postfix (своя ВМ)
postconf -n | grep -E 'mynetworks|relay_domains|relayhost|smtpd_relay_restrictions'
# опасные значения: mynetworks = 0.0.0.0/0, smtpd_relay_restrictions = permit
#                   relay_domains = (пусто при permit), inet_interfaces = all

# 4) анонимная аутентификация и слабые механизмы
python3 - <<'PY'
import smtplib
with smtplib.SMTP('mail.example.lab', 587, timeout=10) as s:
    s.ehlo(); print('STARTTLS:', s.has_extn('starttls'))
    print('AUTH mech:', s.esmtp_features.get('auth'))
PY
```

## Explanation

**Open relay** — сервер, пересылающий почту от неаутентифицированных
отправителей внешним получателям. Последствия: рассылка спама и фишинга
от имени вашего домена, попадание в блэклисты (Spamhaus, Barracuda),
использование инфраструктуры для атак на третьих лиц, юридическая
ответственность.

Как возникает:

* `mynetworks = 0.0.0.0/0` или слишком широкая подсеть в Postfix;
* `smtpd_relay_restrictions = permit` (или отсутствие ограничений);
* в Exchange: коннектор Receive с `Anonymous` и снятой галкой
  «Require authentication» для внешнего трафика;
* в Sendmail: `relay_dom_file`/`RELAY` для `0.0.0.0/0`;
* «промежуточный» хост в DMZ, который по недосмотру принимает
   соединения из интернета (inet_interfaces = all).

Смежные проблемы конфигурации:

* **раскрытие информации в баннере** (версия ПО, hostname) — облегчает
  подбор эксплойтов;
* **VRFY/EXPN включены** — перебор существующих адресов
  (`VRFY user`), используется для валидации списков рассылки;
* **отсутствие SPF/DKIM/DMARC** — любой может отправить письмо от имени
  вашего домена, и оно не будет отклонено;
* **AUTH без TLS** — пароли в открытом виде;
* **submission-порт 587/465 открыт в интернет** без rate limiting —
  площадка для подбора паролей;
* **внутренние списки рассылки доступны извне** — утечка оргструктуры.

Проверка open relay выполняется только с письменного разрешения владельца
или на своей инфраструктуре; публичные «relay test»-сервисы отправляют
письмо вам же и не создают трафика третьим лицам.

## Detection

* Аномальный объём исходящей почты: всплеск `RCPT TO` на внешние домены
  от одного соединения или от неаутентифицированного клиента.
* Логи MTA: в Postfix — строки `relay=`, `client=` из внешних адресов;
  в Exchange — `SMTP RECEIVE` с `TlsDomain` пустым и внешним получателем.
* Алерт на `VRFY`/`EXPN`-команды из интернета.
* Алерт на большое число `AUTH`-попыток с разных IP (перебор паролей
  на submission-порте).
* Мониторинг попадания домена в блэклисты (Spamhaus/Barracuda) —
  индикатор уже случившегося злоупотребления.
* Анализ DMARC-отчётов: письма «от вашего домена», отправленные
  с чужих IP.
* Сетевой детект: исходящий трафик на 25/tcp от хостов, которые не
  являются почтовыми серверами (признак заражённого узла или relay-цепочки).

## Remediation

- Postfix: `mynetworks` — только доверенные подсети;
  `smtpd_relay_restrictions = permit_mynetworks,
  permit_sasl_authenticated, reject_unauth_destination`;
  `smtpd_helo_restrictions = reject_invalid_helo_hostname,
  reject_non_fqdn_helo_hostname`.
- Отключить `VRFY`/`EXPN`: `disable_vrfy_command = yes`.
- Submission-порт: обязательный STARTTLS и SASL, rate limiting,
  `permit_sasl_authenticated` только после аутентификации; fail2ban.
- Exchange: коннекторы Receive — `Anonymous` только для входящей
  внешней почты к валидным получателям вашего домена; запрет relay
  для внешних отправителей; отдельные коннекторы для приложений.
- SPF (жёсткий `-all`), DKIM, DMARC с политикой `reject`/`quarantine`
  и отчётами — обязательный минимум.
- Egress-фильтрация: блокировать исходящий 25/tcp со всех хостов,
  кроме почтовых серверов.
- Баннер: убрать версию (`smtpd_banner = $myhostname ESMTP`);
  регулярные обновления MTA.
- Периодическая проверка open relay и SPF/DKIM/DMARC-соответствия
  (автоматизированный чек в мониторинге).


## Detection rules

```yaml
title: "SMTP relay-злоупотребление: неаутентифицированная пересылка внешним получателям"
id: d4e5f6a7-0001-4d4e-8f5a-000000000301
status: experimental
description: >-
  В логах MTA появляются сообщения, принятые от внешнего клиента и адресованные
  внешнему получателю без аутентификации, либо аномальный всплеск исходящей почты.
references:
  - https://attack.mitre.org/techniques/T1114/002/
  - https://www.postfix.org/RESTRICTION_CLASS_README.html
logsource:
  product: linux
  service: mail
  definition: 'журнал MTA (Postfix/Sendmail) или Exchange SMTP-логи'
detection:
  unauthenticated_relay:
    process: postfix
    message|contains|all:
      - 'client='
      - 'relay='
    message|contains:
      - 'unknown['
  external_rcpt_burst:
    process: postfix
    message|contains: 'to=<'
  vrfy_probe:
    message|contains:
      - 'VRFY'
      - 'EXPN'
  auth_bruteforce:
    message|contains:
      - 'SASL authentication failed'
      - 'authentication failure'
  timeframe: 10m
  condition: unauthenticated_relay or vrfy_probe or (auth_bruteforce | count() by client_ip > 10) or (external_rcpt_burst | count() by client_ip > 200)
fields:
  - client_ip
  - message
  - queue_id
falsepositives:
  - легитимные relay-хосты и партнёрские маршруты (внесите в исключения по client_ip)
level: high
tags:
  - attack.initial_access
  - attack.t1114.002
```
