---
id: http-race-condition-single-packet
title: "Race condition: single-packet attack и повторное использование купона"
type: http
target: http
category: web
difficulty: advanced
bypass: none
tags: [race-condition, logic, toctou, concurrency]
tested_on: ["single-packet attack (HTTP/2), Turbo Intruder"]
success_rate: 0.45
risk: high
cwe: "CWE-362"
lab: null
tester: manual
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/research/smashing-the-state-machine"
graph:
  - target: "headers"
    type: related_to
  - target: "race-condition"
    type: instance_of
  - target: "data-tampering"
    type: leads_to
  - target: "bruteforce"
    type: related_to
---

# Race condition: single-packet attack и повторное использование купона

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# HTTP/2: несколько запросов в ОДНОМ TCP-пакете
POST /apply-coupon  x30 (одновременно, один пакет)
coupon=ONCE100
```

## Explanation

Проверка и использование ресурса разделены во времени (TOCTOU). Если 20–50
параллельных запросов приходят **одновременно**, ни один не успевает увидеть
изменение состояния, сделанное другим, — и одноразовое ограничение нарушается.

Что ломается на практике:

- одноразовый промокод применяется N раз (вывод средств);
- лимит перевода/снятия превышается в N раз;
- gift card / баланс списывается один раз, а зачисляется N;
- выдача роли/доступа: параллельные запросы проходят проверку прав;
- регистрация одного e-mail несколько раз, обход 2FA (параллельные коды),
  обход rate limit (счётчик инкрементируется после проверки);
- «last-byte sync»: запросы удерживаются на последнем байте и отпускаются разом.

Ключ к надёжному воспроизведению — **single-packet attack** (HTTP/2): все запросы
помещаются в один TCP-пакет и обрабатываются сервером практически одновременно,
что устраняет сетевой джиттер. Для HTTP/1.1 используют connection pre-loading
и last-byte sync.

## Detection

1. Выберите операцию с одноразовым ограничением (купон, лимит, голос, заявка).
2. Burp Suite: Repeater -> вкладка групп -> «Send group (parallel)»,
   или Turbo Intruder с `engine=Engine.BURP2` и HTTP/2 single-packet.
3. 20–50 одинаковых запросов; проверьте итоговое состояние (баланс, число применений).
4. Косвенные признаки: отсутствие блокировок/транзакций в коде,
   `SELECT ... ; UPDATE ...` без `FOR UPDATE`/атомарного декремента.
Только на тестовом аккаунте и в лаборатории: на бою это финансовый ущерб.

## Remediation

- Атомарность на уровне данных: `UPDATE ... SET used=1 WHERE code=? AND used=0`
  и проверка числа затронутых строк; `SELECT ... FOR UPDATE`; уникальные
  ограничения (unique constraint на (user_id, coupon_id)).
- Идемпотентность: клиент присылает `Idempotency-Key`, сервер дедуплицирует.
- Оптимистичные блокировки (version/etag) для балансов и счётчиков.
- Rate limiting **до** бизнес-логики, с атомарным счётчиком (Redis INCR + TTL).
- Очередь с одним потребителем на ключ (user_id/код) для критичных операций.
- Тесты на конкурентность в CI (параллельные запросы в интеграционных тестах).
- Мониторинг аномалий: несколько применений одного купона за миллисекунды.

## Variants

```
last-byte sync (HTTP/1.1)
```

```
connection pre-loading + 30 соединений
```

## Detection rules

```yaml
title: Race condition — шквал одинаковых запросов от одного клиента
id: e5f6a7b8-0091-4e5f-9a7b-000000000091
status: experimental
description: >-
  Single-packet attack: десятки идентичных запросов (применение купона,
  списание бонусов, приглашения) приходят практически одновременно от одного
  IP. Признаки: count одинаковых запросов по c-ip и поле same_ts_requests
  в журнале шлюза.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/research/race-conditions-limit-overpassing
logsource:
  category: webserver
  definition: 'access-лог с меткой времени запроса + журнал шлюза (same_ts_requests)'
detection:
  selection_sensitive:
    cs-uri-query|contains:
      - 'coupon='
      - 'promo='
      - 'gift='
      - 'invite='
  gateway_burst:
    same_ts_requests|gte: 20
  condition: (selection_sensitive | count() by c-ip > 10) or gateway_burst
fields:
  - c-ip
  - cs-uri-stem
  - cs-uri-query
  - same_ts_requests
falsepositives:
  - ретраи клиентов при таймаутах (те же URL, но растянуты во времени —
    сравнивайте разброс ts внутри группы)
level: high
tags:
  - attack.impact
  - attack.t1190
  - cwe.362
```
