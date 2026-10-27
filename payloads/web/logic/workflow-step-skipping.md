---
id: logic-workflow-step-skipping
title: "Логика: пропуск шагов многоэтапного процесса"
type: logic
target: http
category: web
difficulty: intermediate
bypass: none
tags: [business-logic, workflow, authorization, state-machine]
tested_on: ["checkout-flow", "onboarding/KYC", "wizard-формы"]
success_rate: 0.5
risk: high
cwe: "CWE-841"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "business-logic"
    type: instance_of
  - target: "auth-bypass"
    type: related_to
  - target: "race-condition"
    type: related_to
---

# Логика: пропуск шагов многоэтапного процесса

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# пропуск шага оплаты: сразу на подтверждение
GET /checkout/confirm?order=1042 HTTP/1.1
Cookie: session=<обычная сессия>
```

## Explanation

Многоэтапные процессы (оформление заказа, KYC, подтверждение e-mail,
мастер настройки, возврат средств) часто реализованы как набор URL,
а состояние «какой шаг пройден» хранится **на клиенте** или не проверяется
на сервере. Отсюда:

- прямой переход на финальный шаг (`/checkout/confirm`, `/kyc/approve`,
  `/account/verify?done=1`) без предыдущих;
- изменение флага в скрытом поле/cookie/параметре (`step=3`, `paid=true`,
  `verified=1`);
- повторная отправка финального запроса (replay) — вторая выдача товара/бонуса;
- параллельные сессии: одна проходит проверку, вторая использует результат;
- откат на предыдущий шаг после подтверждения с изменёнными данными
  (цена пересчитывается, а факт подтверждения остаётся).

Корень проблемы — отсутствие серверной машины состояний: каждый эндпоинт
проверяет только аутентификацию, но не «разрешено ли это действие сейчас».

## Detection

1. Пройдите процесс легально, записывая все запросы (Burp/mitmproxy).
2. Повторите финальный запрос напрямую, без промежуточных шагов.
3. Поменяйте параметры состояния: `step`, `stage`, `paid`, `verified`,
   скрытые поля формы, cookie.
4. Отправьте финальный запрос дважды (replay) и проверьте, удвоился ли результат.
5. Попробуйте вернуться на шаг назад после подтверждения и изменить данные.
6. В логах: заказы, созданные без промежуточных событий; дубли финальных событий.

## Remediation

- Серверная машина состояний: у заказа/KYC-заявки есть поле `status`,
  каждый эндпоинт проверяет допустимый переход (`pending -> paid -> shipped`)
  и отклоняет недопустимые.
- Идентификатор процесса — серверный (не `step` из клиента); клиентские флаги
  не влияют на логику.
- Идемпотентность финальных операций: уникальный ключ операции, unique constraint,
  `ON CONFLICT DO NOTHING`.
- Транзакционность: списание, выдача и смена статуса — одна транзакция.
- Пересчёт всех сумм/условий при любом изменении данных, инвалидация
  предыдущих подтверждений.
- Аудит-лог переходов состояния + алерты на «прыжки».
- Тесты: пропуск шагов, replay, параллельные сессии, откат после подтверждения.

## Variants

```
?paid=true
```

```
?step=4
```

```
скрытое поле verified=1
```

```
replay POST /confirm
```

## Detection rules

```yaml
title: Пропуск шага workflow — подтверждение неоплаченного заказа
id: e5f6a7b8-0081-4e5f-9a7b-000000000081
status: experimental
description: >-
  Событие подтверждения/завершающего шага приходит при payment_status=unpaid
  (или без предшествующего события оплаты того же order_id). Прямой запрос
  /checkout/confirm в обход /checkout/pay — признак перескока через шаг workflow.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: application
  definition: 'логи приложения: события шагов checkout с order_id и payment_status'
detection:
  selection:
    event_action:
      - checkout_confirm
      - order_finalize
      - subscription_activate
  unpaid:
    payment_status:
      - unpaid
      - pending
      - ''
  condition: selection and unpaid
fields:
  - source_ip
  - request_path
  - order_id
  - payment_status
falsepositives:
  - оплата при получении (payment_status=pending легален для таких товаров —
    сверяйте с типом оплаты заказа)
level: high
tags:
  - attack.impact
  - attack.t1190
  - cwe.841
```
