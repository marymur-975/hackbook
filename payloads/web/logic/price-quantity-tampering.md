---
id: logic-price-quantity-tampering
title: "Логика: подмена цены, количества и валюты в заказе"
type: logic
target: http
category: web
difficulty: beginner
bypass: none
tags: [business-logic, tampering, e-commerce, negative-values]
tested_on: ["типовые корзины в PHP/Node/Django", "платёжные интеграции"]
success_rate: 0.45
risk: high
cwe: "CWE-841"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
graph:
  - target: "business-logic"
    type: instance_of
  - target: "data-tampering"
    type: leads_to
  - target: "race-condition"
    type: related_to
---

# Логика: подмена цены, количества и валюты в заказе

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
{"items":[{"id":7,"qty":-3,"price":1}],"currency":"VND","coupon":"ONCE100"}
```

## Explanation

Класс бизнес-логики, который сканеры не находят вовсе: приложение доверяет
значениям, присланным клиентом.

| Поле | Что пробуют | Эффект |
|------|-------------|--------|
| `price`/`amount` | 1, 0, 0.01 | покупка за копейки |
| `qty`/`quantity` | -1, -100, 0 | отрицательная сумма = возврат денег |
| `total`/`subtotal` | своё значение | платёжный шлюз списывает меньше |
| `currency` | VND/IDR/CLP вместо USD | «100» в дешёвой валюте |
| `discount`/`coupon` | 100, 1.0, повторное применение | бесплатная покупка |
| `shipping` | -20 | компенсация стоимости товара |
| `id` товара | чужой/несуществующий | цена другого SKU |
| `weight`/`units` | дробные, NaN, Infinity | сбой расчёта |

Отрицательное количество — самый опасный вариант: часть платёжных систем
трактует его как возврат, и баланс продавца уходит в минус.
Форматы, которые стоит пробовать: `-1`, `--1`, `1e999`, `NaN`, `Infinity`,
`"1,000"` (запятая как разделитель), `0x1`, строки с пробелами.

## Detection

1. Соберите заказ и перехватите запрос: измените `qty` на -1, `price` на 0.01,
   `currency` на другую — сравните итог в ответе и в БД.
2. Проверьте серверный пересчёт: сумма должна считаться на сервере из каталога,
   а не приходить с клиента.
3. Протестируйте дробные/экспоненциальные/NaN значения и переполнения типов
   (int32 -> 2147483648).
4. Проверьте согласованность: заказ в БД vs платёжный запрос vs чек.
5. В логах: заказы с отрицательной суммой, аномальные скидки, разные валюты
   для одного товара.

## Remediation

- Цену, скидку и сумму **всегда** пересчитывать на сервере из каталога и
  правил акций; от клиента принимать только id товара и количество.
- Валидация: qty — целое, 1..N (лимит), price/total — не принимаются вовсе.
- Валюта и формат суммы фиксируются сервером; округление — в большую сторону
  для денег, работа в минорных единицах (копейки/центы), не float.
- Купон применяется атомарно (unique constraint на user_id+coupon_id),
  с проверкой лимитов и срока.
- Сверка с платёжным шлюзом по идемпотентному ключу; алерт на расхождение
  сумм и на отрицательные итоги.
- Автотесты на границах: 0, -1, MAX_INT, дробные, NaN, другие валюты.

## Variants

```
qty=-1
```

```
price=0
```

```
currency=VND
```

```
discount=1.0
```

```
total=0.01
```

## Detection rules

```yaml
title: Манипуляция ценой/количеством в заказе — отрицательные и нулевые значения
id: e5f6a7b8-0080-4e5f-9a7b-000000000080
status: experimental
description: >-
  В теле создания заказа встречаются отрицательные qty/price, нулевая цена,
  смена валюты или повторное применение одноразового купона. Сервер должен
  пересчитывать суммы сам — такие значения в запросе всегда аномалия.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/logic-flaws
logsource:
  category: application
  definition: 'логи приложения: события создания/изменения заказа с телом запроса'
detection:
  order_action:
    event_action:
      - order_create
      - cart_update
      - checkout
  tampering:
    request_body|contains:
      - '"qty":-'
      - '"qty":0'
      - '"price":0'
      - '"price":-'
      - '"amount":-'
      - '"discount":100'
  condition: order_action and tampering
fields:
  - source_ip
  - request_path
  - request_body
falsepositives:
  - возвраты и корректировки, где отрицательные qty легальны (они идут под другим
    event_action — выносите в фильтр)
level: high
tags:
  - attack.impact
  - attack.t1190
  - cwe.841
```
