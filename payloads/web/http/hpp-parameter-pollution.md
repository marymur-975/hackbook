---
id: http-hpp-parameter-pollution
title: "HTTP parameter pollution: рассинхрон между слоями"
type: http
target: http
category: web
difficulty: intermediate
bypass: waf
tags: [hpp, parameter-pollution, waf-bypass]
tested_on: ["PHP", "ASP.NET", "Express", "Spring", "Django"]
success_rate: 0.4
risk: medium
cwe: "CWE-235"
lab: null
last_verified: "2026-10-23"
references:
  - "https://owasp.org/www-project-web-security-testing-guide/"
graph:
  - target: "waf-bypass"
    type: technique_of
  - target: "headers"
    type: related_to
  - target: "auth-bypass"
    type: leads_to
---

# HTTP parameter pollution: рассинхрон между слоями

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
/transfer?amount=1&amount=10000&to=friend
```

## Explanation

Разные стеки по-разному обрабатывают повторяющиеся параметры:

| Стек | `?a=1&a=2` |
|------|------------|
| PHP (`$_GET`) | последнее значение (`2`) |
| ASP.NET | список/склейка через запятую |
| Express (`req.query`) | последнее (или массив при `extended`) |
| Spring | первое значение |
| Django | последнее |
| nginx/WAF при нормализации | часто первое |

Отсюда три практических следствия:

1. **Обход валидации/WAF**: проверка видит `amount=1`, бизнес-логика — `amount=10000`.
2. **Обход фильтра сигнатур**: `?id=1&id=' OR '1'='1` — WAF проверяет первый,
   приложение берёт второй.
3. **Логические ошибки**: разные модули приложения читают разные значения
   (платёжный шлюз и учёт заказов).

Родственный класс — **parameter cloaking**: `?a=1;b=2` (некоторые парсеры считают `;`
разделителем), `?a[]=1&a=2`, `?a=1%26b=2` (декодирование `&` на втором проходе).

## Detection

1. Отправьте `?test=1&test=2` и найдите, какое значение отразилось в ответе.
2. Сравните поведение WAF/валидатора и приложения на дублированном параметре.
3. Проверьте разделители: `;`, `%3b`, `%26`, `[]`.
4. Burp: «Parameter Pollution»-расширение, ручная матрица «параметр × дубликат».

## Remediation

- Явно решать, что делать с дубликатами: отклонять (400) или брать первое значение
  **одинаково во всех слоях** (WAF, gateway, приложение).
- Нормализовать query-строку на границе до передачи в приложение.
- Валидировать данные там, где они используются, а не только на входе.
- Схемы запросов (OpenAPI/JSON Schema) с `allowReserved: false` и запретом
  повторяющихся параметров, где они не предусмотрены.
- Тесты в CI на дубликаты и нестандартные разделители.

## Variants

```
?id=1&id=2
```

```
?id=1;id=2
```

```
?id[]=1&id=2
```

```
?id=1%26admin=true
```

## Detection rules

```yaml
title: HTTP parameter pollution — дубли параметров в одном запросе
id: e5f6a7b8-0086-4e5f-9a7b-000000000086
status: experimental
description: >-
  Один и тот же параметр встречается в запросе два и более раза (amount=1&
  amount=10000): фронтенд и бэкенд (или WAF и приложение) берут разные
  значения — обход валидации и лимитов.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: proxy
  definition: 'журнал шлюза со счётчиком дублирующихся параметров (duplicate_params)'
detection:
  selection:
    duplicate_params|gte: 2
  filter_search:
    path|contains:
      - '/search'
      - '/catalog/filter'
  condition: selection and not filter_search
fields:
  - source_ip
  - method
  - path
  - query
  - duplicate_params
falsepositives:
  - фильтры каталогов, легитимно передающие повторяющиеся параметры (facet-поиск)
    — вынесены в filter_search, дополняйте своими путями
level: medium
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.235
```
