---
id: http-web-cache-deception
title: "Web cache deception: кеш сохраняет приватный ответ"
type: http
target: http
category: web
difficulty: advanced
bypass: none
tags: [cache-deception, cdn, path-confusion, info-disclosure]
tested_on: ["CDN + приложение с роутингом по расширениям"]
success_rate: 0.3
risk: high
cwe: "CWE-525"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/web-cache-deception"
graph:
  - target: "cache-poisoning"
    type: related_to
  - target: "info-disclosure"
    type: leads_to
  - target: "headers"
    type: related_to
---

# Web cache deception: кеш сохраняет приватный ответ

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
/account/settings/nonexistent.css
```

## Explanation

Обратная задача: не отравить кеш для всех, а заставить кеш **сохранить
приватный ответ** и отдать его атакующему. Механизм — рассинхрон в понимании пути:

- CDN решает кешировать по расширению (`.css`, `.js`, `.png`, `.ico`)
  и игнорирует `Cache-Control: private`;
- приложение (фреймворк) отбрасывает последний сегмент пути и отдаёт
  страницу `/account/settings` с персональными данными.

Атакующий присылает жертве ссылку `/account/settings/x.css`; браузер жертвы
делает GET, CDN кеширует приватный ответ; затем атакующий запрашивает тот же URL
и читает данные жертвы. Работают также разделители `;`, `%2f`, `%3b`, `..`,
точка в конце, двойные слеши и query-строка `?x=.css`.

## Detection

1. Возьмите приватный URL (профиль, настройки, баланс) и добавьте к нему
   `/x.css`, `/x.png`, `;.css`, `%2e%2e/x.css`.
2. Ответ вернулся с данными и заголовком `X-Cache: HIT` / `Age: >0` — уязвимость.
3. Проверьте `Cache-Control` ответа: если сервер говорит `private`, а кеш
   всё равно отдаёт HIT — рассинхрон.
4. Инструменты: `web-cache-deception-scanner` (Burp BApp), ручная матрица
   «приватный путь × разделитель × расширение».

## Remediation

- CDN: кешировать только по явному `Cache-Control: public` + точному пути
  (без «расширение значит статика»); нормализовать путь до решения о кешировании.
- Приложение: отдавать 404 на несуществующие пути, не «проглатывать» лишний сегмент
  (строгий роутинг); запретить `;`-параметры и двойные слеши.
- Персонализированные ответы: `Cache-Control: private, no-store` **и** `Vary: Cookie`.
- Аутентифицированные страницы не должны попадать в общий кеш:
  separate origin/hostname или правило «не кешировать при наличии Cookie».
- Тестировать матрицу разделителей в CI.

## Detection rules

```yaml
title: Web cache deception — аутентифицированный динамический ответ закэширован как статика
id: e5f6a7b8-0095-4e5f-9a7b-000000000095
status: experimental
description: >-
  Запрос к персональному пути (/account/...) с «статическим» хвостом
  (nonexistent.css) возвращает 200 и попадает в кэш (HIT) вместе с сессией
  пользователя. Жертву провоцируют перейти по ссылке, атакующий забирает
  кэш с её данными.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://portswigger.net/web-security/web-cache-deception
logsource:
  category: proxy
  definition: 'журнал кэширующего прокси: cache_status, путь, признак сессии'
detection:
  cache_hit:
    cache_status: HIT
  static_ext:
    path|endswith:
      - '.css'
      - '.js'
      - '.png'
      - '.jpg'
      - '.ico'
      - '.woff'
      - '.gif'
  filter_anonymous:
    session_user: ''
  filter_static_dir:
    path|contains:
      - '/static/'
      - '/assets/'
      - '/media/'
  condition: cache_hit and static_ext and not filter_anonymous and not filter_static_dir
fields:
  - source_ip
  - path
  - cache_status
  - session_user
falsepositives:
  - реально статические файлы вне /static/ (favicon.ico в корне) — добавляйте
    их в filter_static_dir
level: high
tags:
  - attack.collection
  - attack.t1190
  - cwe.525
```
