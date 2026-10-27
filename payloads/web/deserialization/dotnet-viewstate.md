---
id: deserialization-dotnet-viewstate
title: ".NET: ViewState и ObjectStateFormatter (MAC off)"
type: deserialization
target: dotnet
category: web
difficulty: advanced
bypass: none
tags: [deserialization, dotnet, viewstate, rce]
tested_on: ["ASP.NET WebForms", "ObjectStateFormatter", "ysoserial.net-класс"]
success_rate: 0.35
risk: critical
cwe: "CWE-502"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/deserialization/exploiting"
graph:
  - target: "deserialization"
    type: instance_of
  - target: "rce"
    type: leads_to
  - target: "csrf"
    type: related_to
---

# .NET: ViewState и ObjectStateFormatter (MAC off)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
__VIEWSTATE=/wEPDwUK…   # base64; при отсутствии MAC — управляемое содержимое
```

## Explanation

ASP.NET WebForms хранит состояние страницы в скрытом поле `__VIEWSTATE`
(сериализованный объект в base64). Если проверка целостности отключена или
ключ известен, поле можно подделать:

- `enableViewStateMac=false` (историческая конфигурация) — MAC не проверяется;
- `machineKey` утёк (web.config, публичные репозитории, дефолтные ключи
  в примерах документации) — MAC можно пересчитать;
- `ObjectStateFormatter`/`LosFormatter` без валидации — десериализация
  приводит к gadget-цепочке и RCE (TypeConfuseDelegate, ActivitySurrogateSelector).

Признаки WebForms в трафике: `__VIEWSTATE`, `__VIEWSTATEGENERATOR`,
`__EVENTVALIDATION`, заголовок `X-AspNet-Version`, cookie `ASP.NET_SessionId`.

Готовые цепочки эксплуатации (ysoserial-гаджеты, шеллкод, обфускация) в проекте
не публикуются: карточка описывает **механизм**, признаки и способы защиты.
Для практики используйте лабораторию с известным уязвимым приложением и
публичный инструментарий в изолированной сети.

## Detection

1. Найдите `__VIEWSTATE` в формах; декодируйте base64 и посмотрите структуру.
2. Измените байт в середине значения: ошибка `Validation of viewstate MAC failed`
   = MAC включён (хорошо); `The state information is invalid` без упоминания MAC —
   возможно, MAC выключен.
3. Burp-расширение «ViewState» показывает, есть ли MAC и подписано ли значение.
4. Проверьте, не утёк ли `machineKey` (поиск по репозиториям, конфиги в артефактах).
5. В логах: `HttpException: Validation of viewstate MAC failed`,
   `System.Runtime.Serialization.SerializationException`.

## Remediation

- `enableViewStateMac=true` (по умолчанию в современных версиях; патч MS14-059
  и бюллетени 2020 г. сделали отключение невозможным — обновите платформу).
- Уникальный `machineKey` на приложение, хранение в Key Vault/DPAPI,
  ротация; никогда не в репозитории.
- Миграция с WebForms (платформа не развивается) или минимум —
  `ViewStateUserKey` для привязки к сессии (защита от CSRF на ViewState).
- Отключить ViewState там, где он не нужен (`EnableViewState=false` на контролах).
- WAF-правила на аномальный `__VIEWSTATE`, мониторинг ошибок MAC.
- .NET ≥ 4.8 + актуальные патчи; `LosFormatter` не использовать с недоверенными данными.

## Detection rules

```yaml
title: ASP.NET ViewState — подделка состояния при отключённой MAC-валидации
id: e5f6a7b8-0109-4e5f-9a7b-000000000109
status: experimental
description: >-
  Запросы с __VIEWSTATE, которые падают с «state information is invalid»,
  или предупреждения о отключённой MAC-валидации — признак эксплуатации
  ViewState (вплоть до RCE через известные гаджеты при known machineKey).
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff649351(v=pandp.10)
logsource:
  category: application
  definition: 'логи ASP.NET-приложения: тело POST и ошибки ViewState'
detection:
  viewstate_marker:
    request_body|contains: '__VIEWSTATE'
  tamper_error:
    error_message|contains:
      - 'state information is invalid'
      - 'Validation of viewstate MAC failed'
      - 'ViewStateException'
      - 'MAC validation'
  condition: viewstate_marker and tamper_error
  # примечание: сам по себе __VIEWSTATE нормален для WebForms — детектируем
  # только сочетание с ошибкой валидации
fields:
  - source_ip
  - request_path
  - error_message
falsepositives:
  - протухшие страницы после деплоя (однократные ошибки у легитимных пользователей;
    серия от одного IP — атака)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.502
```
