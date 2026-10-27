---
name: Новая карточка payload'а
about: Предложить технику для базы payload'ов
title: "[payload] <тип>: <краткое название>"
labels: [payload, triage]
---

## Тип и цель

* **type**: `sqli` | `xss` | `ssrf` | `lfi` | `rfi` | `xxe` | `cmdi` | `ssti` |
  `auth-bypass` | `header` | `network` | `cloud`
* **target**: (СУБД / ОС / сервис / `generic`)
* **category**: `web` | `network` | `active-directory` | `cloud` | `privilege-escalation`
* **difficulty**: `beginner` | `intermediate` | `advanced` | `expert`
* **CWE**: CWE-NNN

## Payload

```
<каноническая нагрузка>
```

## Где проверяли (`tested_on`)

Версии, окружение, лаборатория:

- [ ] лаборатории `hackbook` (какая именно)
- [ ] свой локальный стенд
- [ ] CTF / учебная площадка
- [ ] авторизованный тест на проникновение

## Почему работает (Explanation)

## Как детектировать (Detection)

Признаки в ответе / логах / SIEM:

## Как чинить (Remediation)

## Вариации и обходы

## Чек-лист перед PR

- [ ] Карточка создана из `payloads/templates/payload-template.md`
- [ ] Все обязательные поля front-matter заполнены
- [ ] Секции `Payload`, `Explanation`, `Detection`, `Remediation` на месте
- [ ] `tested_on` отражает реальную проверку
- [ ] Указаны рёбра `graph` (куда техника ведёт)
- [ ] `python tools/validate-payloads.py --strict` — без ошибок
- [ ] `python tools/graph-generator.py --pretty` выполнен, `graph.json` обновлён
- [ ] Нет готового вредоносного кода, реальных секретов и данных третьих лиц
