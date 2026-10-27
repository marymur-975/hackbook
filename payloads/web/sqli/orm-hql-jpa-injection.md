---
id: sqli-orm-hql-jpa-injection
title: "SQLi в ORM: HQL/JPQL, Entity Framework, Sequelize, Prisma, ActiveRecord"
type: sqli
target: generic
category: web
difficulty: advanced
bypass: none
tags: [sqli, orm, hql, jpql, jpa, sequelize, prisma, activerecord, django-orm]
tested_on: ["Hibernate/JPA", "Sequelize", "Django ORM", "ActiveRecord (стенды в контейнерах)"]
success_rate: 0.45
risk: high
cwe: "CWE-89"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# SQLi в ORM: HQL/JPQL, Entity Framework, Sequelize, Prisma, ActiveRecord

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# ── HQL / JPQL (Hibernate) ─────────────────────────────────────────
# динамическая конкатенация в HQL — та же инъекция, но на уровне сущностей
# уязвимый код: String hql = "FROM User u WHERE u.name = '" + name + "'";
' OR '1'='1
' OR 1=1--
# перечисление через функции HQL (зависит от диалекта и прав)
' AND (SELECT COUNT(*) FROM User)>0--
# HQL-специфика: имена сущностей и свойств, а не таблиц и колонок;
# вызовы Java-методов (query passthrough), функции СУБД доступны

# ── Django ORM ─────────────────────────────────────────────────────
# уязвимо: Model.objects.extra(where=["name = '%s'" % name])
# уязвимо: Model.objects.raw("SELECT * FROM t WHERE name='" + name + "'")
# уязвимо: .filter(**json.loads(user_input))  -> инъекция имён полей и операторов
' OR 1=1--
# атакующий управляет ключами фильтра: {"name__startswith": "", "id__gt": 0}

# ── Sequelize (Node.js) ────────────────────────────────────────────
# уязвимо: sequelize.query("SELECT * FROM users WHERE name = '" + name + "'")
# уязвимо: операторные объекты из JSON-тела: {"name": {"$ne": null}}
# уязвимо: order/limit из запроса без whitelist:
#   Model.findAll({ order: [[req.query.sort, req.query.dir]] })
#   -> sort=1) UNION SELECT ... --

# ── Prisma ─────────────────────────────────────────────────────────
# уязвимо: prisma.$queryRawUnsafe(`SELECT * FROM User WHERE name = '${name}'`)
# уязвимо: $executeRawUnsafe, а также динамические orderBy без whitelist

# ── ActiveRecord (Rails) ───────────────────────────────────────────
# уязвимо: User.where("name = '#{params[:name]}'")
# уязвимо: User.order(params[:sort])           # ORDER BY не параметризуется
# уязвимо: User.pluck(params[:field])          # имя колонки из запроса
# безопасно: User.where(name: params[:name])

# ── Entity Framework (.NET) ────────────────────────────────────────
# уязвимо: ctx.Database.SqlQuery<User>($"SELECT * FROM Users WHERE Name='{name}'")
# уязвимо: FromSqlRaw с интерполяцией вместо FromSqlInterpolated
# безопасно: ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name={name}")

# ── JPA Criteria / Specification ───────────────────────────────────
# уязвимо: Specification с динамическим именем атрибута из запроса
#   root.get(userSuppliedAttributeName) -> доступ к любым полям сущности
```

## Explanation

ORM создают ложное ощущение безопасности: «мы же не пишем SQL».
Инъекция остаётся в четырёх типовых местах:

1. **Сырые запросы** (`raw()`, `$queryRawUnsafe`, `FromSqlRaw`,
    `createNativeQuery`, `SqlQuery`) с конкатенацией строк. Это обычный
    SQLi, просто написанный «рядом с ORM».
2. **Динамический HQL/JPQL**: язык запросов поверх сущностей, но
    конкатенация строк даёт ту же инъекцию. Особенность: оперируете
    именами сущностей/свойств, а не таблиц; иногда доступны вызовы
    функций СУБД и (в старых версиях Hibernate) passthrough к JDBC.
3. **Динамические имена полей, сортировка и лимиты**: `ORDER BY`,
    `GROUP BY`, `pluck`, `select`, `orderBy` — позиции, где параметризация
    неприменима (имя колонки нельзя передать как bind-параметр).
    Нужен строгий whitelist допустимых имён и направлений сортировки.
4. **Объектные операторы из JSON**: в API, принимающих тело вроде
    `{"name": {"$ne": null}}` (Mongo/Sequelize-стиль), атакующий
    управляет не только значением, но и оператором. Отдельный класс —
    инъекция в имена полей при `filter(**user_json)` в Django.

Практические выводы:

* параметризация решает 1–2, но не 3 (whitelist имён) и не 4
  (контроль структуры входа);
* `ORDER BY ${req.query.sort}` — самая частая находка в ревью
  Node.js/PHP-приложений;
* в Hibernate/JPA `setParameter`/`TypedQuery` обязательны; `createQuery`
  со склейкой — красный флаг на ревью;
* в EF использовать `FromSqlInterpolated`, а не `FromSqlRaw`;
* в Prisma — `$queryRaw` с теговым шаблоном (он параметризуется),
  а не `*Unsafe`.

## Detection

* Логи SQL ORM: Hibernate `show_sql`/`log_statement`, Django
  `LOGGING` для `django.db.backends`, Rails `ActiveRecord` logger,
  EF `EnableSensitiveDataLogging` (только в dev!). Ищите запросы
  с «встроенными» значениями вместо bind-параметров — признак
  динамической склейки.
* Алерт на ошибки ORM в проде: `QuerySyntaxException`,
  `SQLGrammarException`, `ProgrammingError`, `syntax error at or near`.
* WAF-правила на JSON-тела с операторами (`$ne`, `$gt`, `$regex`,
  `__gt`, `__startswith` в неожиданных местах).
* Детект аномальных `ORDER BY`/`GROUP BY` значений в параметрах запроса
  (`sort=`, `orderBy=`, `dir=`).
* Логи медленных запросов: инъекции часто дают тяжёлые запросы
  (подзапросы, `COUNT(*)`).
* SAST-правила: поиск `raw(`, `$queryRawUnsafe`, `FromSqlRaw`,
  `createQuery` со склейкой, `order(params[...])`, `extra(where=[`.

## Remediation

- Запретить конкатенацию в запросах: код-ревью чек-лист + SAST-правила
  на `raw`/`Unsafe`/`FromSqlRaw`/`extra(where=)`/`createQuery`.
- Всегда bind-параметры: `setParameter`, `?`, `$1`, `:name`;
  в EF — `FromSqlInterpolated`, в Prisma — `$queryRaw` с шаблоном.
- Для `ORDER BY`/`GROUP BY`/имён полей — whitelist-словарь
  (`ALLOWED_SORT = {'created_at', 'name'}`), никакого пропуска
  пользовательской строки.
- Ограничить структуру входящего JSON: схема (JSON Schema/Pydantic/zod),
  запрет операторных объектов; не передавать пользовательский dict
  в `filter(**...)` напрямую.
- Минимальные права учётки приложения; отдельные учётки для чтения/записи.
- Отключить вывод ошибок СУБД/ORM клиенту; централизованное логирование.
- Тесты: негативные кейсы в интеграционных тестах (инъекционные строки
  в каждом параметре поиска/сортировки).
- Обновлять ORM: часть техник (passthrough к JDBC, вызовы функций)
  закрыта в новых версиях.

## Detection rules

```yaml
title: HQL/JPQL-инъекция — ошибки Hibernate QuerySyntaxException
id: e5f6a7b8-0035-4e5f-9a7b-000000000035
status: experimental
description: >-
  ORM-слой падает с QuerySyntaxException/unexpected token — пользовательские
  данные конкатенируются в HQL/JPQL. Маркеры сущностей (FROM User u WHERE)
  в теле запроса усиливают сигнал.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: application
  definition: 'логи Java-приложения с ошибками ORM и телом запроса'
detection:
  orm_error:
    error_message|contains:
      - 'QuerySyntaxException'
      - 'org.hibernate.hql'
      - 'unexpected token ['
      - 'javax.persistence.PersistenceException'
  entity_marker:
    request_body|contains:
      - 'FROM User u WHERE'
      - 'FROM users u WHERE'
      - 'SELECT COUNT(*) FROM User'
  condition: orm_error or entity_marker
fields:
  - source_ip
  - request_path
  - request_body
  - error_message
falsepositives:
  - баги самих HQL-шаблонов приложения (ошибка без внешнего воздействия —
    сверяйте с релизами)
level: medium
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.89
```
