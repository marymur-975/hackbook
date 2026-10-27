# payloads/web/detection — карточки детектирования

Это особый подвид карточек: вместо «как выполнить атаку» они отвечают на вопрос
**«как увидеть атаку в логах»**. Формат карточки сохранён полностью
(обязательные секции `Payload`, `Explanation`, `Detection`, `Remediation`),
но:

- в `Payload` — команды **воспроизведения трафика** в лаборатории
  (а не полезная нагрузка для внедрения);
- в конце добавлена секция `## Detection rules` с готовым Sigma-правилом;
- в front-matter стоит `tester: manual`: `payload-tester.sh` не может
  проверить такую карточку одним запросом, поэтому она помечается SKIP,
  а не FAIL.

## Как проверяются эти карточки

1. **Правило — на фикстурах** (быстро, в CI):

   ```bash
   python3 tools/detections-extract.py --check
   python3 tools/rules-tester.py --verbose
   ```

2. **Правило — на живом трафике лаборатории**:

   ```bash
   cd labs/setup && docker compose up -d vuln-hub
   # генерируем «атакующий» трафик по карточке
   ./tools/payload-tester.sh --lab vuln-hub
   # забираем журнал и ищем признаки, описанные в карточке
   python3 tools/lib/http_fetch.py http://localhost:8090/logs
   ```

3. **Сигнатуры — пакетно**: `wordlists/fuzzing/detection-signatures.txt`
   прогоняется через лабораторию, затем проверяется, что правила из
   `detections/` сработали, а WAF/фильтры — заблокировали.

## Состав

| Карточка                    | Класс           | Источник логов                      |
| --------------------------- | --------------- | ----------------------------------- |
| `webserver-sqli-signatures` | SQLi            | access-лог                          |
| `webserver-lfi-traversal`   | LFI / traversal | access-лог                          |
| `webserver-ssrf-metadata`   | SSRF / IMDS     | access-лог + сетевые логи           |
| `jwt-auth-anomalies`        | JWT / auth      | логи приложения                     |
| `xxe-doctype-in-request`    | XXE             | тело запроса / WAF / ошибки парсера |
| `stored-blind-xss-in-logs`  | XSS             | данные в БД + логи                  |
| `csv-formula-injection`     | экспорт отчётов | данные в БД / тело запроса          |
| `graphql-abuse-logs`        | GraphQL         | логи API-шлюза                      |

Все правила после извлечения попадают в `detections/web/` и `detections/application/` — см. [`detections/index.md`](../../../detections/index.md).
