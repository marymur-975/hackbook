# Каталог детект-правил hackbook

Сгенерировано `tools/detections-extract.py` 2026-10-23. Источник правды — секция `Detection rules` в карточках `payloads/**`.

Правил: **180** в 8 категориях. Карточек с правилами: **178** из 178.

Проверка правил на фикстурах: `python tools/rules-tester.py`.

## application (66)

| Правило | ID | Уровень | Карточка | Статус |
|---------|----|---------|----------|--------|
| ASP.NET ViewState — подделка состояния при отключённой MAC-валидации | `e5f6a7b8-0109…` | high | [deserialization-dotnet-viewstate](../payloads/web/deserialization/dotnet-viewstate.md) | experimental |
| Blind XXE — параметрическая сущность с внешней DTD (OOB-канал) | `e5f6a7b8-0002…` | high | [xxe-blind-oob-exfiltration](../payloads/web/xxe/blind-oob-exfiltration.md) | experimental |
| DOM XSS — payload в location.hash (клиентская телеметрия) | `e5f6a7b8-0047…` | medium | [xss-dom-location-hash](../payloads/web/xss/dom-location-hash.md) | experimental |
| Error-based XXE — содержимое файла уходит в сообщении об ошибке | `e5f6a7b8-0003…` | high | [xxe-error-based-entity](../payloads/web/xxe/error-based-entity.md) | experimental |
| Fastjson/Jackson autoType — JNDI-гаджеты в JSON-теле запроса | `e5f6a7b8-0110…` | critical | [deserialization-fastjson-jackson-autotype](../payloads/web/deserialization/fastjson-jackson-autotype.md) | experimental |
| First-order маркеры — SQL-синтаксис сохраняется в пользовательских данных | `e5f6a7b8-0040…` | high | [sqli-second-order-stored](../payloads/web/sqli/second-order-stored.md) | experimental |
| Freemarker SSTI — Execute/ProcessBuilder через reflection | `e5f6a7b8-0008…` | high | [ssti-java-freemarker-reflection](../payloads/web/ssti/java-freemarker-reflection.md) | experimental |
| GraphQL-злоупотребление — глубина, алиасы и батчинг запросов | `e5f6a7b8-0079…` | medium | [logic-graphql-introspection-batching](../payloads/web/logic/graphql-introspection-batching.md) | experimental |
| HQL/JPQL-инъекция — ошибки Hibernate QuerySyntaxException | `e5f6a7b8-0035…` | medium | [sqli-orm-hql-jpa-injection](../payloads/web/sqli/orm-hql-jpa-injection.md) | experimental |
| IDOR — успешный доступ к чужим объектам по последовательным id | `e5f6a7b8-0104…` | high | [auth-bypass-idor-sequential-ids](../payloads/web/auth-bypass/idor-sequential-ids.md) | experimental |
| JNDI/RMI-инъекция — lookup на внешний LDAP/RMI и ${jndi:} в параметрах | `e5f6a7b8-0115…` | critical | [deserialization-rmi-jmx-jndi](../payloads/web/deserialization/rmi-jmx-jndi.md) | experimental |
| JWT RS2HS — HMAC-подпись токена проверяется публичным RSA-ключом | `e5f6a7b8-0087…` | critical | [auth-bypass-jwt-confused-alg-rs2hs](../payloads/web/http/jwt-confused-alg-rs2hs.md) | experimental |
| JWT alg=none — токен без подписи принимается сервисом | `e5f6a7b8-0105…` | critical | [auth-bypass-jwt-alg-none](../payloads/web/auth-bypass/jwt-alg-none.md) | experimental |
| JWT kid-инъекция — traversal/SQL/команды в идентификаторе ключа | `e5f6a7b8-0088…` | critical | [auth-bypass-jwt-kid-injection](../payloads/web/http/jwt-kid-injection.md) | experimental |
| Java-десериализация — нативный поток (rO0AB/aced0005) во входящих данных | `e5f6a7b8-0111…` | critical | [deserialization-java-native-gadget](../payloads/web/deserialization/java-native-gadget.md) | experimental |
| Log forging — CRLF внутри лог-записи приложения | `e5f6a7b8-0082…` | medium | [http-crlf-log-forging](../payloads/web/http/crlf-log-forging.md) | experimental |
| MSSQL error-based — CONVERT(int, ...) выводит данные в тексте ошибки | `e5f6a7b8-0020…` | high | [sqli-mssql-error-based-convert](../payloads/web/sqli/mssql-error-based-convert.md) | experimental |
| MSSQL — снятие версии и контекста (@@version, DB_NAME, SUSER_SNAME) | `e5f6a7b8-0021…` | medium | [sqli-mssql-version-banner](../payloads/web/sqli/mssql-version-banner.md) | experimental |
| Mutation XSS — «безопасный» экранированный тег в контейнере-мутаторе | `e5f6a7b8-0049…` | medium | [xss-mutation-xss](../payloads/web/xss/mutation-xss.md) | experimental |
| MySQL LOAD_FILE/INTO OUTFILE — чтение файлов и запись webshell | `e5f6a7b8-0025…` | critical | [sqli-mysql-file-read-write](../payloads/web/sqli/mysql-file-read-write.md) | experimental |
| MySQL error-based — EXTRACTVALUE/UPDATEXML/floor-rand в параметрах и ошибках | `e5f6a7b8-0024…` | high | [sqli-mysql-error-based-extractvalue](../payloads/web/sqli/mysql-error-based-extractvalue.md) | experimental |
| NoSQL — JavaScript-инъекция через $where (time-based и логические бомбы) | `e5f6a7b8-0076…` | critical | [nosql-mongodb-where-js](../payloads/web/nosql/mongodb-where-js.md) | experimental |
| NoSQL-инъекция — операторы MongoDB в пользовательских данных | `e5f6a7b8-0074…` | high | [nosql-mongodb-operator-injection](../payloads/web/nosql/mongodb-operator-injection.md) | experimental |
| OAuth — обход валидации redirect_uri (traversal, поддомены, open redirect) | `e5f6a7b8-0089…` | critical | [auth-bypass-oauth-redirect-uri-bypass](../payloads/web/http/oauth-redirect-uri-bypass.md) | experimental |
| Oracle error-based — CTXSYS/DBMS_UTILITY/UTL_INADDR и v$version | `e5f6a7b8-0034…` | high | [sqli-oracle-error-based](../payloads/web/sqli/oracle-error-based.md) | experimental |
| PHP-десериализация — сериализованные объекты (O:N:) во входящих данных | `e5f6a7b8-0113…` | high | [deserialization-php-unserialize-pop](../payloads/web/deserialization/php-unserialize-pop.md) | experimental |
| PostgreSQL COPY TO/FROM PROGRAM — выполнение команд сервером БД | `e5f6a7b8-0037…` | critical | [sqli-postgresql-copy-program](../payloads/web/sqli/postgresql-copy-program.md) | experimental |
| PostgreSQL error-based — CAST((SELECT version()) AS INT) в параметрах и ошибках | `e5f6a7b8-0038…` | high | [sqli-postgresql-error-based-cast](../payloads/web/sqli/postgresql-error-based-cast.md) | experimental |
| PostgreSQL time-based — pg_sleep/generate_series в параметрах и журнале БД | `e5f6a7b8-0036…` | medium | [sqli-postgresql-boolean-sleep](../payloads/web/sqli/postgresql-boolean-sleep.md) | experimental |
| Prototype pollution — __proto__/constructor.prototype в JSON и query | `e5f6a7b8-0112…` | high | [deserialization-nodejs-prototype-pollution](../payloads/web/deserialization/nodejs-prototype-pollution.md) | experimental |
| Python pickle во входящих данных — опкоды и ошибки восстановления классов | `e5f6a7b8-0114…` | critical | [deserialization-python-pickle](../payloads/web/deserialization/python-pickle.md) | experimental |
| SQL-проба HAVING/GROUP BY — ошибка группировки раскрывает схему | `e5f6a7b8-0018…` | medium | [sqli-generic-having-group-by-error](../payloads/web/sqli/generic-having-group-by-error.md) | experimental |
| SQLite — перечисление схемы через sqlite_master и json_extract | `e5f6a7b8-0041…` | medium | [sqli-sqlite-json-extract](../payloads/web/sqli/sqlite-json-extract.md) | experimental |
| SSRF через цепочку редиректов — белый домен ведёт на внутренний адрес | `e5f6a7b8-0073…` | high | [ssrf-redirect-chain-bypass](../payloads/web/ssrf/redirect-chain-bypass.md) | experimental |
| Second-order SQLi — сохранённое значение срабатывает в другом запросе | `e5f6a7b8-0029…` | high | [sqli-mysql-second-order](../payloads/web/sqli/mysql-second-order.md) | experimental |
| Stacked queries — второй запрос через точку с запятой | `e5f6a7b8-0030…` | high | [sqli-mysql-stacked-queries](../payloads/web/sqli/mysql-stacked-queries.md) | experimental |
| Stored XSS в профиле/комментариях — обработчики событий в сохраняемых данных | `e5f6a7b8-0052…` | high | [xss-stored-in-profile](../payloads/web/xss/stored-in-profile.md) | experimental |
| Stored XSS через загруженный SVG — onload/script внутри «картинки» | `e5f6a7b8-0060…` | high | [upload-svg-stored-xss](../payloads/web/upload/svg-stored-xss.md) | experimental |
| Twig/Smarty SSTI — вызов системных функций из шаблона | `e5f6a7b8-0009…` | high | [ssti-php-twig-smarty](../payloads/web/ssti/php-twig-smarty.md) | experimental |
| UNION-перечисление схемы — information_schema/table_schema в параметрах | `e5f6a7b8-0033…` | high | [sqli-mysql-union-select-enumeration](../payloads/web/sqli/mysql-union-select-enumeration.md) | experimental |
| XInclude — подключение локального файла из XML-фрагмента | `e5f6a7b8-0006…` | high | [xxe-xinclude-fragment](../payloads/web/xxe/xinclude-fragment.md) | experimental |
| XML-бомба (billion laughs) — аномальный парсинг с раскрытием сущностей | `e5f6a7b8-0004…` | medium | [xxe-param-entity-dos](../payloads/web/xxe/param-entity-dos.md) | experimental |
| XStream-гаджеты — dynamic-proxy и опасные классы в входящем XML | `e5f6a7b8-0116…` | high | [deserialization-xstream-xml](../payloads/web/deserialization/xstream-xml.md) | experimental |
| XXE через загруженный SVG — DOCTYPE и сущности в «изображении» | `e5f6a7b8-0005…` | high | [xxe-svg-upload-vector](../payloads/web/xxe/svg-upload-vector.md) | experimental |
| XXE — чтение локальных файлов через внешнюю сущность | `e5f6a7b8-0001…` | high | [xxe-basic-external-entity](../payloads/web/xxe/basic-external-entity.md) | experimental |
| YAML unsafe load — python-теги (!!python/object) во входящем YAML | `e5f6a7b8-0117…` | high | [deserialization-yaml-unsafe-load](../payloads/web/deserialization/yaml-unsafe-load.md) | experimental |
| Zip Slip — запись файлов вне каталога при распаковке архива | `e5f6a7b8-0061…` | high | [upload-zip-slip-archive](../payloads/web/upload/zip-slip-archive.md) | experimental |
| Аномалии валидации JWT (подделка токена или подбор секрета) | `b2c3d4e5-0004…` | high | [detection-jwt-auth-anomalies](../payloads/web/detection/jwt-auth-anomalies.md) | experimental |
| Вход с дефолтными учётными данными (admin:admin и типовые пары) | `e5f6a7b8-0103…` | critical | [auth-bypass-default-credentials](../payloads/web/auth-bypass/default-credentials.md) | experimental |
| Входящий XML с DOCTYPE или внешней сущностью (XXE-попытка) | `b2c3d4e5-0005…` | high | [detection-xxe-doctype-in-request](../payloads/web/detection/xxe-doctype-in-request.md) | stable |
| Загрузка .htaccess/.user.ini — переопределение обработчика расширений | `e5f6a7b8-0056…` | high | [upload-htaccess-handler-override](../payloads/web/upload/htaccess-handler-override.md) | experimental |
| Загрузка файла с traversal в имени — запись вне каталога загрузок | `e5f6a7b8-0055…` | high | [upload-filename-path-traversal](../payloads/web/upload/filename-path-traversal.md) | experimental |
| Злоупотребление GraphQL: introspection, батчинг или аномально тяжёлый запрос | `b2c3d4e5-0008…` | medium | [detection-graphql-abuse-logs](../payloads/web/detection/graphql-abuse-logs.md) | experimental |
| Манипуляция ценой/количеством в заказе — отрицательные и нулевые значения | `e5f6a7b8-0080…` | high | [logic-price-quantity-tampering](../payloads/web/logic/price-quantity-tampering.md) | experimental |
| Обход 2FA — доступ к ресурсу при неподтверждённом челлендже | `e5f6a7b8-0102…` | high | [auth-bypass-2fa-bypass-classic](../payloads/web/auth-bypass/2fa-bypass-classic.md) | experimental |
| Обход Trusted Types — CSP-отчёты require-trusted-types-for | `e5f6a7b8-0054…` | medium | [xss-trusted-types-bypass](../payloads/web/xss/trusted-types-bypass.md) | experimental |
| Подбор HMAC-секрета JWT — шквал invalid signature от одного источника | `e5f6a7b8-0106…` | high | [auth-bypass-jwt-weak-secret](../payloads/web/auth-bypass/jwt-weak-secret.md) | experimental |
| Подбор числа колонок через ORDER BY N и ошибка «Unknown column» | `e5f6a7b8-0028…` | low | [sqli-mysql-order-by-column-count](../payloads/web/sqli/mysql-order-by-column-count.md) | experimental |
| Подделка состояния в подписанном cookie — role escalation и сбой подписи | `e5f6a7b8-0108…` | high | [deserialization-cookie-state-forgery](../payloads/web/deserialization/cookie-state-forgery.md) | experimental |
| Подмена Content-Type — скриптовое расширение с типом изображения | `e5f6a7b8-0058…` | high | [upload-mime-content-type-spoof](../payloads/web/upload/mime-content-type-spoof.md) | experimental |
| Признак CSV/formula injection в сохраняемых пользовательских данных | `b2c3d4e5-0007…` | medium | [detection-csv-formula-injection](../payloads/web/detection/csv-formula-injection.md) | experimental |
| Пропуск шага workflow — подтверждение неоплаченного заказа | `e5f6a7b8-0081…` | high | [logic-workflow-step-skipping](../payloads/web/logic/workflow-step-skipping.md) | experimental |
| Сброс пароля на сторонний хост из заголовка Host/X-Forwarded-Host | `e5f6a7b8-0085…` | critical | [http-host-header-password-reset](../payloads/web/http/host-header-password-reset.md) | experimental |
| Слепой NoSQL-перебор — $regex с префиксами в форме входа | `e5f6a7b8-0075…` | high | [nosql-mongodb-regex-blind](../payloads/web/nosql/mongodb-regex-blind.md) | experimental |
| Тавтология в форме входа — успешная аутентификация без пароля | `e5f6a7b8-0031…` | high | [sqli-mysql-tautology-auth-bypass](../payloads/web/sqli/mysql-tautology-auth-bypass.md) | experimental |
| Файл-полиглот — исполняемый код после магических байтов изображения | `e5f6a7b8-0057…` | high | [upload-magic-bytes-polyglot](../payloads/web/upload/magic-bytes-polyglot.md) | experimental |

## cicd (3)

| Правило | ID | Уровень | Карточка | Статус |
|---------|----|---------|----------|--------|
| GitHub Actions — выполнение кода PR с доступом к секретам | `a1b2c3d4-0011…` | high | [ci-cd-github-pull-request-target](../payloads/cloud/cicd-github-pull-request-target.md) | experimental |
| GitLab — регистрация чужого раннера и разведка API job-токеном | `f6a7b8c9-0017…` | high | [ci-cd-gitlab-runner-token-abuse](../payloads/cloud/cicd-gitlab-runner-token-abuse.md) | experimental |
| Supply chain образов — неподписанные push/pull и mutable-теги | `f6a7b8c9-0018…` | medium | [ci-cd-image-supply-chain](../payloads/cloud/cicd-image-supply-chain.md) | experimental |

## cloud (9)

| Правило | ID | Уровень | Карточка | Статус |
|---------|----|---------|----------|--------|
| AWS — изменение IAM-политик как признак эскалации | `a1b2c3d4-0010…` | high | [cloud-aws-iam-privilege-escalation](../payloads/cloud/aws-iam-privilege-escalation.md) | experimental |
| Azure — запрос ключей storage и секретов App Service через ARM | `f6a7b8c9-0016…` | high | [cloud-azure-appservice-storage-keys](../payloads/cloud/azure-appservice-storage-keys.md) | experimental |
| Entra hybrid SSO — использование PRT с неуправляемого устройства | `a7b8c9d0-0011…` | high | [ad-entra-hybrid-prt-sso](../payloads/network/ad/entra-hybrid-prt-sso.md) | experimental |
| GCP — создание ключей сервисных аккаунтов и раздача roles/editor | `f6a7b8c9-0015…` | high | [cloud-gcp-sa-keys-and-default-editor](../payloads/cloud/gcp-sa-keys-and-default-editor.md) | experimental |
| Lambda confused deputy — смена конфигурации функции и чужой AssumeRole | `f6a7b8c9-0011…` | medium | [cloud-lambda-env-vars-confused-deputy](../payloads/cloud/lambda-env-vars-confused-deputy.md) | experimental |
| S3 — публикация бакета/объектов и анонимное скачивание | `f6a7b8c9-0008…` | high | [cloud-aws-s3-object-acl-leak](../payloads/cloud/aws-s3-object-acl-leak.md) | experimental |
| Анонимное перечисление S3-бакетов | `f6a7b8c9-0007…` | medium | [cloud-aws-s3-bucket-enum](../payloads/cloud/aws-s3-bucket-enum.md) | experimental |
| Изменение OIDC-доверия — AssumeRolePolicy и новые OIDC-провайдеры | `f6a7b8c9-0010…` | high | [cloud-aws-oidc-github-actions-trust](../payloads/cloud/aws-oidc-github-actions-trust.md) | experimental |
| Чтение terraform.tfstate из S3 — файл с секретами в открытом виде | `f6a7b8c9-0009…` | high | [cloud-aws-tfstate-secrets-exposure](../payloads/cloud/aws-tfstate-secrets-exposure.md) | experimental |

## k8s (6)

| Правило | ID | Уровень | Карточка | Статус |
|---------|----|---------|----------|--------|
| Kubernetes API — анонимная разведка, включая отклонённые запросы | `f6a7b8c9-0002…` | high | [cloud-kubernetes-api-anonymous-rbac](../payloads/cloud/kubernetes-api-anonymous-rbac.md) | experimental |
| Kubernetes API — успешные анонимные запросы | `f6a7b8c9-0001…` | critical | [cloud-kubernetes-anonymous-api](../payloads/cloud/kubernetes-anonymous-api.md) | experimental |
| Privileged-под с hostPath / — захват узла через монтирование корня | `f6a7b8c9-0004…` | critical | [cloud-kubernetes-hostpath-node-takeover](../payloads/cloud/kubernetes-hostpath-node-takeover.md) | experimental |
| Доступ к секретам кластера — API list/get secrets и прямое чтение etcd | `f6a7b8c9-0003…` | high | [cloud-kubernetes-etcd-no-encryption](../payloads/cloud/kubernetes-etcd-no-encryption.md) | experimental |
| Злоупотребление SA-токеном пода — exec, секреты и чужие ресурсы | `f6a7b8c9-0005…` | high | [cloud-kubernetes-pod-sa-token](../payloads/cloud/kubernetes-pod-sa-token.md) | experimental |
| Опасные RBAC-binding'и — cluster-admin и wildcard-права | `f6a7b8c9-0006…` | high | [cloud-kubernetes-rbac-overpermissive](../payloads/cloud/kubernetes-rbac-overpermissive.md) | experimental |

## linux (14)

| Правило | ID | Уровень | Карточка | Статус |
|---------|----|---------|----------|--------|
| Docker socket escape — docker run --privileged -v / из контейнера | `f6a7b8c9-0019…` | critical | [cloud-docker-socket-escape](../payloads/cloud/docker-socket-escape.md) | experimental |
| LDAP anonymous bind и перечисление каталога без аутентификации | `a7b8c9d0-0003…` | high | [ldap-anonymous-bind](../payloads/network/ldap-anonymous-bind.md) | experimental |
| Redis без аутентификации — команды от внешнего клиента и CONFIG SET | `a7b8c9d0-0004…` | critical | [redis-unauthenticated](../payloads/network/redis-unauthenticated.md) | experimental |
| SMTP relay-злоупотребление: неаутентифицированная пересылка внешним получателям | `d4e5f6a7-0001…` | high | [smtp-open-relay](../payloads/network/smtp-open-relay.md) | experimental |
| SNMP-перебор community-строк и запросы с public/private | `a7b8c9d0-0007…` | medium | [snmp-community-enum](../payloads/network/snmp-community-enum.md) | experimental |
| sudo-вызов интерактивной программы (потенциальная эскалация через GTFOBins) | `c3d4e5f6-0002…` | medium | [linux-sudo-misconfiguration](../payloads/privilege-escalation/linux/sudo-misconfiguration.md) | experimental |
| Аномальная SSH-активность: перебор, вход root по паролю, туннелирование | `d4e5f6a7-0002…` | high | [ssh-misconfiguration](../payloads/network/ssh-misconfiguration.md) | test |
| Анонимный вход на FTP-сервер | `a7b8c9d0-0002…` | medium | [ftp-anonymous-access](../payloads/network/ftp-anonymous-access.md) | experimental |
| Веб-сервер порождает оболочку или интерпретатор (RCE) | `e5f6a7b8-0012…` | critical | [cmdi-basic-chained-commands](../payloads/web/cmdi/basic-chained-commands.md) | experimental |
| Запуск SUID-бинарника, не входящего в эталонный набор ОС | `c3d4e5f6-0001…` | high | [linux-suid-misconfiguration](../payloads/privilege-escalation/linux/suid-misconfiguration.md) | experimental |
| Исполняемый файл задачи root находится в пользовательском каталоге | `c3d4e5f6-0003…` | high | [linux-writable-cron-or-path](../payloads/privilege-escalation/linux/writable-cron-or-path.md) | experimental |
| Использование file capabilities или запись в файлы учёток для эскалации | `c3d4e5f6-0004…` | critical | [linux-writable-passwd-and-nfs](../payloads/privilege-escalation/linux/writable-passwd-and-nfs.md) | experimental |
| Массовое перечисление системы пользователем (recon перед эскалацией) | `c3d4e5f6-0006…` | medium | [linux-enumeration-checklist](../payloads/privilege-escalation/linux/enumeration-checklist.md) | experimental |
| Признак эксплуатации локальной уязвимости (pkexec/sudo/kernel) | `c3d4e5f6-0005…` | high | [linux-kernel-and-service-exploits](../payloads/privilege-escalation/linux/kernel-and-service-exploits.md) | experimental |

## network (7)

| Правило | ID | Уровень | Карточка | Статус |
|---------|----|---------|----------|--------|
| AWS IMDSv1 — учётные данные роли без сессионного PUT-токена | `f6a7b8c9-0013…` | high | [cloud-aws-imdsv1-role-credentials](../payloads/cloud/aws-imdsv1-role-credentials.md) | experimental |
| Azure IMDS — запрос токена managed identity изнутри ВМ | `f6a7b8c9-0014…` | high | [cloud-azure-imds-managed-identity](../payloads/cloud/azure-imds-managed-identity.md) | experimental |
| Blind SSRF — outbound-обращения к OOB-платформам атакующего | `e5f6a7b8-0068…` | high | [ssrf-blind-callback](../payloads/web/ssrf/blind-callback.md) | experimental |
| DNS rebinding — внешнее имя резолвится во внутренний адрес | `e5f6a7b8-0070…` | high | [ssrf-dns-rebinding](../payloads/web/ssrf/dns-rebinding.md) | experimental |
| GCP — запрос токена сервисного аккаунта из metadata-сервиса | `f6a7b8c9-0012…` | high | [cloud-gcp-metadata-token](../payloads/cloud/gcp-metadata-token.md) | experimental |
| SQL-инъекция с OOB-каналом — xp_dirtree/UTL_HTTP и DNS-callback | `e5f6a7b8-0019…` | high | [sqli-generic-out-of-band-dns](../payloads/web/sqli/generic-out-of-band-dns.md) | experimental |
| Передача зоны DNS (AXFR/IXFR) посторонним клиентом | `a7b8c9d0-0001…` | high | [dns-zone-transfer](../payloads/network/dns-zone-transfer.md) | experimental |

## web (56)

| Правило | ID | Уровень | Карточка | Статус |
|---------|----|---------|----------|--------|
| CORS — отражение стороннего Origin с Access-Control-Allow-Credentials | `e5f6a7b8-0097…` | high | [headers-cors-misconfiguration](../payloads/web/headers/cors-misconfiguration.md) | experimental |
| CRLF-инъекция в заголовки — %0d%0a с Set-Cookie/Location в параметрах | `e5f6a7b8-0098…` | high | [headers-crlf-injection](../payloads/web/headers/crlf-header-injection.md) | experimental |
| CSRF — межсайтовый POST без токена и проваленная CSRF-проверка | `e5f6a7b8-0083…` | high | [http-csrf-token-bypass](../payloads/web/http/csrf-token-bypass.md) | experimental |
| CouchDB/Firebase — дампы через _all_docs, _find и открытые .json-эндпоинты | `e5f6a7b8-0078…` | high | [nosql-couchdb-firebase-misc](../payloads/web/nosql/couchdb-firebase-misc.md) | experimental |
| Elasticsearch — DSL-инъекция и открытые служебные эндпоинты | `e5f6a7b8-0077…` | medium | [nosql-elasticsearch-dsl-injection](../payloads/web/nosql/elasticsearch-dsl-injection.md) | experimental |
| HTML/JS-маркеры в пользовательских данных или логах (stored/blind XSS) | `b2c3d4e5-0006…` | medium | [detection-stored-blind-xss-in-logs](../payloads/web/detection/stored-blind-xss-in-logs.md) | experimental |
| HTTP parameter pollution — дубли параметров в одном запросе | `e5f6a7b8-0086…` | medium | [http-hpp-parameter-pollution](../payloads/web/http/hpp-parameter-pollution.md) | experimental |
| HTTP/2 desync — CL и TE одновременно или два Content-Length | `e5f6a7b8-0084…` | high | [http-h2-cl-desync](../payloads/web/http/h2-cl-desync.md) | experimental |
| Host-заголовок стороннего домена в закэшированном ответе | `e5f6a7b8-0099…` | high | [headers-host-cache-poisoning](../payloads/web/headers/host-header-cache-poisoning.md) | experimental |
| LFI с двойным/смешанным URL-кодированием traversal-последовательностей | `e5f6a7b8-0062…` | high | [lfi-double-encoding-bypass](../payloads/web/lfi-rfi/double-encoding-bypass.md) | experimental |
| LFI через /proc/self — environ, cmdline и файловые дескрипторы | `e5f6a7b8-0066…` | high | [lfi-proc-self-environ](../payloads/web/lfi-rfi/proc-self-environ.md) | experimental |
| LIKE-wildcard инъекция — % и _ в параметрах перечисления | `e5f6a7b8-0027…` | medium | [sqli-mysql-like-wildcard](../payloads/web/sqli/mysql-like-wildcard.md) | experimental |
| Log poisoning — PHP-код в User-Agent и include файлов журналов | `e5f6a7b8-0063…` | critical | [lfi-log-poisoning](../payloads/web/lfi-rfi/log-poisoning.md) | experimental |
| MSSQL xp_cmdshell — попытка выполнения команд на сервере БД | `e5f6a7b8-0022…` | critical | [sqli-mssql-xp-cmdshell](../payloads/web/sqli/mssql-xp-cmdshell.md) | experimental |
| MySQL boolean-based blind — посимвольные условия SUBSTRING/ASCII | `e5f6a7b8-0023…` | medium | [sqli-mysql-boolean-blind](../payloads/web/sqli/mysql-boolean-blind.md) | experimental |
| MySQL time-based blind — SLEEP/BENCHMARK с подтверждённой задержкой | `e5f6a7b8-0032…` | high | [sqli-mysql-time-based-sleep](../payloads/web/sqli/mysql-time-based-sleep.md) | experimental |
| MySQL — обход фильтров versioned-комментариями /*! и /**/ | `e5f6a7b8-0026…` | medium | [sqli-mysql-inline-comment-bypass](../payloads/web/sqli/mysql-inline-comment-bypass.md) | experimental |
| Open redirect — внешний адрес в параметре перенаправления | `e5f6a7b8-0090…` | medium | [http-open-redirect-chain](../payloads/web/http/open-redirect-chain.md) | experimental |
| Path traversal / LFI в параметрах запроса | `b2c3d4e5-0002…` | high | [detection-webserver-lfi-traversal](../payloads/web/detection/webserver-lfi-traversal.md) | stable |
| PostgreSQL — снятие контекста через current_user/version()/current_database() | `e5f6a7b8-0039…` | medium | [sqli-postgresql-stack-version](../payloads/web/sqli/postgresql-stack-version.md) | experimental |
| Race condition — шквал одинаковых запросов от одного клиента | `e5f6a7b8-0091…` | high | [http-race-condition-single-packet](../payloads/web/http/race-condition-single-packet.md) | experimental |
| Reflected XSS — script-тег и PoC-маркеры в параметре запроса | `e5f6a7b8-0042…` | high | [xss-reflected-basic-script](../payloads/web/xss/reflected-basic-script.md) | experimental |
| Request smuggling CL.TE — конфликт Content-Length и Transfer-Encoding | `e5f6a7b8-0092…` | high | [http-request-smuggling-cl-te](../payloads/web/http/request-smuggling-cl-te.md) | experimental |
| Request smuggling TE.CL и аномалии chunked-тела с 4xx/5xx | `e5f6a7b8-0093…` | high | [http-request-smuggling-te-cl](../payloads/web/http/request-smuggling-te-cl.md) | experimental |
| Request smuggling TE.TE — обфускация Transfer-Encoding | `e5f6a7b8-0094…` | high | [http-request-smuggling-te-te](../payloads/web/http/request-smuggling-te-te.md) | experimental |
| SQL-инъекция в query-строке с подтверждением по статусу ответа | `b2c3d4e5-0001…` | high | [detection-webserver-sqli-signatures](../payloads/web/detection/webserver-sqli-signatures.md) | test |
| SQL-маркеры — комментарий-терминатор после кавычки в параметре | `e5f6a7b8-0017…` | medium | [sqli-generic-comment-terminators](../payloads/web/sqli/generic-comment-terminators.md) | experimental |
| SSRF на cloud-метаданные — 169.254.169.254 и аналоги | `e5f6a7b8-0069…` | critical | [ssrf-cloud-metadata-169254](../payloads/web/ssrf/cloud-metadata-169254.md) | experimental |
| SSRF с нестандартными схемами — gopher/dict/ldap/file к внутренним сервисам | `e5f6a7b8-0072…` | high | [ssrf-protocol-smuggling-gopher](../payloads/web/ssrf/protocol-smuggling-gopher.md) | experimental |
| SSRF с обфускацией localhost — десятичные, hex, восьмеричные и IPv6-формы | `e5f6a7b8-0071…` | high | [ssrf-localhost-obfuscation](../payloads/web/ssrf/localhost-obfuscation.md) | experimental |
| SSRF — обращение к метаданным или внутренним адресам через параметр URL | `b2c3d4e5-0003…` | high | [detection-webserver-ssrf-metadata](../payloads/web/detection/webserver-ssrf-metadata.md) | test |
| SSTI — цепочки __class__/__mro__/__subclasses__ к интерпретатору | `e5f6a7b8-0010…` | high | [ssti-python-class-chain](../payloads/web/ssti/python-class-chain.md) | experimental |
| SSTI-пробы — шаблонные выражения в параметрах и ошибки движков | `e5f6a7b8-0007…` | high | [ssti-jinja2-detection](../payloads/web/ssti/jinja2-detection.md) | experimental |
| Web cache deception — аутентифицированный динамический ответ закэширован как статика | `e5f6a7b8-0095…` | high | [http-web-cache-deception](../payloads/web/http/web-cache-deception.md) | experimental |
| Web cache poisoning — unkeyed-заголовки в закэшированном ответе | `e5f6a7b8-0096…` | critical | [http-web-cache-poisoning-unkeyed](../payloads/web/http/web-cache-poisoning-unkeyed.md) | experimental |
| X-Forwarded-For спуфинг — внутренний адрес от внешнего клиента | `e5f6a7b8-0101…` | medium | [headers-x-forwarded-for-spoofing](../payloads/web/headers/x-forwarded-for-spoofing.md) | experimental |
| XSS без script-тега — обработчики событий img (onerror/onload) | `e5f6a7b8-0043…` | high | [xss-img-onerror-no-script-tag](../payloads/web/xss/img-onerror-no-script-tag.md) | experimental |
| XSS в HTML->PDF/SVG конвейере — JS с эксфильтрацией DOM и cookie | `e5f6a7b8-0051…` | high | [xss-pdf-svg-generation](../payloads/web/xss/pdf-svg-generation.md) | experimental |
| XSS во фреймворках — template-инъекции Angular/React/Vue в пользовательских данных | `e5f6a7b8-0053…` | high | [xss-angular-react-framework-contexts](../payloads/web/xss/angular-react-framework-contexts.md) | experimental |
| XSS с HTML-entity/двойным кодированием обработчиков событий | `e5f6a7b8-0046…` | medium | [xss-html-entity-encoding-bypass](../payloads/web/xss/html-entity-encoding-bypass.md) | experimental |
| XSS через SVG — onload/onbegin и animate-элементы | `e5f6a7b8-0048…` | high | [xss-svg-onload-namespace](../payloads/web/xss/svg-onload-namespace.md) | experimental |
| javascript:-схема в ссылках и сохраняемых полях | `e5f6a7b8-0045…` | high | [xss-href-javascript-scheme](../payloads/web/xss/href-javascript-scheme.md) | experimental |
| php://filter — чтение исходников через base64-конвертер | `e5f6a7b8-0064…` | high | [lfi-php-filter-base64](../payloads/web/lfi-rfi/php-filter-base64.md) | experimental |
| php://input и data:// — выполнение кода из тела запроса | `e5f6a7b8-0065…` | critical | [lfi-php-input-data-wrapper](../payloads/web/lfi-rfi/php-input-data-wrapper.md) | experimental |
| Выход из HTML-атрибута — кавычка и autofocus/onfocus/onmouseover | `e5f6a7b8-0044…` | high | [xss-attribute-breakout-double-quote](../payloads/web/xss/attribute-breakout-double-quote.md) | experimental |
| Двойное расширение и гонка загрузки — shell.php.jpg исполняется как PHP | `e5f6a7b8-0059…` | high | [upload-race-double-extension](../payloads/web/upload/race-double-extension.md) | experimental |
| Инъекция аргументов в серверные утилиты (curl, tar, find, ssh) | `e5f6a7b8-0015…` | medium | [cmdi-argument-injection](../payloads/web/cmdi/argument-injection.md) | experimental |
| Инъекция в User-Agent — canary-маркеры и подделка формата лог-строки | `e5f6a7b8-0100…` | medium | [headers-user-agent-log-injection](../payloads/web/headers/user-agent-log-injection.md) | experimental |
| Инъекция команд в Windows-контексте — маркеры cmd.exe и PowerShell | `e5f6a7b8-0016…` | high | [cmdi-windows-specific](../payloads/web/cmdi/windows-specific.md) | experimental |
| Инъекция команд с обходом фильтров — IFS, склейка кавычек, base64-pipe | `e5f6a7b8-0014…` | high | [cmdi-filter-bypass-obfuscation](../payloads/web/cmdi/filter-bypass-obfuscation.md) | experimental |
| Инъекция команд — цепочки и подстановки в query-строке | `e5f6a7b8-0011…` | high | [cmdi-basic-chained-commands](../payloads/web/cmdi/basic-chained-commands.md) | experimental |
| Исполнение скрипта из каталога загрузок | `3f2b8c1a-9d4e…` | critical | [upload-extension-blacklist-bypass](../payloads/web/upload/extension-blacklist-bypass.md) | experimental |
| Обход CSP через JSONP-эндпоинты доверенных доменов | `e5f6a7b8-0050…` | medium | [xss-csp-bypass-jsonp](../payloads/web/xss/csp-bypass-jsonp.md) | experimental |
| Обход аутентификации нормализацией пути — ..;, /.;/, ..%3b | `e5f6a7b8-0107…` | high | [auth-bypass-path-traversal-normalization](../payloads/web/auth-bypass/path-traversal-normalization.md) | experimental |
| Слепая инъекция команд — задержка ответа совпадает с sleep/timeout | `e5f6a7b8-0013…` | medium | [cmdi-blind-time-based](../payloads/web/cmdi/blind-time-based.md) | experimental |
| Чтение системных файлов через веб — /etc/passwd, win.ini и веб-процесс с cat | `e5f6a7b8-0067…` | high | [lfi-traversal-etc-passwd](../payloads/web/lfi-rfi/traversal-etc-passwd.md) | experimental |

## windows (19)

| Правило | ID | Уровень | Карточка | Статус |
|---------|----|---------|----------|--------|
| AS-REP roasting — запрос билета без пред-аутентификации | `a1b2c3d4-0002…` | high | [ad-as-rep-roasting](../payloads/network/ad/as-rep-roasting.md) | experimental |
| DCSync — доступ к атрибутам репликации не-DC учёткой | `a1b2c3d4-0007…` | critical | [ad-dcsync-replication-rights](../payloads/network/ad/dcsync-replication-rights.md) | stable |
| NTLM-relay — сетевой вход машинной учётки с чужого IP | `a7b8c9d0-0006…` | high | [smb-signing-relay](../payloads/network/smb-signing-relay.md) | experimental |
| RBCD/constrained delegation — правка msDS-AllowedTo* атрибутов | `a7b8c9d0-0008…` | high | [ad-constrained-delegation-rbcd](../payloads/network/ad/constrained-delegation-rbcd.md) | experimental |
| SMB null-сессия — анонимный сетевой вход и доступ к IPC$ | `a7b8c9d0-0005…` | medium | [smb-null-session](../payloads/network/smb-null-session.md) | experimental |
| Аномальная RDP-активность: перебор, shadowing и входы в нерабочее время | `d4e5f6a7-0003…` | high | [rdp-exposure](../payloads/network/rdp-exposure.md) | test |
| Включено unconstrained delegation у объекта AD | `a1b2c3d4-0004…` | high | [ad-unconstrained-delegation](../payloads/network/ad/unconstrained-delegation.md) | experimental |
| Возможный Kerberoasting — аномальные TGS-запросы | `a1b2c3d4-0001…` | high | [ad-kerberoasting-spn](../payloads/network/ad/kerberoasting-spn.md) | experimental |
| Выпуск сертификата AD CS с чужим субъектом (ESC1-признак) | `a1b2c3d4-0006…` | critical | [ad-adcs-template-esc1](../payloads/network/ad/adcs-template-esc1.md) | experimental |
| Добавление участника в привилегированную группу AD | `a1b2c3d4-0005…` | high | [ad-acl-abuse-genericall](../payloads/network/ad/acl-abuse-genericall.md) | stable |
| Доступ к LSASS или извлечение SAM/SYSTEM/NTDS | `c3d4e5f6-0009…` | critical | [windows-credential-harvesting](../payloads/privilege-escalation/windows/credential-harvesting.md) | stable |
| Загрузка DLL из пользовательского каталога процессом из Program Files | `c3d4e5f6-0010…` | high | [windows-dll-hijacking](../payloads/privilege-escalation/windows/dll-hijacking.md) | experimental |
| Изменение механизмов автозапуска Windows (Run-ключи, IFEO, Winlogon) | `c3d4e5f6-0011…` | high | [windows-registry-and-startup](../payloads/privilege-escalation/windows/registry-and-startup.md) | test |
| Массовые неудачные pre-auth (перебор имён/паролей) | `a1b2c3d4-0003…` | medium | [ad-as-rep-roasting](../payloads/network/ad/as-rep-roasting.md) | experimental |
| Назначение или использование опасных привилегий токена | `c3d4e5f6-0008…` | high | [windows-token-and-uac-bypass](../payloads/privilege-escalation/windows/token-and-uac-bypass.md) | experimental |
| Подмена binPath службы или запуск службы из нестандартного каталога | `c3d4e5f6-0007…` | high | [windows-service-permissions](../payloads/privilege-escalation/windows/service-permissions.md) | experimental |
| Последовательность команд перечисления Windows (post-exploitation recon) | `c3d4e5f6-0012…` | medium | [windows-enumeration-checklist](../payloads/privilege-escalation/windows/enumeration-checklist.md) | experimental |
| Чтение GPP-файлов из SYSVOL — поиск cpassword | `a7b8c9d0-0009…` | high | [ad-gpp-cpassword-sysvol](../payloads/network/ad/gpp-cpassword-sysvol.md) | experimental |
| Чтение LAPS-пароля (ms-Mcs-AdmPwd) не привилегированной учёткой | `a7b8c9d0-0010…` | high | [ad-laps-misconfiguration](../payloads/network/ad/laps-misconfiguration.md) | experimental |

## Покрытие по типам техник

| Тип карточек | Всего карточек | С правилами | Покрытие |
|--------------|---------------:|------------:|---------:|
| `ad` | 10 | 10 | 100% |
| `auth-bypass` | 10 | 10 | 100% |
| `ci-cd` | 3 | 3 | 100% |
| `cloud` | 18 | 18 | 100% |
| `cmdi` | 5 | 5 | 100% |
| `deserialization` | 10 | 10 | 100% |
| `header` | 5 | 5 | 100% |
| `http` | 12 | 12 | 100% |
| `lfi` | 7 | 7 | 100% |
| `logic` | 5 | 5 | 100% |
| `network` | 10 | 10 | 100% |
| `nosql` | 5 | 5 | 100% |
| `privesc` | 12 | 12 | 100% |
| `sqli` | 26 | 26 | 100% |
| `ssrf` | 7 | 7 | 100% |
| `ssti` | 4 | 4 | 100% |
| `upload` | 8 | 8 | 100% |
| `xss` | 14 | 14 | 100% |
| `xxe` | 7 | 7 | 100% |

## Как добавить правило

1. Откройте карточку техники (или создайте её по шаблону).
2. Добавьте секцию `## Detection rules` с блоком ```yaml.
3. Обязательные поля Sigma: `title`, `id` (UUID), `status`, `description`,
   `logsource` (`product`/`service`/`category`), `detection`, `condition`,
   `level`, `falsepositives`.
4. Укажите в `description` или `references`, какая техника детектируется,
   и добавьте ссылку на карточку.
5. Добавьте фикстуру и ожидание в `detections/tests/` — правило без теста
   деградирует при первом изменении формата логов.
6. `python tools/detections-extract.py --check && python tools/rules-tester.py`.

Правила со статусом `experimental` не включаются в прод-алертинг:
сначала прогон на реальных логах, затем `test` и только потом `stable`.
