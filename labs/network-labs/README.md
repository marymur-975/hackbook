# network-labs — сетевая лаборатория

Соответствует главе 2 («Сетевая безопасность»). Здесь нет самописных приложений:
используются **настоящие** сервисы, настроенные намеренно небезопасно, чтобы
разведка и hardening отрабатывались на реальном поведении протоколов.

```bash
cd labs/setup
docker compose --profile network up -d
docker compose ps
```

| Сервис | Порт (localhost) | Намеренная проблема |
|--------|------------------|---------------------|
| Redis 7 | 6379 | `protected-mode no`, без `requirepass` |
| OpenLDAP 2.6 | 1389 / 1636 | разрешён anonymous bind, каталог читается без учётки |
| vsftpd | 2121 (+21100-21110 passive) | анонимный вход, слабые учётные данные `lab:lab` |

Все порты опубликованы только на `127.0.0.1`.

## Задания

### 1. Инвентаризация

```bash
nmap -sS -sV -p 2121,6379,1389,1636 localhost
nmap -sU -p 1389 localhost          # UDP-проверка LDAP
```

Зафиксируйте: порт, сервис, версию,/banner, необходимость аутентификации.

### 2. Redis без аутентификации

```bash
redis-cli -h 127.0.0.1 -p 6379 INFO keyspace
redis-cli -h 127.0.0.1 -p 6379 CONFIG GET dir
redis-cli -h 127.0.0.1 -p 6379 KEYS '*'
```

Ответьте:

* какие данные можно прочитать и что среди них чувствительного;
* как через `CONFIG SET dir` + `SAVE` получить запись файла (теория —
  см. `payloads/network/redis-unauthenticated.md`);
* почему в production Redis обязан иметь `requirepass`/ACL, `bind`, `protected-mode yes`
  и быть недоступным из других сегментов.

### 3. LDAP anonymous bind

```bash
ldapsearch -x -H ldap://127.0.0.1:1389 -s base -b '' '+'          # RootDSE
ldapsearch -x -H ldap://127.0.0.1:1389 -b 'dc=lab,dc=local' '(objectClass=*)' dn
ldapsearch -x -H ldap://127.0.0.1:1389 -b 'ou=people,dc=lab,dc=local' \
  '(objectClass=inetOrgPerson)' uid mail title description
ldapsearch -x -H ldap://127.0.0.1:1389 -b 'ou=groups,dc=lab,dc=local' \
  '(objectClass=groupOfNames)' cn member
```

Что даёт злоумышленнику этот список? Составьте словарь для password spray
(имена, сервисные учётки) и объясните, почему сервисные учётки
(`svc_backup`, `svc_sql`) — приоритетная цель (см. главу 3).

### 4. FTP

```bash
ftp -n 127.0.0.1 2121 <<'EOF'
user anonymous anonymous@
ls
bye
EOF
```

Проверьте, возможна ли запись (`put`). Объясните, почему запись в каталог,
который раздаёт веб-сервер, — это путь к размещению webshell.

### 5. Hardening

Примените исправления и перепроверьте каждое:

* Redis: `requirepass`, `bind 127.0.0.1`, `protected-mode yes`,
  `rename-command CONFIG ""`, ACL-пользователь с минимальными командами.
* OpenLDAP: запретить anonymous bind, требовать TLS, ограничить чтение
  по DN и группам, включить аудит запросов.
* FTP: заменить на SFTP; если FTP остаётся — закрыть анонимный доступ,
  включить TLS (FTPS), chroot, права только на чтение.

### 6. Сегментация

Нарисуйте схему, в которой эти три сервиса недоступны из «пользовательского»
сегмента, и опишите правила firewall. В `labs/setup/docker-compose.yml`
есть закомментированная строка `internal: true` — включите её и проверьте,
что изменилось (egress исчезает, что ломает OOB-эксфильтрацию).

## Артефакты для разбора

* `payloads/network/redis-unauthenticated.md`
* `payloads/network/ldap-anonymous-bind.md`
* `payloads/network/ftp-anonymous-access.md`
* `payloads/network/snmp-community-enum.md`
* `payloads/network/dns-zone-transfer.md`
* `payloads/network/smb-null-session.md`
* `payloads/network/smb-signing-relay.md`

## Примечания по образам

* `redis:7-alpine` и `bitnami/openldap:2.6` — официальные/поддерживаемые образы.
* `fauria/vsftpd` — учебный образ FTP; для production не используется.
* Если образ недоступен в вашем окружении, отключите сервис в compose
  (профиль `network`) — веб-лабы от этого не зависят.
