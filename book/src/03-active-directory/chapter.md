---
title: "Active Directory: поверхность атаки домена"
chapter: 3
difficulty: advanced
category: active-directory
tags: [active-directory, kerberos, ntlm, ldap, gpo, privilege-escalation]
prerequisites:
  - "Сетевая безопасность: разведка, сервисы, сегментация"
  - "Основы Kerberos"
  - "Windows-администрирование"
related_payloads:
  - "payloads/network/smb-signing-relay.md"
  - "payloads/network/smb-null-session.md"
  - "payloads/network/ldap-anonymous-bind.md"
  - "payloads/web/sqli/mssql-xp-cmdshell.md"
lab: null
---

# Active Directory: поверхность атаки домена

Active Directory редко «взламывают эксплойтом». Домен падает из-за набора
конфигурационных решений, каждое из которых по отдельности выглядит безобидно:
одинаковые локальные администраторы на всех машинах, сервисные учётки в группе
Domain Admins, незащищённые делегирования, SPN с паролями, которые не менялись
пять лет, GPO, раздающие права «всем компьютерам», и отсутствие аудита.

Эта глава — про то, как эти решения складываются в цепочку, и как их находить
**до** того, как это сделает кто-то другой.

## Язык Kerberos за 10 минут

```
Клиент            KDC (DC)                Сервис
  │  AS-REQ (pre-auth: хеш пароля)         │
  ├──────────────►│                        │
  │  AS-REP: TGT  │ (зашифровано ключом krbtgt)
  │◄──────────────┤                        │
  │  TGS-REQ: нужен билет к HTTP/host      │
  ├──────────────►│                        │
  │  TGS-REP: service ticket               │
  │◄──────────────┤                        │
  │  AP-REQ: билет + authenticator         │
  ├────────────────────────────────────────►
```

Ключевые следствия для защиты:

* пароль пользователя никогда не передаётся — передаётся производный ключ;
* билет TGT зашифрован ключом `krbtgt`: кто владеет хешем `krbtgt`, владеет доменом
  (golden ticket, срок жизни — до смены пароля дважды);
* сервисный билет зашифрован ключом учётной службы: офлайн-подбор даёт пароль службы
  (kerberoasting);
* если у пользователя **нет** пред-аутентификации, AS-REP можно получить и подобрать
  офлайн (AS-REP roasting).

## Карта поверхности атаки

| Класс | Примеры | Как находить | Как чинить |
|-------|---------|--------------|------------|
| Пароли | Kerberoasting, AS-REP roast, перебор, spray | `GetUserSPNs.py`, `GetNPUsers.py`, аудит политик | Длинные пароли служб (gMSA), LAPS, запрет pre-auth off |
| Делегирование | Unconstrained/constrained/RBD | `findDelegation.py`, LDAP-атрибут `msDS-AllowedToDelegateTo` | Только RBD, без `msDS-AllowedToActOnBehalfOfOtherIdentity` у критичных |
| Права (ACL) | GenericAll, WriteDacl, AddMembers, ForceChangePassword | `bloodhound`, `Get-ObjectAcl` | Удаление лишних ACE, tiering, ревизия групп |
| Группы и членства | Сервис в Domain Admins, вложенные группы | `bloodhound`, `net group` | Tier 0/1/2, минимализм, review каждые 90 дней |
| GPO | Скрипты входа, права локального админа, `password` в XML | `bloodhound`, SYSVOL-обход | CPASS не использовать (MS14-025), предпочитать LAPS |
| Сервисы | MSSQL `xp_cmdshell`, ADCS, Exchange, backup-агенты | перечисление SPN, ADCS-чекеры | Минимальные права служб, аудит шаблонов ADCS |
| Протоколы | NTLM relay, LDAP без подписи, SMB без подписи | `crackmapexec --gen-relay-list` | Подписи обязательны, LLMNR off, NTLM ограничен |
| Аудит | Отключённые логи, отсутствие алертов | проверка 4662/4672/4768/4769/4771 | Advanced Audit Policy + SIEM-правила |

## Перечисление домена

### С учётными данными (обычный пользователь)

```bash
# сводка по домену: пользователи, группы, политики, сессии
crackmapexec smb dc01.lab.local -u user -p 'Passw0rd!' --shares --pass-pol --users --groups

# кто сейчас залогинен и где (для планирования перехвата)
crackmapexec smb 10.10.10.0/24 -u user -p 'Passw0rd!' --loggedon-users

# граф прав и путей эскалации
bloodhound-python -d lab.local -u user -p 'Passw0rd!' -ns 10.10.10.5 \
  -c All,LocalAdmin,Session,Trusts --zip
```

### Без учётных данных

```bash
rpcclient -U '' -N dc01.lab.local -c 'enumdomusers; enumdomgroups'
ldapsearch -x -H ldap://dc01.lab.local -b 'DC=lab,DC=local' '(objectClass=user)' \
  sAMAccountName userAccountControl servicePrincipalName
nmap --script smb-enum-users,smb-enum-shares,smb2-security-mode -p445 dc01.lab.local
```

Критически важный атрибут — `userAccountControl`. Флаги, которые стоит искать:

| Флаг | Значение | Почему опасно |
|------|----------|---------------|
| `DONT_REQ_PREAUTH` (4194304) | пред-аутентификация отключена | AS-REP roasting |
| `PASSWORD_NOT_REQUIRED` | пустой пароль разрешён | вход без пароля |
| `TRUSTED_FOR_DELEGATION` (524288) | unconstrained delegation | перехват TGT любого, кто подключился |
| `TRUSTED_TO_AUTH_FOR_DELEGATION` | constrained + protocol transition | эскалация к любому сервису |
| `DONT_EXPIRE_PASSWORD` | пароль не истекает | вечные креды сервисов |

## Атаки на пароли: что проверять обязательно

### Kerberoasting

У любой учётки с SPN можно запросить сервисный билет и подобрать его офлайн —
права нужны уровня обычного пользователя домена.

```bash
GetUserSPNs.py lab.local/user:'Passw0rd!' -dc-ip 10.10.10.5 -request -outputfile spn.txt
hashcat -m 13100 spn.txt wordlists/passwords/service-accounts.txt
```

Защита: **gMSA** (120-символьные пароли, автоматическая ротация 30 дней) для всех
служб, запрет «человеческих» паролей у сервисных учёток, алерт на аномальное число
TGS-запросов от одной учётки (Event 4769 с шифрованием RC4 — отдельный красный флаг).

### AS-REP roasting

```bash
GetNPUsers.py lab.local/ -usersfile wordlists/usernames/common.txt -no-pass \
  -dc-ip 10.10.10.5 -format hashcat
```

Защита: включить пред-аутентификацию у всех (группа «Do not require Kerberos
preauthentication» должна быть пуста), мониторить 4768 с флагом pre-auth off.

### Password spraying и перебор

```bash
# одна парольная попытка на каждого пользователя — блокировки не срабатывают
crackmapexec smb 10.10.10.5 -u wordlists/usernames/common.txt \
  -p wordlists/passwords/top-100.txt --no-bruteforce
```

Защита: порог блокировки + **умная** блокировка (по IP и по учётке отдельно),
запрет общих паролей (`Azure AD Password Protection` / свой blacklist),
MFA для интерактивного входа, разные локальные админ-пароли (LAPS).

## Делегирование

| Тип | Что может | Опасность |
|-----|-----------|-----------|
| Unconstrained | Кэшировать TGT любого подключившегося | Хост с таким правом = ключ к домену, если на него зайдёт админ |
| Constrained | Обращаться к указанному сервису от имени любого | Доступ к данным сервиса |
| Constrained + protocol transition | Без билета пользователя, от любого имени | Ещё хуже |
| Resource-based (RBCD) | Настройка **на целевом** объекте | Кто может править `msDS-AllowedToActOnBehalfOfOtherIdentity` целевой машины, тот получает к ней доступ |

Проверка:

```bash
findDelegation.py lab.local/user:'Passw0rd!' -dc-ip 10.10.10.5
ldapsearch -x -H ldap://dc01.lab.local -b 'DC=lab,DC=local' \
  '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' dn
```

Защита: unconstrained delegation — только на DC и только там, где это неизбежно;
для всего остального — RBCD с явной ревизией; критичные объекты (DC, файловые
серверы Tier 0) — в группе «Protected Users» и с `Account is sensitive and cannot
be delegated`.

## ACL и пути эскалации прав

BloodHound отвечает на вопрос «каким кратчайшим путём обычный пользователь становится
админом домена». Типовые опасные права:

| Право | Что даёт | Как чинить |
|-------|----------|------------|
| `GenericAll` на пользователя | Смена пароля, добавление SPN, RBCD | Убрать ACE |
| `WriteDacl` | Выдача себе любых прав | Убрать ACE |
| `AddMembers` на группу | Включение себя в Domain Admins | Ревизия членства |
| `ForceChangePassword` | Смена пароля цели | Убрать ACE |
| `WriteOwner` | Смена владельца -> полный контроль | Убрать ACE |
| `GenericWrite` на компьютер | RBCD-эскалация | Убрать ACE |
| `Owns` + `WriteDacl` на OU | Наследуемые права на все объекты OU | Ревизия OU-прав |
| `GPO-права` (WriteGPO) | Изменение политики -> код на всех машинах OU | Tiering, отдельные права |

```powershell
# проверить опасные ACE для конкретной группы
Get-ObjectAcl "CN=Domain Admins,CN=Users,DC=lab,DC=local" |
  ? { $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' } |
  Select IdentityReference, ActiveDirectoryRights, AccessControlType
```

## GPO как вектор массового доступа

Политика, применённая к OU с серверами, — это способ выполнить код сразу на всех
машинах OU. Что смотреть:

* `Computer Configuration → Preferences → Control Panel Settings → Local Users and Groups`
  (создание локального админа на всех машинах);
* скрипты запуска/входа (`startup.ps1` в SYSVOL);
* назначенные задачи (Scheduled Tasks) в GPO;
* исторический `Groups.xml` с CPASS-паролем (уязвимость MS14-025 — пароль
  расшифровывается публичным ключом Microsoft, но файлы до сих пор лежат в SYSVOL).

```bash
# поиск паролей в SYSVOL
crackmapexec smb dc01.lab.local -u user -p 'Passw0rd!' -M gpp_autologin
crackmapexec smb dc01.lab.local -u user -p 'Passw0rd!' -M gpp_password
```

## ADCS: сертификаты как путь в домен

Active Directory Certificate Services — самый недооценённый вектор последних лет.
Опасные свойства шаблонов сертификатов:

| Свойство | Почему опасно |
|----------|---------------|
| `ENROLLEE_SUPPLIES_SUBJECT` | Можно указать любое имя субъекта (в т.ч. администратора) |
| `Client Authentication` + низкие права на enrol | Выпуск сертификата от имени любого |
| `NoSecurityExtension` / `CT_FLAG_NO_SECURITY_EXTENSION` | Обход защиты `StrongCertificateBindingEnforcement` |
| Права `WriteOwner`/`WriteDacl` на шаблон | Меняем шаблон под себя |
| `Manager Approval` выключен + широкие права | Автоматический выпуск |

```bash
certipy find lab.local/user:'Passw0rd!'@dc01.lab.local -vulnerable -stdout
```

Защита: аудит шаблонов, запрет `ENROLLEE_SUPPLIES_SUBJECT` для шаблонов с
client authentication, `StrongCertificateBindingEnforcement=2`, мониторинг
выпуска сертификатов для привилегированных субъектов (Event 4886/4887).

## Аудит: какие события важны

| Event ID | Что означает | На что смотреть |
|----------|--------------|-----------------|
| 4624 / 4625 | Вход успешный / неудачный | Тип входа 3 (сеть), необычные источники, spray |
| 4672 | Назначение привилегий | Кто входит как администратор |
| 4662 | Доступ к объекту каталога | Чтение секретов, изменения ACL |
| 4698 / 4699 | Создание / удаление задачи | Закрепление через Scheduled Task |
| 4720 / 4726 | Создание / удаление учётки | Новые пользователи в домене |
| 4728 / 4732 / 4756 | Добавление в группу | Кто попал в privileged-группы |
| 4768 / 4769 / 4771 | Kerberos: AS-REQ / TGS-REQ / pre-auth fail | Roasting, перебор, RC4-шифрование |
| 4776 | NTLM-аутентификация | Relay и использование NTLM там, где нужен Kerberos |
| 4886 / 4887 | ADCS: запрос / выпуск сертификата | Выпуск для привилегированных имён |
| 5136 | Изменение объекта каталога | Правки ACL, делегирования, RBCD |
| 1102 | Очистка журнала безопасности | Заметание следов — критический алерт |

Без включённой Advanced Audit Policy и пересылки в SIEM домен фактически слеп:
большинство атак выше не оставляет следов в «обычных» логах.

## Модель защиты: tiering

```
Tier 0  ── DC, PKI, ADFS, hyper-v hosts, привилегированные рабочие места
           доступ ТОЛЬКО с PAW, только из Tier 0; учётки не входят в Tier 1/2
Tier 1  ── серверы приложений, СУБД, файловые
           доступ только с Tier 1-админок; Tier 0-учётки сюда не заходят
Tier 2  ── рабочие станции пользователей
           доступ только с Tier 2; админ Tier 0 никогда не входит сюда
```

Правило простое: **младший tier не может аутентифицироваться в старшем**
(настройка через Authentication Policies / silos). Это ломает большинство
цепочек эскалации: перехват хеша на рабочей станции больше не даёт доступ к DC.

## Практика

Учебный домен поднимается отдельно от основных лабораторий (требует Windows-образов):

```bash
cd labs/network-labs/ad
docker compose up -d          # или vagrant up (см. README лабы)
```

Задания:

1. Соберите BloodHound-данные обычным пользователем. Найдите кратчайший путь
   к Domain Admins и объясните каждое звено.
2. Найдите все учётки с SPN и с отключённой пред-аутентификацией. Проверьте пароли
   офлайн словарём `wordlists/passwords/service-accounts.txt`.
3. Перечислите объекты с unconstrained/RBCD-делегированием.
4. Найдите опасные ACE (`GenericAll`, `WriteDacl`) на привилегированных группах.
5. Проверьте SYSVOL на GPP-пароли и скрипты.
6. Включите аудит (4662, 4768, 4769, 4771, 5136) и постройте правило SIEM, которое
   ловит kerberoasting по аномальному числу TGS-запросов.
7. Внедрите LAPS + gMSA на тестовом OU и убедитесь, что пункты 2–3 больше не работают.

### Чек-лист аудита домена

- [ ] LAPS или аналог включён; одинаковых локальных админ-паролей нет.
- [ ] Все сервисные учётки — gMSA; пароли служб не «человеческие».
- [ ] Группа «Do not require Kerberos preauthentication» пуста.
- [ ] Unconstrained delegation только там, где обосновано (и не на рабочих станциях).
- [ ] Нет сервисных учёток в Domain/Enterprise Admins.
- [ ] NTLM ограничен, SMB/LDAP-подписи обязательны, LLMNR/NBT-NS отключены.
- [ ] ADCS-шаблоны без `ENROLLEE_SUPPLIES_SUBJECT` для client auth.
- [ ] SYSVOL не содержит паролей и «живых» скриптов с правами.
- [ ] Tiering + Authentication Policies настроены.
- [ ] Advanced Audit Policy включён, логи уходят в SIEM, алерты на 1102 и 4776.
- [ ] Есть процесс ежеквартальной ревизии привилегированных групп и ACE.
