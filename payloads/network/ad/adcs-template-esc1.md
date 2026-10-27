---
id: ad-adcs-template-esc1
title: "AD CS: шаблоны с ENROLLEE_SUPPLIES_SUBJECT (ESC1) и права на выпуск"
type: ad
target: active-directory
category: active-directory
difficulty: advanced
bypass: auth
tags: [adcs, pki, certificate, template, privilege-escalation]
tested_on: ["AD CS на Windows Server 2019/2022", "шаблоны с client authentication"]
success_rate: 0.4
risk: critical
cwe: "CWE-295"
lab: null
last_verified: "2026-10-23"
references:
  - "https://learn.microsoft.com/en-us/windows-server/identity/"
  - "https://posts.specterops.io/certified-pre-owned-d95910965cd2"
graph:
  - target: "adcs"
    type: instance_of
  - target: "privilege-escalation"
    type: leads_to
  - target: "auth-bypass"
    type: leads_to
  - target: "active-directory"
    type: related_to
---

# AD CS: шаблоны с ENROLLEE_SUPPLIES_SUBJECT (ESC1) и права на выпуск

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# аудит шаблонов: какие разрешают задавать субъект и имеют client-auth EKU
certutil -config dc01.lab.local\LabCA -template -display | \
  grep -iE 'Template Name|Subject Name|Enrollee Supplies Subject|EKU|Security Descriptor'
```

## Explanation

Active Directory Certificate Services выпускает сертификаты по шаблонам.
Опасная комбинация свойств шаблона (в классификации «Certified Pre-Owned» — ESC1):

1. `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` — заявитель сам указывает субъект
   (в т.ч. имя администратора);
2. EKU включает **Client Authentication** / **Smart Card Logon** /
   **Any Purpose** (`2.5.29.37.0`) — сертификат годится для входа;
3. широкие права на enrollment (Domain Users / Authenticated Users);
4. **Manager Approval выключен** и не требуется подписанное уполномоченным
   лицом заявление;
5. не включён `CT_FLAG_NO_SECURITY_EXTENSION` (иначе SChannel-расширение
   отсутствует и часть защит игнорируется) — наоборот, его наличие
   **снижает** защиту при `StrongCertificateBindingEnforcement=1`.

Итог: обычный пользователь выпускает себе сертификат с `SAN = Administrator`
и входит от имени администратора (PKINIT -> TGT). Домен скомпрометирован
без единого угаданного пароля.

Родственные классы: ESC2 (Any Purpose + широкие права), ESC3 (enrollment agent
цепочки), ESC4 (права `WriteOwner`/`WriteDacl` на шаблон -> меняем свойства),
ESC6 (`EDITF_ATTRIBUTESUBJECTALTNAME2` на уровне CA — SAN для **любых**
шаблонов), ESC7 (права на управление CA), ESC8 (NTLM relay на HTTP-эндпоинт
Web Enrollment), ESC9/10/11 — более поздние вариации.

## Detection

1. Полный аудит ADCS: `certipy find -vulnerable -stdout`, `PSPKI`/`Certify`,
   ручной разбор `certutil -template -display` по признакам выше.
2. **Event 4886/4887** (запрос и выпуск сертификата) — алерт на выпуск
   сертификата, где `Subject`/`SAN` не совпадает с учёткой заявителя,
   либо субъект — привилегированное имя (Administrator, DC, krbtgt).
3. **Event 4882/4883** — отклонённые/одобренные заявления; всплеск запросов.
4. **Event 4768** с `Certificate Issuer Name` вместо обычного логона —
   признак входа по сертификату (PKINIT).
5. Инвентаризация прав на шаблоны и на объект CA (`WriteOwner`, `WriteDacl`,
   `Enroll`, `ManageCA`).
6. Проверка `EDITF_ATTRIBUTESUBJECTALTNAME2` в `certutil -getreg policy\*`.

## Remediation

- Отключить `ENROLLEE_SUPPLIES_SUBJECT` у всех шаблонов с client-auth EKU;
  субъект задаётся из AD, а не заявителем.
- Снять `EDITF_ATTRIBUTESUBJECTALTNAME2` на CA (закрывает ESC6);
  включить `StrongCertificateBindingEnforcement = 2` (требует SID-расширение).
- Ограничить права enrollment: никаких Domain Users/Authenticated Users
  на шаблонах с client authentication; включить Manager Approval
  для чувствительных шаблонов.
- Убрать лишние EKU (`Any Purpose`), разделить шаблоны для людей/машин/агентов.
- Требовать TLS и аутентификацию на Web Enrollment (закрыть ESC8),
  отключить NTLM на HTTP-эндпоинте CA или включить EPA.
- Аудит прав на шаблоны и CA-объект (ESC4/ESC7), регулярный diff.
- Мониторинг 4886/4887/4882 и PKINIT-входов; алерт на сертификаты,
  выпущенные для привилегированных имён не их владельцами.
- Резервные копии ключей CA защищены; ротация и отзыв компрометированных
  сертификатов (CRL), планирование восстановления после компрометации CA.


## Detection rules

```yaml
title: Выпуск сертификата AD CS с чужим субъектом (ESC1-признак)
id: a1b2c3d4-0006-4a1b-9c1d-000000000006
status: experimental
description: >-
  Запрос сертификата, где атрибут Subject Alternative Name или Subject содержит
  имя, отличное от учётки заявителя, либо привилегированное имя.
logsource:
  product: windows
  service: security
  definition: 'CA-хост, аудит Certification Services (Events 4886/4887)'
detection:
  selection:
    EventID:
      - 4886    # Certificate Services received a certificate request
      - 4887    # Certificate Services approved a certificate request and issued
  priv_subject:
    Subject|contains:
      - 'Administrator'
      - 'Domain Admin'
      - 'Enterprise Admin'
      - 'krbtgt'
  condition: selection and priv_subject
falsepositives:
  - легитимный выпуск сервисных сертификатов для админ-учёток (сопоставляйте с CMDB)
level: critical
tags: [attack.credential_access, attack.t1649]
```
