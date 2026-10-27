---
id: rdp-exposure
title: "RDP: публикация 3389, NLA, CredSSP и перехват сессий"
type: network
target: rdp
category: web
difficulty: intermediate
bypass: none
tags: [network, rdp, 3389, nla, exposure, lateral-movement, shadowing]
tested_on: ["Windows Server 2022 (собственная ВМ)", "сканирование лабораторной сети"]
success_rate: 0.75
risk: high
cwe: "CWE-300"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/techniques/T1021/001/"
  - "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-users"
---

# RDP: публикация 3389, NLA, CredSSP и перехват сессий

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) доступен ли RDP извне (проверка своей инфраструктуры)
python3 - <<'PY'
import socket, sys
host, port = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1', 3389
try:
    s = socket.create_connection((host, port), timeout=6)
    # X.224 Connection Request с запросом протокола CredSSP/NLA
    req = bytes.fromhex('030000130ee00100000000000000000000000000')
    s.sendall(req); data = s.recv(64)
    print('RDP отвечает:', data.hex())
    s.close()
except Exception as e:
    print('нет доступа:', e.__class__.__name__, e)
PY

# 2) конфигурация на сервере (Windows, своя ВМ)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer
# fDenyTSConnections=0 -> RDP включён
# UserAuthentication=0 -> NLA ОТКЛЮЧЁН (опасно: MITM, DoS до аутентификации)
# SecurityLayer=0/1    -> RDP Security / Negotiate (2 = TLS + NLA)

# 3) кто разрешён к подключению
net localgroup "Remote Desktop Users"
qwinsta /server:localhost

# 4) перехват/тень сессий (административная функция, требующая контроля)
query session
# shadow-режим: tscon <id> /dest:rdp-tcp#0  (подключение к чужой сессии
# без пароля при определённых политиках) — проверяйте GPO
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

# 5) признаки эксплуатации (BlueKeep-класс) — только как индикатор патч-уровня
wmic qfe get HotFixID,InstalledOn | findstr /i "4500331 4499149 4499180"

# 6) сетевая разведка (своя сеть)
# nmap -p 3389 --script rdp-ntlm-info,rdp-vuln-ms12-020,rdp-enum-encryption <своя подсеть>
```

## Explanation

RDP — самый частый вектор первоначального доступа в инцидентах с
шифровальщиками. Проблемы делятся на четыре группы:

1. **Публикация порта 3389 в интернет** (или проброс через NAT/VPN-дыры).
    Даже с NLA это даёт площадку для перебора паролей и эксплуатации
    уязвимостей протокола. Правильная модель: RDP только из VPN или
    через шлюз удалённого доступа (RD Gateway) с MFA.
2. **Отключённый NLA** (`UserAuthentication=0`). Без NLA аутентификация
    происходит после установления сессии: сервер уязвим к DoS и MITM
    до проверки учётных данных, а также к ряду исторических уязвимостей
    (MS12-020, BlueKeep-класс), которые частично требуют именно
    такого режима.
3. **Учётные данные и NTLM**: RDP по умолчанию может использовать NTLM,
    что открывает relay-атаки (`ntlmrelayx` на RDP/SMB/LDAP).
    Плюс кэширование учётных данных в Credential Manager и
    `Restricted Admin`/`Remote Credential Guard` — режимы, которые
    при неправильном применении раскрывают хеши.
4. **Перехват сессий (shadowing)**: административная функция
    «подключиться к сессии пользователя» без его пароля. При слабой
    политике (`Shadow=2` — без уведомления) компрометация админ-учётки
    даёт бесшумный доступ к активным сессиям.

Смежные проблемы: локальные админы с одинаковыми паролями (LAPS решает),
общие учётки, отсутствие ограничений по времени/IP, RDP-порты,
проброшенные на контроллеры домена.

## Detection

* EventID 4624 (Logon Type 10 — RemoteInteractive) и 4625 (failed):
  всплеск неудачных входов типа 10 — перебор RDP.
* EventID 4778/4779 (переподключение/отключение сессии),
  21/22/23/24/25 в `TerminalServices-LocalSessionManager` — полная
  картина сессий.
* Алерт на `RemoteInteractive`-вход в нерабочее время или с новых IP.
* Детект shadowing: EventID 4624 type 10 с учёткой, отличной от
  владельца сессии; изменение политики `Shadow` в реестре (Sysmon 13).
* Сетевой детект: входящие соединения на 3389 из интернета; X.224
  handshake с аномальными параметрами (признак сканирования/эксплуатации).
* EventID 4648 (вход с явными учётными данными) — признак использования
  чужих кредов для RDP.
* Мониторинг `tscon`/`qwinsta`/`mstsc` с флагами shadow.
* NTLM-аудит: EventID 4624 с `Authentication Package: NTLM` для
  RemoteInteractive — повод перевести на Kerberos.

## Remediation

- Не публиковать 3389. Доступ через VPN или RD Gateway с MFA
  (HTTPS/443), либо через bastion с записью сессий.
- Включить NLA: `UserAuthentication=1`, `SecurityLayer=2`
  (GPO: Computer Configuration → Administrative Templates →
  Windows Components → Remote Desktop Services → … → Require user
  authentication for remote connections by using NLA).
- Требовать Kerberos, отключить NTLM где возможно; включить
  `Restricted Admin`/`Remote Credential Guard` только после понимания
  модели (они защищают клиент, но имеют свои ограничения).
- LAPS для локальных админов; отдельные привилегированные учётки;
  запрет интерактивного входа доменных админов на рабочие станции.
- Ограничить членство в `Remote Desktop Users`; убрать локальных
  администраторов из разрешённых к RDP где возможно.
- Политика shadowing: `Shadow=0` (запрет) или `Shadow=1`
  (с уведомлением и согласием пользователя).
- Патчи: своевременная установка обновлений RDP-компонентов;
  отключить RDP там, где он не нужен.
- Сетевые ACL/брандмауэр: источник — только управляющая подсеть;
  блокировка исходящего 3389 (признак закрепления/латерала).
- Ограничение времени сессий и автоотключение простоя.
- Мониторинг и алерты на аномальные RDP-входы (см. детект).


## Detection rules

```yaml
title: "Аномальная RDP-активность: перебор, shadowing и входы в нерабочее время"
id: d4e5f6a7-0003-4d4e-8f5a-000000000303
status: test
description: >-
  Неудачные RemoteInteractive-входы пачками, подключение к чужой сессии
  (shadowing), а также успешные RDP-входы привилегированных учёток с новых адресов.
references:
  - https://attack.mitre.org/techniques/T1021/001/
  - https://attack.mitre.org/techniques/T1136/
logsource:
  product: windows
  service: security
  definition: 'EventID 4624/4625 (LogonType 10), 4778/4779, TerminalServices-LocalSessionManager'
detection:
  failed_rdp:
    EventID: 4625
    LogonType: 10
  success_rdp:
    EventID: 4624
    LogonType: 10
  reconnect:
    EventID:
      - 4778
      - 4779
  shadow_tool:
    EventID: 4688
    CommandLine|contains:
      - 'tscon'
      - ' /shadow'
      - 'qwinsta'
  ntlm_rdp:
    EventID: 4624
    LogonType: 10
    AuthenticationPackageName: NTLM
  timeframe: 10m
  condition: shadow_tool or (failed_rdp | count() by IpAddress > 10) or (success_rdp and ntlm_rdp) or reconnect
fields:
  - IpAddress
  - TargetUserName
  - LogonType
  - AuthenticationPackageName
  - CommandLine
falsepositives:
  - легитимная поддержка с подключением к сессиям (фиксируйте список учёток и Shadow-политику)
  - переключения сессий администраторами между хостами
level: high
tags:
  - attack.lateral_movement
  - attack.initial_access
  - attack.t1021.001
```
