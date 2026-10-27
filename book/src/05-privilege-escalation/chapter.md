---
title: "Эскалация привилегий: Linux и Windows"
chapter: 5
difficulty: advanced
category: privilege-escalation
tags: [privilege-escalation, linux, windows, sudo, suid, kernel, service]
prerequisites:
  - "Сетевая безопасность: разведка, сервисы, сегментация"
  - "Active Directory: поверхность атаки домена"
related_payloads:
  - "payloads/web/lfi-rfi/log-poisoning.md"
  - "payloads/web/lfi-rfi/proc-self-environ.md"
  - "payloads/network/redis-unauthenticated.md"
  - "payloads/cloud/docker-socket-escape.md"
  - "payloads/cloud/kubernetes-pod-sa-token.md"
lab: null
---

# Эскалация привилегий: Linux и Windows

Эскалация — это не отдельная техника, а **метод перебора всех мест, где система
доверяет вам больше, чем должна**. У вас уже есть выполнение кода от имени
обычного пользователя; дальше вы ищете объект, права на который настроены неверно:
бинарник с SUID, запись в `sudoers`, сервис, запускаемый от root, задание cron,
файл, доступный на запись, переменная окружения, capability, ядро.

Работа строится одинаково на обеих платформах: **инвентаризация → проверка
конфигурации → поиск несоответствия → безопасное подтверждение → исправление**.

## Методология

```
1. Кто я и где я            id, hostname, uname -a, cat /etc/os-release
2. Что доступно              sudo -l, capabilities, SUID/SGID, cron, services
3. Что можно записать        find -writable, /etc/passwd, пути в $PATH, конфиги
4. Что запущено от root      ps aux, systemctl list-units, netstat -tulpn
5. Что лежит рядом           секреты в файлах, истории, бэкапы, .git, docker.sock
6. Что отдаёт сеть           открытые локальные сервисы (Redis, X11, NFS)
7. Ядро и пользователи       версия ядра против известных CVE
```

## Linux

### Первый шаг: sudo и SUID

```bash
sudo -l                                  # что можно через sudo
find / -perm -4000 -type f 2>/dev/null   # SUID-бинарники
find / -perm -2000 -type f 2>/dev/null   # SGID
getcap -r / 2>/dev/null                  # file capabilities (setuid без SUID-бита)
```

Классические SUID-векторы (проверяйте по GTFOBins — база команд для каждого бинарника):

| Бинарник | Почему опасен |
|----------|---------------|
| `find -exec` | Выполнение произвольной команды от владельца бита |
| `vim`, `less`, `more` | `:!sh`, `:set shell=` — выход в оболочку |
| `python -c`, `perl -e` | Прямое выполнение кода |
| `nmap --interactive` (legacy), `nmap` + скрипт | `os.execute` |
| `tar --checkpoint-action=exec=` | Выполнение команды при архивации |
| `cp`, `mv` | Перезапись `/etc/passwd`, `/etc/shadow`, cron-файлов |
| `rsync -e` | Выполнение произвольной команды |
| `systemctl` | Чтение юнитов и `edit` -> выполнение кода |
| `pkexec` | CVE-2021-4034 (PwnKit) — исторический пример |
| `mount` | Монтирование ФС с setuid, доступ к чужим данным |

Capabilities — то, что часто забывают: `cap_setuid+ep` на `python` даёт root без
единого SUID-бита, `cap_dac_read_search` — чтение любого файла,
`cap_sys_ptrace` — инъекция в процессы root.

```bash
# пример проверки (без эксплуатации)
getcap -r / 2>/dev/null | grep -E 'setuid|dac_read_search|sys_ptrace|sys_admin'
```

### sudo-конфигурация: типовые ошибки

```sudoers
# ОПАСНО: NOPASSWD на "безобидную" утилиту
user ALL=(ALL) NOPASSWD: /usr/bin/vim, /usr/bin/find, /usr/bin/systemctl

# ОПАСНО: путь без полного указания или с wildcard
user ALL=(ALL) NOPASSWD: /usr/bin/python *, /usr/bin/less /var/log/*

# ОПАСНО: возможность повлиять на исполняемый файл через env
Defaults env_keep += "LD_PRELOAD PYTHONPATH"
```

Проверки, которые нужно делать при аудите:

* `sudoedit` с `SUDO_EDITOR` — редактор вызывается с правами root;
* wildcard в аргументах (`/var/log/*`) — можно подсунуть свой файл;
* `LD_PRELOAD`/`LD_LIBRARY_PATH` в `env_keep` — перехват библиотек;
* `runas` со списком пользователей — часто разрешён запуск от root неявно;
* относительные пути в `sudoers` (зависят от CWD).

### cron и systemd-timers

```bash
cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers --all
# скрипты, которые cron запускает от root
for f in $(grep -rhoE '/[A-Za-z0-9_./-]+\.(sh|py|pl)' /etc/cron* 2>/dev/null | sort -u); do
  ls -l "$f" 2>/dev/null
done
```

Опасно, когда:

* скрипт из cron **доступен на запись** любому пользователю;
* cron вызывает программу **без полного пути** (`backup.sh` вместо `/usr/local/bin/backup.sh`)
  и каталог из `$PATH` доступен на запись;
* скрипт использует **относительные пути** и запускается из предсказуемого каталога;
* в скрипте есть `cd` в каталог, где мы можем создать файл (перехват `.py`/`.sh`).

### Запись в системные файлы

```bash
find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev)' | head -30
ls -l /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

Если `/etc/passwd` доступен на запись — добавление пользователя с пустым полем пароля
и `uid 0` даёт root немедленно. Если доступен `/etc/sudoers.d/` — добавление своей
строки. Оба случая — грубейшая ошибка прав, встречающаяся в образах контейнеров
и в «починенных вручную» системах.

### Переменные окружения и PATH

```bash
echo $PATH
for d in ${PATH//:/ }; do [ -w "$d" ] && echo "writable in PATH: $d"; done
```

Если в `$PATH` есть каталог, доступный на запись, и privileged-скрипт вызывает
утилиту без полного пути — подменяем её своей. Аналогично работают `PYTHONPATH`,
`PERL5LIB`, `GIT_SSH`, `VISUAL`/`EDITOR`, `PAGER`, `MANPAGER`.

### Ядро и контейнеры

```bash
uname -r; cat /etc/os-release
# локальные CVE-чекеры (только как подсказка, всегда подтверждать вручную)
# linux-exploit-suggester, pspy (наблюдение за процессами в реальном времени)
```

Отдельный класс — **выход из контейнера**: `docker.sock`, `--privileged`,
`hostPath: /`, `hostPID` + `ptrace`, уязвимости рантайма. Разбор — в главе
про облака и в `payloads/cloud/docker-socket-escape.md`.

`pspy` полезен, когда эскалация происходит через короткоживущий процесс,
который не поймать в `ps`: он показывает все `execve` без root-прав.

### Linux-чек-лист

- [ ] Нет лишних SUID/SGID и file capabilities (инвентаризация + baseline).
- [ ] `sudo -l` не содержит «интерактивных» утилит, wildcard'ов и относительных путей.
- [ ] `Defaults env_reset`, никаких `env_keep` с `LD_*`/`PYTHONPATH`.
- [ ] Скрипты cron/systemd принадлежат root, права 0750 и ниже, вызываются по полному пути.
- [ ] `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*` — только root на запись.
- [ ] В `$PATH` нет каталогов, доступных на запись непривилегированным пользователям.
- [ ] Ядро обновлено; включены `kernel.dmesg_restrict=1`, `kernel.kptr_restrict=2`,
      `kernel.unprivileged_bpf_disabled=1`, `kernel.yama.ptrace_scope=1`.
- [ ] `protect-system=strict`, `PrivateTmp=`, `NoNewPrivileges=yes` в юнитах.
- [ ] Аудит включён (`auditd`) с правилами на изменения `/etc/sudoers`, SUID-файлов,
      cron-каталогов.
- [ ] Пользователи в группе `wheel`/`sudo` пересмотрены; `NOPASSWD` обоснован.

## Windows

### Первый шаг: кто я и что доступно

```powershell
whoami /all                       # SID, группы, привилегии
whoami /priv                      # какие привилегии включены (SeBackup, SeImpersonate...)
net user; net localgroup administrators
systeminfo                        # версия ОС и список хотфиксов
```

Привилегии, которые сами по себе ведут к SYSTEM:

| Привилегия | Как используется |
|------------|------------------|
| `SeImpersonatePrivilege` | Класс Potato-атак: создание сервиса от имени SYSTEM (сервисные учётки, IIS apppool) |
| `SeBackupPrivilege` | Чтение любого файла, включая `SAM`/`SYSTEM` (dump реестра) |
| `SeRestorePrivilege` | Запись в защищённые файлы (сервисы, DLL) |
| `SeDebugPrivilege` | Открытие процесса LSASS -> дампы учётных данных |
| `SeLoadDriverPrivilege` | Загрузка уязвимого драйвера (BYOVD) |
| `SeTakeOwnershipPrivilege` | Смена владельца объекта |
| `SeTcbPrivilege` | Повышение через TCB (редко, обычно = SYSTEM) |

### Сервисы: самая частая находка

```powershell
# сервисы с небезопасными правами на бинарник/каталог
Get-CimInstance Win32_Service | ? { $_.PathName } |
  Select Name, StartName, State, PathName | Format-Table -Wrap

# слабые ACL на путях сервисов (нужен accesschk из Sysinternals)
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwqs Users "C:\Program Files\*"
```

Что искать:

* **unquoted service path** — путь с пробелами без кавычек: `C:\Program Files\App\svc.exe`
  позволяет подложить `C:\Program.exe` или `C:\Program Files\App.exe`;
* **бинарник сервиса доступен на запись** — прямая подмена;
* **каталог в пути доступен на запись** — подмена DLL или exe;
* **сервис запускается от SYSTEM**, а права на изменение — у обычных пользователей
  (`NT AUTHORITY\Authenticated Users`);
* **AlwaysInstallElevated** — MSI-пакеты ставятся от SYSTEM:
  `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`.

```powershell
# проверка unquoted paths
Get-CimInstance Win32_Service | ? {
  $_.PathName -match ' ' -and $_.PathName -notmatch '"' } |
  Select Name, PathName
# AlwaysInstallElevated
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -EA 0
Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -EA 0
```

### Автозапуск и планировщик задач

```powershell
Get-CimInstance Win32_StartupCommand | Select Name, Command, Location, User
schtasks /query /fo LIST /v | Select-String -Pattern "TaskName|Run As|Task To Run" -Context 0,1
# ACL на ключах автозапуска
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Опасно, когда скрипт/бинарник из автозапуска лежит в каталоге, доступном на запись
пользователям (частая ситуация: `C:\ProgramData\...`, `C:\Users\Public\...`).

### DLL-перехват (hijacking)

Приложение ищет DLL в порядке: каталог приложения → системные → `%PATH%`.
Если DLL отсутствует, а каталог из `%PATH` доступен на запись — подменяем.

```powershell
# что грузит процесс (Process Monitor: Result = NAME NOT FOUND + Path ends with .dll)
# каталоги из PATH, доступные на запись
$env:Path -split ';' | ? { $_ -and (Test-Path $_) } | % {
  $acl = Get-Acl $_
  if ($acl.Access | ? { $_.IdentityReference -match 'Users|Everyone|Authenticated' `
        -and $_.FileSystemRights -match 'Write|Modify|FullControl' }) { $_ }
}
```

Защита: `SafeDllSearchMode`, `LOAD_LIBRARY_SEARCH_*`, подпись DLL, запрет записи
в каталоги из `%PATH` для обычных пользователей.

### Учётные данные, которые лежат рядом

| Где | Что |
|-----|-----|
| `LSASS` | Хеши/билеты (нужен SeDebugPrivilege; защита — Credential Guard, LSA PPL) |
| `HKLM\SAM` + `HKLM\SYSTEM` | Локальные хеши (dump через reg save / VSS) |
| DPAPI (`%APPDATA%\Microsoft\Protect`) | Защищённые мастер-ключом секреты |
| Credential Manager (`cmdkey /list`) | Сохранённые пароли |
| `Unattend.xml`, `Sysprep.inf` | Пароли в открытом/base64 виде |
| История PowerShell, `ConsoleHost_history.txt` | Пароли в командах |
| Файлы `web.config`, `appsettings.json` | Connection strings |
| GPP `Groups.xml` в SYSVOL | CPASS-пароли (MS14-025) |
| KeePass-базы + `KeePass.config.xml` | Мастера защиты памяти (KeeThief-класс) |
| Браузеры, почтовые клиенты | Сохранённые пароли |
| `\\localhost\c$` и админ-шары | Доступ при наличии локального админа |

Практический вывод для защиты: **Credential Guard + LSA Protection + LAPS +
отсутствие одинаковых локальных админов** закрывают большую часть этого списка.

### Домен: после локального root/SYSTEM

Локальный админ на рабочей станции — не цель, а ступень. Дальше идут техники
из главы про Active Directory: перехват сессий, Kerberos-атаки, ACL-пути
в BloodHound, делегирование, ADCS. Отдельно стоит помнить про tiering:
если админ Tier 0 не заходит на машины Tier 2, перехват хеша на рабочей станции
не даёт доступа к контроллеру домена.

### Windows-чек-лист

- [ ] Нет сервисов с unquoted path и с бинарниками/каталогами, доступными на запись.
- [ ] `AlwaysInstallElevated` выключен (HKLM и HKCU).
- [ ] В `%PATH` нет каталогов, доступных на запись пользователям.
- [ ] Автозапуск и планировщик ссылаются на файлы с правами только для администраторов.
- [ ] Локальные админ-пароли уникальны (LAPS); встроенный Administrator отключён/переименован.
- [ ] `SeImpersonatePrivilege` не выдан сервисным учёткам без необходимости.
- [ ] Credential Guard / LSA PPL / HVCI включены на всех поддерживаемых системах.
- [ ] PowerShell: Constrained Language Mode, ScriptBlock Logging, AMSI активны.
- [ ] Аудит процессов (4688 с командной строкой), установки драйверов (Sysmon 6),
      доступа к LSASS (Sysmon 10), изменений служб (7045).
- [ ] Нет «забытых» админ-учёток, сервисов от имени доменного админа, и общих паролей.

## Автоматизация разведки (и почему её мало)

Скрипты-агрегаторы (`linpeas`, `winpeas`, `Seatbelt`, `PowerUp`, `JAWS`) экономят
время, но дают **гипотезы**, а не выводы. Каждую находку нужно подтверждать:

1. Понять механизм (почему это работает).
2. Проверить права и контекст (кто владелец, кто может запустить).
3. Подтвердить безопасно (не перезаписывая критичные файлы; в лабе — да, в бою — нет).
4. Описать в отчёте с remediation, а не только с PoC.

В CI этого репозитория `tools/payload-tester.sh` прогоняет безопасные проверки
против лабораторий, чтобы карточки payload'ов не «протухали».

## Практика

```bash
cd labs/network-labs
docker compose up -d priv-esc-lab      # контейнер с намеренно слабыми правами
docker exec -it hackbook-priv-esc bash # вход от пользователя lowpriv
```

Задания (все — в контейнере, ничего не ломает хост):

1. Соберите полную картину прав: `id`, `sudo -l`, SUID-список, capabilities, cron.
2. Найдите SUID-бинарник, который позволяет выполнить команду, и объясните механизм.
3. Найдите cron-скрипт, вызываемый без полного пути, и подтвердите перехват через `$PATH`.
4. Найдите запись в `/etc/sudoers.d/` с wildcard и объясните, как её ограничить.
5. Почините все четыре находки и повторите проверку — эскалация должна перестать работать.
6. Напишите правило `auditd`, которое логирует изменения SUID-битов и `/etc/sudoers`.
