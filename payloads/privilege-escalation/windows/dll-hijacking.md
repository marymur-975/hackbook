---
id: windows-dll-hijacking
title: "Windows: DLL hijacking (перехват поиска библиотек)"
type: privesc
target: windows
category: web
difficulty: intermediate
bypass: none
tags: [privesc, windows, dll-hijacking, dll-search-order, persistence]
tested_on: ["Windows 10/11, Windows Server 2022 (собственные ВМ)"]
success_rate: 0.5
risk: high
cwe: "CWE-427"
lab: null
last_verified: "2026-10-23"
references:
  - "https://attack.mitre.org/techniques/T1574/001/"
  - "https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order"
---

# Windows: DLL hijacking (перехват поиска библиотек)

!!! warning "Этика"
    Только лаборатории `hackbook` или системы с письменным разрешением на тестирование.

## Payload
```
# 1) какие DLL ищет процесс: Process Monitor (своя ВМ)
#    Filter: Process Name = <target>.exe, Path contains .dll,
#    Result = NAME NOT FOUND  -> кандидат на перехват

# 2) где процесс ищет (порядок по умолчанию):
#    a) каталог, из которого запущен EXE
#    b) System32, SysWOW64
#    c) Windows
#    d) текущий рабочий каталог (CWD)
#    e) каталоги из PATH
#    -> перехват возможен, если запись есть в (a), (d) или (e)

# 3) проверка PATH на записываемые каталоги
echo %PATH% | tr ';' '\n' | for /f "delims=" %d in ('more') do @icacls "%d" | findstr /i "Users:(M) Users:(F) Authenticated"

# 4) KnownDLLs: список DLL, которые всегда грузятся из System32
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"

# 5) безопасная проверка (стенд): положить свою DLL в найденный
#    записываемый каталог и запустить целевой EXE; DLL должна содержать
#    только экспорты-заглушки оригинала + лог факта загрузки (Proof of Concept)
#    Пример экспорта-заглушки: extern "C" __declspec(dllexport) void Fn()
#    и DllMain, пишущий отметку в C:\Temp\HB-DLL-LOADED.txt

# 6) Phantom-DLL: зависимость, которой нет на диске (часто в каталоге EXE)
#    -> положить DLL с нужным именем
```

## Explanation

Поиск DLL в Windows идёт по определённому порядку. Перехват возможен,
когда **раньше легитимного каталога** в поиске оказывается путь, куда
непривилегированный пользователь может писать. Три типовых случая:

1. **Каталог приложения доступен на запись** (`C:\Program Files\App`
    с `Users:(M)` — ошибка установщика). DLL, лежащая рядом с EXE,
    загружается первой.
2. **Отсутствующая (phantom) зависимость**: приложение ищет DLL, которой
    нет в комплекте (опциональный компонент, языковой пакет, драйвер).
    Поиск доходит до каталога EXE или CWD — туда и кладётся подделка.
3. **Записываемый каталог в PATH** (редко, но встречается: `C:\Temp`,
    сетевые шары, пользовательские каталоги в системном PATH).
4. **CWD-перехват**: если EXE запускается из каталога, куда есть запись
    (например, через ярлык или планировщик с рабочей папкой в `%TEMP%`).

Значение для эскалации: если перехваченная DLL загружается
привилегированным процессом (служба, автозапуск от администратора),
код выполняется с его правами. Значение для закрепления: подмена DLL
часто переживает обновления и не меняет реестр, поэтому остаётся
незамеченной.

Как искать: Process Monitor с фильтром `Result = NAME NOT FOUND` по
`.dll`, затем проверка ACL найденных каталогов. Автоматизация —
специализированные инструменты аудита DLL-поиска (на своей ВМ).

Важно: `KnownDLLs` не перехватываются (всегда грузятся из System32),
а `SafeDllSearchMode` убирает CWD из ранней позиции — но не защищает
от записи в каталог приложения.

## Detection

* Sysmon EventID 7 (ImageLoad): загрузка DLL из нестандартных каталогов
  (`\Users\`, `\Temp\`, `\ProgramData\`, `\Downloads\`) — особенно
  для процессов из `Program Files`.
* EventID 7 с отсутствующей или не-майкрософтовской подписью у DLL,
  загруженной подписанным EXE.
* EventID 11 (FileCreate): появление `.dll` в каталогах, где её не было
  (сравнение с baseline-инвентаризацией).
* Алерт на `NAME NOT FOUND`-паттерн в EDR-телеметрии (если доступна).
* Контроль ACL: регулярный скан `icacls` по каталогам установленного
  ПО на наличие записи для `Users`/`Authenticated Users`.
* Контроль `PATH`: записываемые каталоги в системном PATH — алерт.
* EventID 4688: процесс из `Program Files`, порождённый с CWD в `Temp`.

## Remediation

- Установщики: файлы только в защищённые каталоги, ACL без записи для
  `Users`/`Authenticated Users`; обновления выполняются от elevated-контекста.
- Загружать зависимости по полному пути (`LoadLibraryEx` с
  `LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR`).
- Включить `SafeDllSearchMode`, установить `CwdIllegalInDllSearch=2`
  (запрет CWD в поиске), использовать manifests с явными зависимостями.
- Проверять целостность: подписи DLL и блокировка загрузки
  неподписанных (`EnforceSignatureChecking`, WDAC/AppLocker в режиме
  enforcement для DLL).
- Системный PATH: только защищённые каталоги; аудит на записываемые
  элементы.
- Убирать неиспользуемые зависимости (phantom DLL) из кода.
- Включить HVCI/Memory Integrity и контроль драйверов: часть техник
  требует загрузки кода в ядро.


## Detection rules

```yaml
title: Загрузка DLL из пользовательского каталога процессом из Program Files
id: c3d4e5f6-0010-4c3d-9e4f-000000000210
status: experimental
description: >-
  Признак DLL hijacking: привилегированный или установленный процесс загружает
  библиотеку из каталога, доступного на запись пользователю.
references:
  - https://attack.mitre.org/techniques/T1574/001/
  - https://attack.mitre.org/techniques/T1574/007/
logsource:
  product: windows
  service: sysmon
  definition: 'Sysmon EventID 7 (Image Loaded), 11 (File Create)'
detection:
  load_from_user_dirs:
    EventID: 7
    ImageLoaded|contains:
      - '\Users\Public\'
      - '\AppData\Local\Temp\'
      - '\ProgramData\'
      - '\Users\Default\'
      - '\Windows\Temp\'
      - '\Downloads\'
  image_is_installed:
    Image|contains:
      - '\Program Files\'
      - '\Program Files (x86)\'
      - '\Windows\System32\'
  unsigned_dll:
    Signed: 'false'
  new_dll_in_appdir:
    EventID: 11
    TargetFilename|contains:
      - '\Program Files\'
    TargetFilename|endswith: '.dll'
  condition: (load_from_user_dirs and image_is_installed) or (load_from_user_dirs and unsigned_dll) or new_dll_in_appdir
fields:
  - Image
  - ImageLoaded
  - Signed
  - User
falsepositives:
  - установщики и апдейтеры, легитимно пишущие в Program Files (фильтр по подписи Image)
  - приложения, использующие ProgramData для кэшей (уточните список DLL)
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1574.001
```
