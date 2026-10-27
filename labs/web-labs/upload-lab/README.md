# upload-lab — лаборатория загрузки файлов

Намеренно уязвимое приложение на Python stdlib. Соответствует главе 1
(«Web Security») и карточкам `payloads/web/upload/`.

```bash
cd labs/setup && docker compose up -d upload-lab
# или без Docker:
UPLOAD_DIR=/tmp/up STATE_DB=/tmp/up/app.db PORT=8082 \
  python3 labs/web-labs/upload-lab/app.py
```

URL: http://localhost:8082

## Карта эндпоинтов

| Эндпоинт | Поведение |
|----------|-----------|
| `POST /upload` | **УЯЗВИМО**: blacklist расширений (`.php .exe .sh`), `Content-Type` берётся из клиента, файл сохраняется под оригинальным именем |
| `POST /upload_safe` | whitelist расширений, проверка magic bytes, запрет исполняемых конструкций в `.txt`, имя = UUID |
| `GET /uploads/<name>` | отдаёт загруженный файл; `Content-Type` определяется по расширению |
| `GET /profile` | **УЯЗВИМО**: имена файлов выводятся без экранирования → stored XSS |
| `GET /files` | JSON-список загруженного (оригинальные и сохранённые имена) |
| `GET /health` | healthcheck |

## Важно понимать

Приложение написано на Python, поэтому **PHP-код в нём не исполняется**.
Учебная цель — показать цепочку ошибок, которая в реальном стеке
(Apache+PHP, IIS+ASP.NET, nginx+PHP-FPM, Tomcat+JSP) даёт выполнение кода:

1. blacklist расширений пропускает `.php5`, `.phtml`, `.phar`, `.php.jpg`, `.PhP`;
2. доверие `Content-Type` от клиента пропускает код под видом `image/png`;
3. полиглот `GIF89a;<?php … ?>` проходит проверку «это изображение»;
4. сохранение под оригинальным именем даёт stored XSS в `/profile`
   и неконтролируемые имена в каталоге;
5. файл доступен по предсказуемому URL в веб-пространстве.

Разделители пути в имени заменяются на `_`, поэтому выход за пределы каталога
загрузок в этой лабе не работает — это сделано намеренно, чтобы задание
оставалось воспроизводимым и безопасным. Полноценный traversal демонстрируется
в теории карточкой `upload-filename-path-traversal`.

## Задания

### 1. Обход blacklist расширений

```bash
python3 tools/lib/http_fetch.py http://localhost:8082/upload 5 POST "" \
  "file=probe.php;content=<?php echo 1; ?>"        # -> «запрещено»
python3 tools/lib/http_fetch.py http://localhost:8082/upload 5 POST "" \
  "file=probe.php5;content=<?php echo 1; ?>"       # -> принят
```

Проверьте по очереди: `.phtml`, `.phar`, `.php.jpg`, `.PhP`, `.php%20`,
`.htaccess`. Какие приняты и почему? Сформулируйте, чем whitelist отличается
от blacklist с точки зрения сопровождения.

### 2. Доверие клиентскому MIME

Загрузите файл с PHP-кодом и `Content-Type: image/png` — приложение примет его,
потому что тип берётся из заголовка части multipart, а не из содержимого.
Найдите в `app.py` место, где это происходит, и объясните, какая проверка
должна быть вместо этого (magic bytes + пересборка изображения).

### 3. Полиглот

```bash
python3 tools/lib/http_fetch.py http://localhost:8082/upload 5 POST "" \
  "file=polyglot.gif;content=GIF89a;<?php echo 'HBMARK'; ?>"
```

Файл принят и доступен по `/uploads/polyglot.gif`. Объясните, почему
`getimagesize()`-подобные проверки его пропускают и что делает пересборка
изображения декодером.

### 4. Stored XSS через имя файла

```bash
python3 tools/lib/http_fetch.py http://localhost:8082/upload 5 POST "" \
  "file=<svg onload=alert(document.domain)>.txt;content=x"
# затем откройте /profile в браузере
```

Критерий: скрипт исполняется на странице профиля. Почините вывод
(`html.escape`) и убедитесь, что вектор больше не срабатывает.

### 5. Сравнение с безопасным эндпоинтом

Повторите задания 1–4 на `/upload_safe` и зафиксируйте, какая именно мера
блокирует каждый вектор:

| Вектор | Мера в `/upload_safe` |
|--------|-----------------------|
| `.php5`, `.phtml`, `.php.jpg` | whitelist расширений |
| код под видом `image/png` | проверка magic bytes |
| PHP внутри `.txt` | запрет исполняемых конструкций |
| XSS через имя | имя не используется: UUID + экранирование при выводе |
| предсказуемый URL | непредсказуемое имя |

### 6. Починить уязвимый эндпоинт

Минимальный набор изменений (образец — `handle_safe` в `app.py`):

1. whitelist расширений вместо blacklist;
2. определение типа по содержимому, а не по заголовку клиента;
3. пересборка изображений (в stdlib нет декодера — зафиксируйте как TODO
   и обсудите, какая библиотека нужна в реальном стеке);
4. генерируемое имя файла, оригинал — только в БД и только экранированным;
5. хранение вне веб-корня и отдача с `Content-Disposition: attachment`;
6. запрет исполнения скриптов в каталоге загрузок (на уровне веб-сервера).

После починки:

```bash
tools/payload-tester.sh --lab upload-lab    # карточки должны перестать проходить
```

### 7. Что видно в логах

```bash
docker compose logs upload-lab | grep -iE "upload|POST"
python3 tools/lib/http_fetch.py http://localhost:8082/files
```

Сформулируйте правило детектирования: загрузка файла с исполняемым расширением
или с именем, содержащим HTML-разметку, с последующим GET к `/uploads/…`
(см. главу 7 и секцию `Detection rules` в карточке
`upload-extension-blacklist-bypass`).

## Автоматические тесты

```bash
tools/payload-tester.sh --lab upload-lab --report reports/upload.json
tools/payload-tester.sh --lab upload-lab --list
```

Критерий `PASS`: файл принят и сохранён (в ответе «Файл принят»/«Сохранён как»)
и при этом не сработали защитные сообщения. Для `/upload_safe` ожидаемый
результат — отказ.

## Артефакты для разбора

* `payloads/web/upload/extension-blacklist-bypass.md` (+ Sigma-правило)
* `payloads/web/upload/mime-content-type-spoof.md`
* `payloads/web/upload/magic-bytes-polyglot.md`
* `payloads/web/upload/htaccess-handler-override.md`
* `payloads/web/upload/filename-path-traversal.md`
* `payloads/web/upload/svg-stored-xss.md`
* `payloads/web/upload/zip-slip-archive.md`
* `payloads/web/upload/race-double-extension.md`
