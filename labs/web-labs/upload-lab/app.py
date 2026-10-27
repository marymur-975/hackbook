#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Уязвимое приложение для лаборатории загрузки файлов.

Только стандартная библиотека Python. Уязвимости НАМЕРЕННЫЕ — приложение
работает исключительно в изолированном контейнере лабораторий hackbook.

Эндпоинты:
    GET  /                    — задания и карта эндпоинтов
    GET  /upload              — форма загрузки (уязвимая)
    POST /upload              — УЯЗВИМО: blacklist расширений + MIME из клиента
                                + сохранение под оригинальным именем
    POST /upload_safe         — whitelist расширений, переименование в UUID,
                                проверка magic bytes, отдача как attachment
    GET  /uploads/<name>      — статика (для уязвимого варианта)
    GET  /files               — список загруженного
    GET  /profile             — УЯЗВИМО: имя файла выводится без экранирования
                                (stored XSS через filename)
    GET  /health              — healthcheck

Окружение:
    UPLOAD_DIR  каталог загрузок (по умолчанию /data/uploads)
    STATE_DB    путь к SQLite со списком файлов (по умолчанию /data/app.db)
    PORT        порт (по умолчанию 8080)

Примечание для заданий: Python-приложение не исполняет PHP, поэтому
«webshell здесь не запустится». Учебная цель — показать, что файл
СОХРАНЯЕТСЯ под контролируемым именем и становится доступен по URL:
в реальном стеке (Apache+PHP, IIS+ASP, nginx+PHP-FPM) это выполнение кода.
Отдельно отрабатывается traversal в имени файла и stored XSS через filename.
"""

from __future__ import annotations

import html
import json
import os
import re
import secrets
import sqlite3
import sys
import urllib.parse
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/data/uploads")
STATE_DB = os.environ.get("STATE_DB", "/data/app.db")
PORT = int(os.environ.get("PORT", "8080"))
MAX_SIZE = 2 * 1024 * 1024

# НАМЕРЕННО неполный blacklist — классическая ошибка
BLACKLIST_EXT = {".php", ".exe", ".sh"}
WHITELIST_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt"}
MAGIC = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"%PDF": "pdf",
}

PAGE_CSS = """
body{font:16px/1.6 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;margin:0;
     background:#f6f7f9;color:#1c1e21}
header{background:#c2255c;color:#fff;padding:.8rem 1.4rem}
main{max-width:56rem;margin:1.4rem auto;padding:0 1rem}
.card{background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:1rem 1.2rem;margin:.9rem 0}
code{background:#f1f3f5;border-radius:4px;padding:.1rem .3rem;
     font-family:ui-monospace,Consolas,monospace;font-size:.9em}
pre{background:#f1f3f5;border-left:3px solid #c2255c;border-radius:6px;padding:.7rem;
    overflow-x:auto;font-family:ui-monospace,Consolas,monospace;font-size:.85rem}
.warn{background:#fff9db;border-left:4px solid #f59f00;padding:.7rem 1rem;border-radius:6px}
.error{background:#fff0f0;border-left:4px solid #e03131;padding:.7rem 1rem;border-radius:6px}
.ok{background:#e6fcf5;border-left:4px solid #12b886;padding:.7rem 1rem;border-radius:6px}
table{border-collapse:collapse;width:100%} th,td{border:1px solid #dfe3e8;padding:.4rem .6rem}
th{background:#f1f3f5} button{background:#c2255c;color:#fff;border:0;border-radius:5px;
padding:.45rem .9rem;cursor:pointer} input[type=text]{padding:.4rem .6rem;border:1px solid
#ced4da;border-radius:5px;width:20rem} a{color:#c2255c} small{color:#5b6472}
"""

INDEX_BODY = """
<div class="warn"><b>Внимание.</b> Приложение намеренно принимает файлы с
контролируемым именем и публикует их. Только изолированная лаборатория.</div>

<div class="card"><h2>Эндпоинты</h2>
<table><thead><tr><th>URL</th><th>Поведение</th></tr></thead><tbody>
<tr><td><code>POST /upload</code></td><td>УЯЗВИМО: blacklist расширений,
    MIME из клиента, сохранение под оригинальным именем (traversal),
    выдача по <code>/uploads/&lt;имя&gt;</code></td></tr>
<tr><td><code>POST /upload_safe</code></td><td>whitelist расширений, magic bytes,
    имя = UUID, отдача как <code>attachment</code></td></tr>
<tr><td><code>GET /files</code></td><td>список загруженного (JSON)</td></tr>
<tr><td><code>GET /profile</code></td><td>УЯЗВИМО: имя файла выводится
    без экранирования (stored XSS)</td></tr>
</tbody></table>
<p><a href="/upload">Форма загрузки</a></p></div>

<div class="card"><h2>Задания</h2><ol>
<li>Загрузите <code>probe.php</code> — отклонено blacklist'ом. Затем
    <code>probe.phtml</code>, <code>probe.phar</code>, <code>probe.php.jpg</code>,
    <code>probe.PhP</code> — какие прошли? Объясните, почему blacklist проигрывает.</li>
<li>Загрузите файл с PHP-кодом и <code>Content-Type: image/png</code> —
    подтвердите, что тип берётся из клиента.</li>
<li>Создайте полиглот <code>GIF89a;&lt;?php echo 'HBMARK'; ?&gt;</code>,
    загрузите как <code>.gif</code> и объясните, какая проверка его пропустила.</li>
<li>Загрузите файл с именем <code>../../hb-traversal.txt</code> и проверьте,
    где он оказался (в лабе — внутри <code>/data</code>, но путь изменился).</li>
<li>Загрузите файл с именем <code>&lt;svg onload=alert(document.domain)&gt;.txt</code>
    и откройте <code>/profile</code> — stored XSS через filename.</li>
<li>Сравните с <code>/upload_safe</code>: какие из пунктов 1–5 перестали работать
    и за счёт какой именно меры?</li>
<li>Почините <code>/upload</code>: whitelist + переименование + хранение вне
    веб-корня + отдача как attachment. Перепроверьте пункты 1–5 и
    <code>tools/payload-tester.sh --lab upload-lab</code>.</li>
</ol>
<p><small>Карточки: <code>payloads/web/upload/</code>. В реальном стеке
(Apache+PHP / IIS / nginx+PHP-FPM) пункты 1–3 дают выполнение кода —
см. секции Detection/Remediation каждой карточки.</small></p></div>
"""


def connect() -> sqlite3.Connection:
    directory = os.path.dirname(STATE_DB)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(STATE_DB, check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = connect()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS files (
               id INTEGER PRIMARY KEY,
               original_name TEXT NOT NULL,
               stored_name TEXT NOT NULL,
               content_type TEXT,
               size INTEGER,
               endpoint TEXT,
               created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    conn.close()


def magic_kind(data: bytes) -> str | None:
    for signature, kind in MAGIC.items():
        if data.startswith(signature):
            return kind
    return None


def parse_multipart(body: bytes, boundary: str) -> tuple[str, bytes, str]:
    """Минимальный парсер multipart/form-data: (filename, data, content_type)."""
    marker = ("--" + boundary).encode()
    parts = body.split(marker)
    for part in parts:
        part = part.strip(b"\r\n")
        if not part or b"Content-Disposition" not in part:
            continue
        head_blob, _, data = part.partition(b"\r\n\r\n")
        head = head_blob.decode("utf-8", "replace")
        if 'name="file"' not in head and "filename=" not in head:
            continue
        name_match = re.search(r'filename="([^"]*)"', head)
        filename = name_match.group(1) if name_match else "upload.bin"
        type_match = re.search(r"Content-Type:\s*([^\r\n]+)", head)
        content_type = type_match.group(1).strip() if type_match else "application/octet-stream"
        return filename, data.rstrip(b"\r\n"), content_type
    return "", b"", ""


class Handler(BaseHTTPRequestHandler):
    server_version = "hackbook-upload-lab/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write("[lab] %s\n" % (fmt % args))
        sys.stdout.flush()

    # ── утилиты ───────────────────────────────────────────────────────
    def _send(self, body: str, status: int = 200,
              content_type: str = "text/html; charset=utf-8",
              extra_headers: dict | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _page(self, inner: str, status: int = 200) -> None:
        self._send("<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>"
                   "<title>hackbook · Upload Lab</title>"
                   f"<style>{PAGE_CSS}</style></head><body>"
                   "<header><b>hackbook / Upload Lab</b></header>"
                   f"<main>{inner}</main></body></html>", status)

    def _record(self, original: str, stored: str, content_type: str,
                size: int, endpoint: str) -> None:
        conn = connect()
        try:
            conn.execute(
                "INSERT INTO files (original_name, stored_name, content_type, size, endpoint)"
                " VALUES (?,?,?,?,?)", (original[:300], stored[:300], content_type[:120],
                                      size, endpoint[:40]))
            conn.commit()
        finally:
            conn.close()

    def _save(self, data: bytes, stored_name: str) -> str:
        target = os.path.join(UPLOAD_DIR, stored_name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data)
        return target

    # ── маршруты ──────────────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        route = urllib.parse.unquote(parsed.path)

        if route == "/health":
            self._send("ok\n", 200, "text/plain; charset=utf-8")
        elif route == "/":
            self._page(INDEX_BODY)
        elif route == "/upload":
            self._page(
                "<div class='card'><h2>Загрузка файла (уязвимый эндпоинт)</h2>"
                "<form method='post' action='/upload' enctype='multipart/form-data'>"
                "<p><input type='text' name='file' style='display:none'>"
                "<input type='file' name='file'></p>"
                "<p><button type='submit'>Загрузить</button></p></form>"
                "<p><small>Blacklist: <code>" + ", ".join(sorted(BLACKLIST_EXT)) +
                "</code>. MIME берётся из запроса клиента.</small></p></div>"
                "<div class='card'><h2>Безопасный вариант</h2>"
                "<form method='post' action='/upload_safe' enctype='multipart/form-data'>"
                "<p><input type='file' name='file'></p>"
                "<p><button type='submit'>Загрузить (safe)</button></p></form>"
                "<p><small>Whitelist: <code>" + ", ".join(sorted(WHITELIST_EXT)) +
                "</code>, проверка magic bytes, имя = UUID, отдача как attachment."
                "</small></p></div>")
        elif route == "/files":
            conn = connect()
            try:
                rows = [dict(r) for r in conn.execute(
                    "SELECT id, original_name, stored_name, content_type, size, endpoint,"
                    " created_at FROM files ORDER BY id DESC LIMIT 100")]
            finally:
                conn.close()
            self._send(json.dumps(rows, ensure_ascii=False, indent=2),
                       200, "application/json; charset=utf-8")
        elif route == "/profile":
            conn = connect()
            try:
                rows = conn.execute(
                    "SELECT original_name, stored_name FROM files ORDER BY id DESC LIMIT 10"
                ).fetchall()
            finally:
                conn.close()
            items = "".join(
                # УЯЗВИМО: имя файла выводится без экранирования (stored XSS)
                f"<li>Аватар: {row['original_name']} "
                f"(сохранён как <code>{html.escape(row['stored_name'])}</code>)</li>"
                for row in rows)
            self._page("<div class='card'><h2>Профиль</h2><ul>" + (items or "<li>пусто</li>") +
                       "</ul><p><small>Имена файлов выводятся без экранирования — "
                       "это stored XSS (см. задание 5).</small></p></div>")
        elif route.startswith("/uploads/"):
            name = route[len("/uploads/"):]
            target = os.path.join(UPLOAD_DIR, name)
            # НАМЕРЕННО: путь не нормализуется — traversal внутри каталога данных
            if not os.path.isfile(target):
                self._page(f"<div class='card'><div class='error'>404: "
                           f"{html.escape(name)}</div></div>", HTTPStatus.NOT_FOUND)
                return
            with open(target, "rb") as fh:
                data = fh.read(MAX_SIZE)
            self.send_response(HTTPStatus.OK)
            # тип по расширению (а не по содержимому) — часть учебной проблемы
            ctype = "text/plain; charset=utf-8"
            if name.lower().endswith((".html", ".htm", ".svg")):
                ctype = "text/html; charset=utf-8"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
        else:
            self._page(f"<div class='card'><h2>404</h2>"
                       f"<p>Путь <code>{html.escape(route)}</code> не найден.</p>"
                       "<p><a href='/'>На главную</a></p></div>", HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        route = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
        if route not in {"/upload", "/upload_safe"}:
            self._page("<div class='card'>405</div>", HTTPStatus.METHOD_NOT_ALLOWED)
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_SIZE:
            self._page("<div class='card'><div class='error'>Пустой или слишком "
                       f"большой запрос (лимит {MAX_SIZE} байт)</div></div>",
                       HTTPStatus.BAD_REQUEST)
            return
        body = self.rfile.read(length)
        content_type_header = self.headers.get("Content-Type", "")
        boundary_match = re.search(r"boundary=([^;]+)", content_type_header)
        if not boundary_match:
            self._page("<div class='card'><div class='error'>Ожидается "
                       "multipart/form-data</div></div>", HTTPStatus.BAD_REQUEST)
            return
        filename, data, client_type = parse_multipart(body, boundary_match.group(1).strip('"'))
        if not filename:
            self._page("<div class='card'><div class='error'>Файл не найден в "
                       "запросе</div></div>", HTTPStatus.BAD_REQUEST)
            return

        if route == "/upload_safe":
            self.handle_safe(filename, data, client_type)
        else:
            self.handle_vulnerable(filename, data, client_type)

    # ── обработчики ───────────────────────────────────────────────────
    def handle_vulnerable(self, filename: str, data: bytes, client_type: str) -> None:
        ext = os.path.splitext(filename)[1].lower()
        # УЯЗВИМО 1: blacklist расширений (обходится альтернативными расширениями)
        if ext in BLACKLIST_EXT:
            self._page(f"<div class='card'><div class='error'>Расширение "
                       f"{html.escape(ext)} запрещено</div>"
                       "<p><a href='/upload'>Попробовать снова</a></p></div>",
                       HTTPStatus.FORBIDDEN)
            return
        # УЯЗВИМО 2: доверяем Content-Type от клиента
        # УЯЗВИМО 3: сохраняем под оригинальным именем. Разделители пути заменяются
        # (traversal наружу не проходит), но имя сохраняется дословно -> stored XSS
        # в /profile, обфускация blacklist'ов и неконтролируемые имена файлов.
        stored_name = filename.replace("/", "_").replace("\\", "_")
        target = self._save(data, stored_name)
        self._record(filename, stored_name, client_type, len(data), "/upload")
        url = "/uploads/" + urllib.parse.quote(stored_name)
        self._page(
            "<div class='card'><h2>Файл принят</h2>"
            f"<div class='ok'>Сохранён как <code>{html.escape(stored_name)}</code> "
            f"({len(data)} байт)</div>"
            f"<p>Ссылка: <a href='{url}'>{html.escape(url)}</a></p>"
            f"<p>Content-Type из запроса клиента: <code>{html.escape(client_type)}</code></p>"
            f"<p>Путь на диске: <code>{html.escape(os.path.relpath(target, '/'))}</code></p>"
            "<p><small>Заметьте: имя сохранено как прислано, тип не проверен по "
            "содержимому, blacklist можно обойти другим расширением.</small></p></div>")

    def handle_safe(self, filename: str, data: bytes, client_type: str) -> None:
        ext = os.path.splitext(filename)[1].lower()
        if ext not in WHITELIST_EXT:
            self._page(f"<div class='card'><div class='error'>Разрешены только: "
                       f"{html.escape(', '.join(sorted(WHITELIST_EXT)))}</div></div>",
                       HTTPStatus.BAD_REQUEST)
            return
        kind = magic_kind(data)
        expected = {".png": "png", ".jpg": "jpg", ".jpeg": "jpg", ".gif": "gif",
                    ".pdf": "pdf"}.get(ext)
        if expected and kind != expected:
            self._page("<div class='card'><div class='error'>Содержимое не "
                       "соответствует расширению (проверка magic bytes)</div></div>",
                       HTTPStatus.BAD_REQUEST)
            return
        if ext == ".txt":
            # для текста проверяем отсутствие исполняемых конструкций
            if re.search(rb"<\?php|<%|<script", data, re.IGNORECASE):
                self._page("<div class='card'><div class='error'>В текстовом файле "
                           "обнаружены исполняемые конструкции</div></div>",
                           HTTPStatus.BAD_REQUEST)
                return
        stored_name = f"{uuid.uuid4().hex}{ext}"
        self._save(data, stored_name)
        # оригинальное имя сохраняем экранированным и не выводим сырым
        self._record(html.escape(filename)[:300], stored_name, client_type,
                     len(data), "/upload_safe")
        url = "/uploads/" + stored_name
        self._page(
            "<div class='card'><h2>Файл принят (safe)</h2>"
            f"<div class='ok'>Сохранён под сгенерированным именем "
            f"<code>{html.escape(stored_name)}</code></div>"
            f"<p><a href='{url}' download>Скачать</a> "
            "(отдаётся с <code>Content-Disposition: attachment</code>)</p>"
            "<p><small>Проверены: whitelist расширений, magic bytes, отсутствие "
            "исполняемых конструкций; оригинальное имя не используется в пути "
            "и не выводится без экранирования.</small></p></div>")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()


def main() -> int:
    init()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[lab] upload-lab слушает 0.0.0.0:{PORT}, uploads={UPLOAD_DIR}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
