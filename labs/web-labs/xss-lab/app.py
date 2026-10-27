#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Уязвимое приложение для лаборатории XSS.

Только стандартная библиотека Python. Уязвимости НАМЕРЕННЫЕ — приложение живёт
внутри изолированного контейнера лабораторий hackbook.

Эндпоинты:
    GET  /                — задания и список контекстов
    GET  /reflect?q=      — УЯЗВИМО: вывод в теле HTML без экранирования
    GET  /attribute?v=    — УЯЗВИМО: вывод внутри атрибута value
    GET  /js?name=        — УЯЗВИМО: вывод внутри JS-строки
    GET  /filtered?q=     — blacklist-фильтр «наивный WAF» (обходится)
    GET  /safe?q=         — экранирование + CSP (контрольная точка)
    GET|POST /guestbook   — УЯЗВИМО: stored XSS (сообщения в SQLite)
    GET  /csp             — страница со строгой CSP и тем же выводом
    GET  /health          — для docker healthcheck

Окружение:
    DB_PATH   путь к SQLite (по умолчанию /data/app.db)
    PORT      порт (по умолчанию 8080)
"""

from __future__ import annotations

import html
import json
import os
import re
import sqlite3
import sys
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")
PORT = int(os.environ.get("PORT", "8080"))

PAGE_CSS = """
body{font:16px/1.6 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;margin:0;
     background:#f6f7f9;color:#1c1e21}
header{background:#5f3dc4;color:#fff;padding:.8rem 1.4rem}
main{max-width:56rem;margin:1.4rem auto;padding:0 1rem}
.card{background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:1rem 1.2rem;margin:.9rem 0}
code{background:#f1f3f5;border-radius:4px;padding:.1rem .3rem;
     font-family:ui-monospace,Consolas,monospace;font-size:.9em}
pre{background:#f1f3f5;border-left:3px solid #5f3dc4;border-radius:6px;padding:.7rem;
    overflow-x:auto;font-family:ui-monospace,Consolas,monospace;font-size:.85rem}
.warn{background:#fff9db;border-left:4px solid #f59f00;padding:.7rem 1rem;border-radius:6px}
.error{background:#fff0f0;border-left:4px solid #e03131;padding:.7rem 1rem;border-radius:6px}
.ok{background:#e6fcf5;border-left:4px solid #12b886;padding:.7rem 1rem;border-radius:6px}
input[type=text],textarea{padding:.4rem .6rem;border:1px solid #ced4da;border-radius:5px;
       width:24rem;font-size:1rem;font-family:inherit}
button{background:#5f3dc4;color:#fff;border:0;border-radius:5px;padding:.45rem .9rem;
       cursor:pointer;font-size:1rem}
a{color:#5f3dc4} small{color:#5b6472} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #dfe3e8;padding:.4rem .6rem;text-align:left} th{background:#f1f3f5}
"""

# Наивный blacklist — специально слабый, чтобы показать, почему blacklist не работает.
NAIVE_FILTER = re.compile(r"<\s*script", re.IGNORECASE)


def page(inner: str, csp: str | None = None) -> str:
    meta = ""
    if csp:
        meta = f"<meta http-equiv='Content-Security-Policy' content=\"{html.escape(csp, quote=True)}\">"
    return ("<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>"
            f"<title>hackbook · XSS Lab</title>{meta}"
            f"<style>{PAGE_CSS}</style></head><body>"
            "<header><b>hackbook / XSS Lab</b> &nbsp;·&nbsp; намеренно уязвимое "
            "приложение для локальных лабораторий</header>"
            f"<main>{inner}</main></body></html>")


INDEX_BODY = """
<div class="warn"><b>Внимание.</b> Приложение намеренно отражает и сохраняет
пользовательский ввод без экранирования. Поднимайте его только в изолированной
сети Docker и не заходите в него с рабочей сессией браузера.</div>

<div class="card"><h2>Контексты вывода</h2>
<table><thead><tr><th>URL</th><th>Контекст</th><th>Что пробовать</th></tr></thead><tbody>
<tr><td><a href="/reflect?q=test">/reflect?q=</a></td><td>тело HTML</td>
    <td><code>&lt;svg onload=alert(document.domain)&gt;</code></td></tr>
<tr><td><a href="/attribute?v=test">/attribute?v=</a></td><td>атрибут value</td>
    <td><code>" autofocus onfocus=alert(document.domain) x="</code></td></tr>
<tr><td><a href="/js?name=test">/js?name=</a></td><td>JS-строка</td>
    <td><code>';alert(document.domain);//</code></td></tr>
<tr><td><a href="/filtered?q=&lt;script&gt;">/filtered?q=</a></td><td>тело HTML + blacklist</td>
    <td><code>&lt;img src=x onerror=alert(document.domain)&gt;</code></td></tr>
<tr><td><a href="/guestbook">/guestbook</a></td><td>stored (SQLite)</td>
    <td><code>&lt;details open ontoggle=alert(document.domain)&gt;</code></td></tr>
<tr><td><a href="/safe?q=test">/safe?q=</a></td><td>экранирование</td>
    <td>контрольная точка — ничего не должно сработать</td></tr>
<tr><td><a href="/csp?q=test">/csp?q=</a></td><td>CSP + экранирование</td>
    <td>проверьте, какие векторы CSP всё же не блокирует</td></tr>
</tbody></table></div>

<div class="card"><h2>Задания</h2><ol>
<li>Для каждого из трёх контекстов (тело, атрибут, JS) подберите рабочий вектор
и объясните, почему экранирование «для HTML» не спасает в остальных.</li>
<li>Обойдите blacklist в <code>/filtered</code> тремя разными способами
(тег без <code>script</code>, изменение регистра, HTML-сущности).</li>
<li>Разместите stored-payload в гостевой книге и найдите все места, где он
исполняется (включая страницу «сырого» JSON-экспорта).</li>
<li>Включите CSP <code>default-src 'self'</code> на странице <code>/csp</code>
и определите, какие векторы остались рабочими. Объясните результат.</li>
<li>Почините <code>/reflect</code>, <code>/attribute</code> и <code>/js</code>:
примените контекстно-зависимое экранирование и убедитесь, что тесты
<code>tools/payload-tester.sh --lab xss-lab</code> больше не проходят.</li>
</ol>
<p><small>Карточки payload'ов: <code>payloads/web/xss/</code> ·
Разбор: глава 1 книги</small></p></div>
"""


def connect() -> sqlite3.Connection:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    if conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"] == 0:
        conn.executemany(
            "INSERT INTO messages (author, body) VALUES (?,?)",
            [
                ("instructor", "Добро пожаловать в лабораторию XSS. Сообщения "
                               "сохраняются без санитизации — это часть задания."),
                ("student", "Проверил /reflect — вектор с svg работает."),
            ],
        )
    conn.commit()
    conn.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "hackbook-xss-lab/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write("[lab] %s\n" % (fmt % args))
        sys.stdout.flush()

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

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        params = {k: v[0] for k, v in
                  urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}
        route = parsed.path.rstrip("/") or "/"

        if route == "/health":
            self._send("ok\n", 200, "text/plain; charset=utf-8")
        elif route == "/":
            self._send(page(INDEX_BODY))
        elif route == "/reflect":
            value = params.get("q", "")
            # УЯЗВИМО: сырое значение в теле HTML
            self._send(page("<div class='card'><h2>Reflected (HTML-тело)</h2>"
                            f"<p>Вы сказали: {value}</p>"
                            "<p><small>Значение выведено без экранирования.</small></p></div>"))
        elif route == "/attribute":
            value = params.get("v", "")
            # УЯЗВИМО: сырое значение внутри атрибута
            self._send(page("<div class='card'><h2>Reflected (атрибут)</h2>"
                            f"<p><input type='text' value=\"{value}\" size='40'></p>"
                            "<p><small>Кавычки не экранируются — breakout возможен.</small></p></div>"))
        elif route == "/js":
            value = params.get("name", "")
            # УЯЗВИМО: сырое значение внутри JS-строки
            self._send(page("<div class='card'><h2>Reflected (JavaScript)</h2>"
                            "<p id='out'></p><script>"
                            f"const name = '{value}';"
                            "document.getElementById('out').textContent = 'Привет, ' + name;"
                            "</script>"
                            "<p><small>HTML-экранирование здесь не помогает: нужен "
                            "JSON-контекст.</small></p></div>"))
        elif route == "/filtered":
            value = params.get("q", "")
            cleaned = NAIVE_FILTER.sub("&lt;script", value)
            # УЯЗВИМО: blacklist только на <script
            self._send(page("<div class='card'><h2>«Отфильтрованный» вывод</h2>"
                            f"<p>Вы сказали: {cleaned}</p>"
                            "<p><small>Фильтр вырезает только <code>&lt;script</code>. "
                            "Это иллюстрация, почему blacklist не работает.</small></p></div>"))
        elif route == "/safe":
            value = html.escape(params.get("q", ""), quote=True)
            self._send(page("<div class='card'><h2>Безопасный вывод</h2>"
                            f"<p>Вы сказали: {value}</p>"
                            "<div class='ok'>Значение экранировано: <code>&lt; &gt; "
                            "&quot; &#x27;</code> — векторы не исполняются.</div></div>"))
        elif route == "/csp":
            value = html.escape(params.get("q", ""), quote=True)
            self._send(page("<div class='card'><h2>CSP + экранирование</h2>"
                            f"<p>Вы сказали: {value}</p>"
                            "<div class='ok'>Политика <code>default-src 'self'</code> "
                            "блокирует inline-скрипты и обработчики событий.</div></div>"),
                       extra_headers={"Content-Security-Policy":
                                      "default-src 'self'; script-src 'self'; "
                                      "object-src 'none'; base-uri 'none'"})
        elif route == "/guestbook":
            self.guestbook()
        elif route == "/guestbook.json":
            conn = connect()
            try:
                rows = [dict(r) for r in conn.execute(
                    "SELECT id, author, body, created_at FROM messages ORDER BY id DESC LIMIT 50")]
            finally:
                conn.close()
            self._send(json.dumps(rows, ensure_ascii=False, indent=2),
                       200, "application/json; charset=utf-8")
        else:
            self._send(page("<div class='card'><h2>404</h2>"
                            f"<p>Путь <code>{html.escape(self.path)}</code> не найден.</p>"
                            "<p><a href='/'>На главную</a></p></div>"),
                       HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        route = parsed.path.rstrip("/") or "/"
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
        if route == "/guestbook":
            author = form.get("author", "anon")[:80]
            body = form.get("body", "")[:2000]
            conn = connect()
            try:
                conn.execute("INSERT INTO messages (author, body) VALUES (?,?)",
                             (author, body))
                conn.commit()
            finally:
                conn.close()
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/guestbook")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(page("<div class='card'>405</div>"), HTTPStatus.METHOD_NOT_ALLOWED)

    def guestbook(self) -> None:
        conn = connect()
        try:
            rows = conn.execute(
                "SELECT id, author, body, created_at FROM messages ORDER BY id DESC LIMIT 50"
            ).fetchall()
        finally:
            conn.close()
        items = []
        for row in rows:
            # УЯЗВИМО: stored XSS — и автор, и текст выводятся без санитизации
            items.append(
                "<tr>"
                f"<td>{row['id']}</td>"
                f"<td>{row['author']}</td>"
                f"<td>{row['body']}</td>"
                f"<td><small>{html.escape(str(row['created_at']))}</small></td>"
                "</tr>")
        table = "".join(items)
        self._send(page(
            "<div class='card'><h2>Гостевая книга (stored XSS)</h2>"
            "<form method='post' action='/guestbook'>"
            "<p><input type='text' name='author' placeholder='имя' value='student'></p>"
            "<p><textarea name='body' rows='3' placeholder='сообщение'></textarea></p>"
            "<p><button type='submit'>Отправить</button></p></form>"
            "<p><small>Сырой экспорт: <a href='/guestbook.json'>/guestbook.json</a>. "
            "Сообщения хранятся в SQLite и выводятся без санитизации.</small></p>"
            "<table><thead><tr><th>id</th><th>автор</th><th>сообщение</th>"
            f"<th>когда</th></tr></thead><tbody>{table}</tbody></table></div>"))


def main() -> int:
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[lab] xss-lab слушает 0.0.0.0:{PORT}, БД: {DB_PATH}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
