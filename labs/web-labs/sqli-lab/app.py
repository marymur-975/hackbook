#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Уязвимое приложение для лаборатории SQL Injection.

Стек — только стандартная библиотека Python (http.server + sqlite3), поэтому
образ собирается без сети и без pip. Все уязвимости НАМЕРЕННЫЕ: приложение
существует исключительно внутри изолированного контейнера лабораторий hackbook.

Эндпоинты:
    GET  /                 — каталог и задания
    GET  /item?id=         — УЯЗВИМО: конкатенация значения в SQL
    GET  /item_safe?id=    — тот же запрос, но с prepared statements
    GET  /search?q=        — УЯЗВИМО: LIKE без экранирования метасимволов
    GET  /search_safe?q=   — безопасный поиск
    GET|POST /login        — УЯЗВИМО: тавтология в форме входа
    GET|POST /login_safe   — безопасный вход
    GET  /admin            — только для аутентифицированных
    GET  /health           — для docker healthcheck
    GET  /robots.txt       — приманка для enumeration

Окружение:
    DB_PATH         путь к SQLite (по умолчанию /data/app.db)
    SHOW_DB_ERRORS  1 — отдавать текст ошибок СУБД клиенту (по умолчанию 1:
                    это отдельная учебная находка «раскрытие internals»)
    PORT            порт (по умолчанию 8080)
"""

from __future__ import annotations

import hashlib
import html
import os
import secrets
import sqlite3
import sys
import urllib.parse
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")
SHOW_DB_ERRORS = os.environ.get("SHOW_DB_ERRORS", "1") == "1"
PORT = int(os.environ.get("PORT", "8080"))

PAGE_CSS = """
body{font:16px/1.6 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;margin:0;
     background:#f6f7f9;color:#1c1e21}
header{background:#0b7285;color:#fff;padding:.8rem 1.4rem}
main{max-width:56rem;margin:1.4rem auto;padding:0 1rem}
.card{background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:1rem 1.2rem;margin:.9rem 0}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #dfe3e8;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#f1f3f5}
code{background:#f1f3f5;border-radius:4px;padding:.1rem .3rem;
     font-family:ui-monospace,Consolas,monospace;font-size:.9em}
pre{background:#f1f3f5;border-left:3px solid #0b7285;border-radius:6px;padding:.7rem;
    overflow-x:auto;font-family:ui-monospace,Consolas,monospace;font-size:.85rem}
.error{background:#fff0f0;border-left:4px solid #e03131;padding:.7rem 1rem;border-radius:6px;
       font-family:ui-monospace,Consolas,monospace;font-size:.85rem;white-space:pre-wrap}
.ok{background:#e6fcf5;border-left:4px solid #12b886;padding:.7rem 1rem;border-radius:6px}
.warn{background:#fff9db;border-left:4px solid #f59f00;padding:.7rem 1rem;border-radius:6px}
input[type=text],input[type=password]{padding:.4rem .6rem;border:1px solid #ced4da;
       border-radius:5px;width:16rem;font-size:1rem}
button{background:#0b7285;color:#fff;border:0;border-radius:5px;padding:.45rem .9rem;
       cursor:pointer;font-size:1rem}
a{color:#0b7285} small{color:#5b6472}
"""


def page(inner: str) -> str:
    return ("<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>"
            "<title>hackbook · SQLi Lab</title>"
            f"<style>{PAGE_CSS}</style></head><body>"
            "<header><b>hackbook / SQLi Lab</b> &nbsp;·&nbsp; намеренно уязвимое "
            "приложение для локальных лабораторий</header>"
            f"<main>{inner}</main></body></html>")


INDEX_BODY = """
<div class="warn"><b>Внимание.</b> Приложение содержит намеренные уязвимости:
SQL injection, раскрытие текста ошибок СУБД, хранение паролей в MD5 без соли,
отсутствие rate limiting. Поднимайте его только в изолированной сети Docker.</div>

<div class="card"><h2>Точки входа</h2>
<ul>
<li><a href="/item?id=1">/item?id=1</a> — уязвимый запрос (конкатенация)</li>
<li><a href="/item_safe?id=1">/item_safe?id=1</a> — безопасный (параметры)</li>
<li><a href="/search?q=laptop">/search?q=laptop</a> — уязвимый LIKE</li>
<li><a href="/search_safe?q=laptop">/search_safe?q=laptop</a> — безопасный LIKE</li>
<li><a href="/login">/login</a> — уязвимая форма входа, <a href="/login_safe">/login_safe</a> — безопасная</li>
<li><a href="/admin">/admin</a> — цель обхода аутентификации</li>
</ul></div>

<div class="card"><h2>Задания</h2><ol>
<li>Подтвердите инъекцию в <code>/item?id=</code> тремя способами: синтаксическая
ошибка, логическое различие (<code>AND 1=1</code> против <code>AND 1=2</code>),
задержка во времени.</li>
<li>Определите число колонок (<code>ORDER BY n</code>) и выведите версию СУБД
через UNION.</li>
<li>Перечислите схему через <code>sqlite_master</code>.</li>
<li>Прочитайте таблицу <code>users</code> и объясните, почему MD5 без соли —
отдельная находка, даже если инъекцию починили.</li>
<li>Обойдите аутентификацию в <code>/login</code> тавтологией и зайдите в
<code>/admin</code>.</li>
<li>Проверьте wildcard-инъекцию: <code>/search?q=%</code> против
<code>/search?q=_</code>.</li>
<li>Повторите пункты 1–6 на <code>/item_safe</code> и объясните, почему они
не срабатывают.</li>
<li>Почините <code>/item</code> (переведите на параметры) и убедитесь, что
тесты <code>tools/payload-tester.sh --lab sqli-lab</code> больше не проходят.</li>
</ol>
<p><small>Карточки payload'ов: <code>payloads/web/sqli/</code> ·
Разбор: глава 1 книги · Тесты: <code>labs/web-labs/sqli-lab/tests.yaml</code></small></p>
</div>
"""


def connect() -> sqlite3.Connection:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def md5(value: str) -> str:
    # НАМЕРЕННО слабая схема хранения — часть учебного задания
    return hashlib.md5(value.encode()).hexdigest()


def init_db() -> None:
    conn = connect()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            stock INTEGER
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            login TEXT UNIQUE NOT NULL,
            password_md5 TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            ts TEXT DEFAULT CURRENT_TIMESTAMP,
            path TEXT,
            query TEXT,
            user_agent TEXT
        );
        """
    )
    if cur.execute("SELECT COUNT(*) AS c FROM items").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO items (name, description, price, stock) VALUES (?,?,?,?)",
            [
                ("Laptop ThinkPad T14", "Учебный товар лаборатории", 1290.0, 7),
                ("Switch 24p", "Коммутатор уровня доступа", 410.5, 3),
                ("YubiKey 5", "Аппаратный ключ второго фактора", 55.0, 15),
                ("Raspberry Pi 5", "Одноплатный компьютер для стендов", 88.0, 12),
                ("Web Application Security", "Книга к главе 1", 42.0, 9),
            ],
        )
    if cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO users (login, password_md5, role, email) VALUES (?,?,?,?)",
            [
                ("admin", md5("admin123"), "admin", "admin@lab.local"),
                ("manager", md5("Password1"), "manager", "manager@lab.local"),
                ("guest", md5("guest"), "user", "guest@lab.local"),
                ("svc_backup", md5("backup2026"), "service", "backup@lab.local"),
            ],
        )
    conn.commit()
    conn.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "hackbook-sqli-lab/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # компактный лог в stdout контейнера
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

    def _audit(self, query: str) -> None:
        try:
            conn = connect()
            conn.execute(
                "INSERT INTO audit_log (path, query, user_agent) VALUES (?,?,?)",
                (self.path[:500], query[:500], self.headers.get("User-Agent", "")[:200]),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error:
            pass

    def _sql_error(self, exc: Exception, query: str) -> str:
        if SHOW_DB_ERRORS:
            return ("<div class='error'><b>SQL error</b>\n"
                    f"{html.escape(str(exc))}\n\n"
                    f"<small>query: {html.escape(query)}</small></div>")
        return "<div class='error'>Внутренняя ошибка приложения</div>"

    def _session_user(self) -> sqlite3.Row | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("session")
        if not morsel:
            return None
        conn = connect()
        try:
            return conn.execute(
                "SELECT u.id, u.login, u.role FROM sessions s "
                "JOIN users u ON u.id = s.user_id WHERE s.token = ?",
                (morsel.value,),
            ).fetchone()
        finally:
            conn.close()

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

    def _items_table(self, rows) -> str:
        body = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(row[key]))}</td>"
                             for key in row.keys()) + "</tr>"
            for row in rows)
        head = "".join(f"<th>{html.escape(k)}</th>" for k in rows[0].keys()) if rows else ""
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    # ── маршруты ──────────────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        params = {k: v[0] for k, v in
                  urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}
        self._audit(parsed.query)
        route = parsed.path.rstrip("/") or "/"

        if route == "/health":
            self._send("ok\n", 200, "text/plain; charset=utf-8")
        elif route == "/robots.txt":
            self._send("User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n",
                       200, "text/plain; charset=utf-8")
        elif route == "/":
            self._send(page(INDEX_BODY))
        elif route == "/item":
            self.item(params.get("id", "1"), safe=False)
        elif route == "/item_safe":
            self.item(params.get("id", "1"), safe=True)
        elif route == "/search":
            self.search(params.get("q", ""), safe=False)
        elif route == "/search_safe":
            self.search(params.get("q", ""), safe=True)
        elif route == "/login":
            self.login_form(safe=False)
        elif route == "/login_safe":
            self.login_form(safe=True)
        elif route == "/admin":
            self.admin()
        else:
            self._send(page("<div class='card'><h2>404</h2>"
                            f"<p>Путь <code>{html.escape(self.path)}</code> не найден.</p>"
                            "<p><a href='/'>На главную</a></p></div>"),
                       HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        route = parsed.path.rstrip("/") or "/"
        form = self._read_body()
        self._audit(urllib.parse.urlencode(form))
        if route in {"/login", "/login_safe"}:
            self.login_submit(form.get("login", ""), form.get("password", ""),
                              safe=route == "/login_safe")
        else:
            self._send(page("<div class='card'>405</div>"), HTTPStatus.METHOD_NOT_ALLOWED)

    # ── обработчики ───────────────────────────────────────────────────
    def item(self, item_id: str, *, safe: bool) -> None:
        conn = connect()
        try:
            if safe:
                query = "SELECT * FROM items WHERE id = ?"
                rows = conn.execute(query, (item_id,)).fetchall()
            else:
                # УЯЗВИМО: значение пользователя склеивается с текстом запроса
                query = f"SELECT * FROM items WHERE id = {item_id}"
                rows = conn.execute(query).fetchall()
        except sqlite3.Error as exc:
            self._send(page(f"<div class='card'><h2>/item{'_safe' if safe else ''}</h2>"
                            f"<pre>{html.escape(query)}</pre>"
                            f"{self._sql_error(exc, query)}</div>"),
                       HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        finally:
            conn.close()

        if rows:
            inner = ("<div class='card'><h2>Результат</h2>"
                     f"<pre>{html.escape(query)}</pre>{self._items_table(rows)}</div>")
        else:
            inner = ("<div class='card'><h2>Ничего не найдено</h2>"
                     f"<pre>{html.escape(query)}</pre>"
                     "<p>Запрос не вернул строк.</p></div>")
        self._send(page(inner))

    def search(self, term: str, *, safe: bool) -> None:
        conn = connect()
        try:
            if safe:
                query = ("SELECT * FROM items WHERE name LIKE ? ESCAPE '\\' "
                         "OR description LIKE ? ESCAPE '\\'")
                escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                rows = conn.execute(query, (f"%{escaped}%", f"%{escaped}%")).fetchall()
            else:
                # УЯЗВИМО: метасимволы LIKE не экранируются + конкатенация
                query = (f"SELECT * FROM items WHERE name LIKE '%{term}%' "
                         f"OR description LIKE '%{term}%'")
                rows = conn.execute(query).fetchall()
        except sqlite3.Error as exc:
            self._send(page(f"<div class='card'><h2>/search</h2>"
                            f"{self._sql_error(exc, query)}</div>"),
                       HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        finally:
            conn.close()
        table = self._items_table(rows) if rows else "<p>Ничего не найдено.</p>"
        self._send(page(f"<div class='card'><h2>Поиск: {html.escape(term)}</h2>"
                        f"<pre>{html.escape(query)}</pre>{table}</div>"))

    def login_form(self, *, safe: bool) -> None:
        action = "/login_safe" if safe else "/login"
        self._send(page(
            "<div class='card'><h2>Вход</h2>"
            f"<p><small>Форма: <code>{action}</code>"
            f"{' (безопасная)' if safe else ' (уязвимая)'}</small></p>"
            f"<form method='post' action='{action}'>"
            "<p><input type='text' name='login' placeholder='логин' value='guest'></p>"
            "<p><input type='password' name='password' placeholder='пароль'></p>"
            "<p><button type='submit'>Войти</button></p></form>"
            "<p><small>Учётки для стенда: admin / manager / guest / svc_backup. "
            "Пароль guest — <code>guest</code>.</small></p></div>"))

    def login_submit(self, login: str, password: str, *, safe: bool) -> None:
        conn = connect()
        try:
            if safe:
                query = ("SELECT * FROM users WHERE login = ? AND password_md5 = ?")
                args = (login, md5(password))
                row = conn.execute(query, args).fetchone()
            else:
                # УЯЗВИМО: логин и пароль конкатенируются в условие WHERE
                query = ("SELECT * FROM users WHERE login = '" + login +
                         "' AND password_md5 = '" + md5(password) + "'")
                try:
                    row = conn.execute(query).fetchone()
                except sqlite3.Error as exc:
                    self._send(page(f"<div class='card'><h2>Вход</h2>"
                                    f"{self._sql_error(exc, query)}</div>"),
                               HTTPStatus.INTERNAL_SERVER_ERROR)
                    return
            if not row:
                self._send(page("<div class='card'><h2>Вход</h2>"
                                "<div class='error'>Неверный логин или пароль</div>"
                                "<p><a href='/login'>Попробовать снова</a></p></div>"),
                           HTTPStatus.UNAUTHORIZED)
                return
            token = secrets.token_hex(16)
            conn.execute("INSERT INTO sessions (token, user_id) VALUES (?,?)",
                         (token, row["id"]))
            conn.commit()
        finally:
            conn.close()
        self._send(page("<div class='card'><h2>Вход выполнен</h2>"
                        f"<div class='ok'>Добро пожаловать, {html.escape(row['login'])} "
                        f"(роль: {html.escape(row['role'])})</div>"
                        "<p><a href='/admin'>Перейти в админ-панель</a></p></div>"),
                   extra_headers={"Set-Cookie": f"session={token}; Path=/; HttpOnly; SameSite=Lax"})

    def admin(self) -> None:
        user = self._session_user()
        if not user:
            self._send(page("<div class='card'><h2>Админ-панель</h2>"
                            "<div class='error'>Требуется аутентификация</div>"
                            "<p><a href='/login'>Войти</a></p></div>"),
                       HTTPStatus.FORBIDDEN)
            return
        conn = connect()
        try:
            users = conn.execute("SELECT id, login, password_md5, role, email "
                                 "FROM users ORDER BY id").fetchall()
            logs = conn.execute("SELECT id, ts, path, query FROM audit_log "
                                "ORDER BY id DESC LIMIT 20").fetchall()
        finally:
            conn.close()
        rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(u[k]))}</td>"
                                        for k in u.keys()) + "</tr>" for u in users)
        log_rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(l[k]))}</td>"
                                           for k in l.keys()) + "</tr>" for l in logs)
        self._send(page(
            "<div class='card'><h2>Админ-панель</h2>"
            f"<div class='ok'>Вошли как {html.escape(user['login'])} "
            f"({html.escape(user['role'])})</div>"
            "<p><small>Обратите внимание: панель показывает MD5-хеши паролей — "
            "это вторая находка после самой инъекции.</small></p>"
            "<h3>Пользователи</h3><table><thead><tr><th>id</th><th>login</th>"
            "<th>password_md5</th><th>role</th><th>email</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>"
            "<div class='card'><h3>Последние запросы (audit_log)</h3>"
            "<table><thead><tr><th>id</th><th>ts</th><th>path</th><th>query</th>"
            f"</tr></thead><tbody>{log_rows}</tbody></table></div>"))


def main() -> int:
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[lab] sqli-lab слушает 0.0.0.0:{PORT}, БД: {DB_PATH}, "
          f"ошибки СУБД клиенту: {SHOW_DB_ERRORS}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
