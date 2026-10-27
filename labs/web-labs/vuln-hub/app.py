#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vuln-hub — лаборатория «всё в одном» для карточек hackbook.

Одно приложение на стандартной библиотеке Python с намеренно уязвимыми
эндпоинтами по разным классам + безопасные аналоги каждого (контрольные точки).

    Класс            Уязвимый эндпоинт          Безопасный аналог
    ---------------- -------------------------- --------------------
    SQLi             GET /items?id=             GET /items_safe?id=
    IDOR             GET /notes?id=             GET /notes_safe?id=
    XSS              GET /echo?q=               GET /echo_safe?q=
    SSRF             GET /fetch?url=            GET /fetch_safe?url=
    XXE              POST /lookup               POST /lookup_safe
    Command inject.  GET /ping?host=            GET /ping_safe?host=
    LFI / traversal  GET /read?file=            GET /read_safe?file=
    Auth (JWT)       POST /login, /me, /admin   POST /login_safe, /me_safe
    2FA bypass       POST /verify               POST /verify_safe

Все уязвимые места помечены `# УЯЗВИМО:`. Приложение работает только внутри
изолированного контейнера лабораторий hackbook.

Окружение:
    DB_PATH     SQLite (по умолчанию /data/app.db)
    DOCS_DIR    каталог «документов» для /read (по умолчанию /app/docs)
    JWT_SECRET  секрет подписи (по умолчанию "secret" — намеренно слабый)
    ALLOWED_SSRF_HOSTS  разрешённые хосты для /fetch_safe (CSV)
    PORT        порт (по умолчанию 8080)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.parsers.expat
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")
DOCS_DIR = os.environ.get("DOCS_DIR", "/app/docs")
JWT_SECRET = os.environ.get("JWT_SECRET", "secret")     # намеренно слабый
ALLOWED_SSRF_HOSTS = {h.strip() for h in
                      os.environ.get("ALLOWED_SSRF_HOSTS", "example.com").split(",") if h.strip()}
PORT = int(os.environ.get("PORT", "8080"))
PUBLIC_KEY_PEM = os.environ.get("PUBLIC_KEY_PEM", "-----BEGIN PUBLIC KEY-----\nHB-LAB\n-----END PUBLIC KEY-----")

PAGE_CSS = """
body{font:16px/1.6 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;margin:0;
     background:#f6f7f9;color:#1c1e21}
header{background:#1864ab;color:#fff;padding:.8rem 1.4rem}
main{max-width:60rem;margin:1.4rem auto;padding:0 1rem}
.card{background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:1rem 1.2rem;margin:.9rem 0}
code{background:#f1f3f5;border-radius:4px;padding:.1rem .3rem;
     font-family:ui-monospace,Consolas,monospace;font-size:.9em}
pre{background:#f1f3f5;border-left:3px solid #1864ab;border-radius:6px;padding:.7rem;
    overflow-x:auto;font-family:ui-monospace,Consolas,monospace;font-size:.85rem;white-space:pre-wrap}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #dfe3e8;padding:.4rem .6rem;text-align:left}
th{background:#f1f3f5}
.warn{background:#fff9db;border-left:4px solid #f59f00;padding:.7rem 1rem;border-radius:6px}
.error{background:#fff0f0;border-left:4px solid #e03131;padding:.7rem 1rem;border-radius:6px}
.ok{background:#e6fcf5;border-left:4px solid #12b886;padding:.7rem 1rem;border-radius:6px}
input[type=text],input[type=password]{padding:.4rem .6rem;border:1px solid #ced4da;
       border-radius:5px;width:22rem;font-size:1rem}
button{background:#1864ab;color:#fff;border:0;border-radius:5px;padding:.45rem .9rem;cursor:pointer}
a{color:#1864ab}small{color:#5b6472}
"""

INDEX_ROWS = [
    ("SQLi", "/items?id=1", "/items_safe?id=1", "конкатенация в WHERE"),
    ("IDOR", "/notes?id=2", "/notes_safe?id=2", "нет проверки владельца"),
    ("XSS", "/echo?q=test", "/echo_safe?q=test", "вывод без экранирования"),
    ("SSRF", "/fetch?url=http://127.0.0.1:9/", "/fetch_safe?url=https://example.com", "нет whitelist"),
    ("XXE", "POST /lookup (XML)", "POST /lookup_safe (XML)", "внешние сущности разрешены"),
    ("CMDi", "/ping?host=127.0.0.1", "/ping_safe?host=127.0.0.1", "shell=True с вводом пользователя"),
    ("LFI", "/read?file=readme.txt", "/read_safe?file=readme.txt", "путь из параметра без нормализации"),
    ("JWT", "POST /login, затем /me и /admin", "POST /login_safe, /me_safe", "alg из токена, слабый секрет"),
    ("2FA", "POST /verify", "POST /verify_safe", "флаг прохождения на клиенте"),
]


def index_body() -> str:
    rows = "".join(
        f"<tr><td>{kind}</td><td><a href='{html.escape(vuln, quote=True)}'><code>{html.escape(vuln)}</code></a></td>"
        f"<td><code>{html.escape(safe)}</code></td><td>{html.escape(why)}</td></tr>"
        for kind, vuln, safe, why in INDEX_ROWS)
    return f"""
<div class="warn"><b>Внимание.</b> Приложение намеренно уязвимо по девяти классам.
Только изолированная лаборатория hackbook; наружу не публиковать.</div>
<div class="card"><h2>Эндпоинты</h2>
<table><thead><tr><th>Класс</th><th>Уязвимый</th><th>Безопасный</th><th>Причина</th></tr></thead>
<tbody>{rows}</tbody></table>
<p><small>JWT-секрет лаборатории: <code>secret</code> (в <code>wordlists/passwords/jwt-secrets.txt</code>).
Публичный «RSA-ключ» для задания на algorithm confusion: <code>/jwks</code>.</small></p></div>
<div class="card"><h2>Задания</h2><ol>
<li>Подтвердите SQLi в <code>/items?id=</code> и извлеките схему через UNION;
сравните с <code>/items_safe</code>.</li>
<li>Прочитайте чужую заметку через <code>/notes?id=</code> (IDOR) и объясните,
почему <code>/notes_safe</code> возвращает 404 тем же ответом, что и для несуществующей.</li>
<li>Отразите вектор XSS в <code>/echo?q=</code>; проверьте, что <code>/echo_safe</code>
экранирует, и включите CSP на отдельной странице.</li>
<li>Через <code>/fetch?url=</code> обратитесь к внутреннему сервису
(<code>http://127.0.0.1:8080/health</code>) и к <code>file:///etc/hostname</code>;
затем покажите, как whitelist в <code>/fetch_safe</code> это закрывает.</li>
<li>Отправьте в <code>/lookup</code> XML с внешней сущностью и получите содержимое
<code>/etc/hostname</code>; сравните с <code>/lookup_safe</code> (DTD запрещён).</li>
<li>Выполните <code>/ping?host=127.0.0.1; id</code> и подтвердите вывод команды;
объясните, почему <code>/ping_safe</code> (массив аргументов + whitelist) не уязвим.</li>
<li>Прочитайте <code>/read?file=../../etc/passwd</code>; затем покажите, как
<code>realpath</code> + проверка префикса в <code>/read_safe</code> закрывает traversal.</li>
<li>Получите JWT в <code>/login</code>, измените <code>role</code> на <code>admin</code>
и переподпишите ключом <code>secret</code>; проверьте <code>/admin</code>.
Затем попробуйте <code>alg=none</code>. Объясните, что именно чинит <code>/login_safe</code>.</li>
<li>Обойдите 2FA в <code>/verify</code> (флаг на клиенте) и покажите серверную
проверку в <code>/verify_safe</code>.</li>
<li>Для каждого пункта сформулируйте правило детектирования по логам лаборатории
(<code>/logs</code>) — см. главу 7 книги.</li>
</ol></div>
"""


def connect() -> sqlite3.Connection:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def md5(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def init() -> None:
    os.makedirs(DOCS_DIR, exist_ok=True)
    readme = os.path.join(DOCS_DIR, "readme.txt")
    if not os.path.exists(readme):
        with open(readme, "w", encoding="utf-8") as fh:
            fh.write("HB-DOC: учебный документ лаборатории vuln-hub.\n")
    conn = connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY, name TEXT, price REAL, secret_note TEXT);
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, login TEXT UNIQUE, password_sha256 TEXT,
            role TEXT, totp_secret TEXT);
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id INTEGER, mfa_passed INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY, ts TEXT DEFAULT CURRENT_TIMESTAMP,
            method TEXT, path TEXT, query TEXT, status INTEGER, user_agent TEXT);
        """
    )
    cur = conn.cursor()
    if cur.execute("SELECT COUNT(*) c FROM items").fetchone()["c"] == 0:
        cur.executemany("INSERT INTO items (name, price, secret_note) VALUES (?,?,?)",
                        [("YubiKey 5", 55.0, "HB-ITEM-1"),
                         ("Raspberry Pi 5", 88.0, "HB-ITEM-2"),
                         ("Книга по AppSec", 42.0, "HB-ITEM-3")])
    if cur.execute("SELECT COUNT(*) c FROM notes").fetchone()["c"] == 0:
        cur.executemany("INSERT INTO notes (owner, body) VALUES (?,?)",
                        [("alice", "HB-NOTE-ALICE: приватная заметка Alice"),
                         ("bob", "HB-NOTE-BOB: приватная заметка Bob"),
                         ("guest", "HB-NOTE-GUEST: публичная заметка")])
    if cur.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        cur.executemany("INSERT INTO users (login, password_sha256, role, totp_secret) VALUES (?,?,?,?)",
                        [("admin", sha256("admin123"), "admin", "JBSWY3DPEHPK3PXP"),
                         ("guest", sha256("guest"), "user", "JBSWY3DPEHPK3PXP")])
    conn.commit()
    conn.close()


# ── JWT (учебная реализация HS256) ────────────────────────────────────
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def jwt_encode(claims: dict, secret: str, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    if alg == "none":
        return signing_input + "."
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(signature)}"


def jwt_decode(token: str, secret: str, *, strict_alg: bool = False) -> dict:
    """Учебный декодер.

    strict_alg=False — НАМЕРЕННО уязвимое поведение: алгоритм берётся из
    заголовка токена, `none` принимается, а при `alg=HS256` секретом может
    выступать «публичный ключ» (algorithm confusion).
    strict_alg=True — allowlist алгоритмов, обязательная подпись.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header = json.loads(b64url_decode(parts[0]) or b"{}")
    claims = json.loads(b64url_decode(parts[1]) or b"{}")
    alg = header.get("alg", "HS256")

    if strict_alg:
        if alg != "HS256":
            raise ValueError(f"algorithm not allowed: {alg}")
        expected = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(),
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64url_decode(parts[2]) or b""):
            raise ValueError("bad signature")
    else:
        # УЯЗВИМО: доверяем alg из заголовка
        if alg == "none":
            return claims
        key = secret
        if alg == "HS256" and secret.startswith("-----BEGIN"):
            key = secret  # algorithm confusion: «публичный ключ» как HMAC-секрет
        expected = hmac.new(key.encode(), f"{parts[0]}.{parts[1]}".encode(),
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64url_decode(parts[2]) or b""):
            raise ValueError("bad signature")

    if "exp" in claims and claims["exp"] < time.time():
        raise ValueError("token expired")
    return claims


# ── XXE: парсер на expat с разрешёнными внешними сущностями ───────────
def parse_xml_unsafe(data: str, *, allow_dtd: bool = True) -> dict:
    """Учебный XML-парсер.

    allow_dtd=True (УЯЗВИМО): объявление DOCTYPE обрабатывается, внешние
    сущности `file://` и `http://` читаются и подставляются в документ.
    allow_dtd=False: любое DOCTYPE отклоняется (безопасный режим).
    """
    result: dict = {"entities": [], "text": [], "error": None}
    parser = xml.parsers.expat.ParserCreate()

    def entity_decl(name, is_param, value, base, system_id, public_id, notation):
        result["entities"].append({"name": name, "system": system_id, "value": value})

    def start_element(name, attrs):
        result["text"].append(f"<{name}>")

    def char_data(data):
        if data.strip():
            result["text"].append(data.strip())

    if allow_dtd:
        parser.EntityDeclHandler = entity_decl
    else:
        def reject_doctype(*_args):
            raise ValueError("DOCTYPE is not allowed")
        parser.StartDoctypeDeclHandler = reject_doctype

    parser.StartElementHandler = start_element
    parser.CharacterDataHandler = char_data

    # подстановка внешних сущностей вручную (имитация уязвимого парсера)
    expanded = data
    if allow_dtd:
        for match in re.finditer(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"', data):
            name, system_id = match.group(1), match.group(2)
            content = ""
            try:
                if system_id.startswith("file://"):
                    with open(system_id[7:], encoding="utf-8", errors="replace") as fh:
                        content = fh.read(4096)
                elif system_id.startswith(("http://", "https://")):
                    with urllib.request.urlopen(system_id, timeout=3) as response:
                        content = response.read(4096).decode("utf-8", "replace")
            except Exception as exc:  # noqa: BLE001
                content = f"[entity error: {exc.__class__.__name__}]"
            expanded = expanded.replace(f"&{name};", html.escape(content))

    try:
        parser.Parse(expanded, True)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{exc.__class__.__name__}: {exc}"
    return result


# ── SSRF-защита ───────────────────────────────────────────────────────
def is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def validate_url_safe(raw: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"схема не разрешена: {parsed.scheme or '<пусто>'}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("пустой host")
    if host not in ALLOWED_SSRF_HOSTS:
        raise ValueError(f"хост не в whitelist: {host}")
    try:
        infos = {ai[4][0] for ai in __import__("socket").getaddrinfo(host, None)}
    except OSError as exc:
        raise ValueError(f"не удалось разрешить имя: {exc}") from exc
    for ip in infos:
        if is_private_ip(ip):
            raise ValueError(f"адрес в приватном диапазоне: {ip}")
    return parsed


class Handler(BaseHTTPRequestHandler):
    server_version = "hackbook-vuln-hub/1.0"
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

    def _page(self, inner: str, status: int = 200,
              extra_headers: dict | None = None) -> None:
        self._send("<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>"
                   "<title>hackbook · vuln-hub</title>"
                   f"<style>{PAGE_CSS}</style></head><body>"
                   "<header><b>hackbook / vuln-hub</b> &nbsp;·&nbsp; девять классов "
                   "уязвимостей в одном стенде</header>"
                   f"<main>{inner}</main></body></html>", status,
                   extra_headers=extra_headers)

    def _audit(self, status: int) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        user = self._token_user() or "-"
        try:
            conn = connect()
            conn.execute(
                "INSERT INTO audit_log (method, path, query, status, user_agent) VALUES (?,?,?,?,?)",
                (self.command, parsed.path[:200], parsed.query[:500], status,
                 self.headers.get("User-Agent", "")[:160]))
            conn.commit()
            conn.close()
        except sqlite3.Error:
            pass

    def _params(self) -> dict:
        parsed = urllib.parse.urlsplit(self.path)
        return {k: v[0] for k, v in
                urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(min(length, 1024 * 1024)) if length else b""

    def _token(self) -> str | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("token")
        if morsel:
            return morsel.value
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return None

    def _token_user(self) -> str | None:
        token = self._token()
        if not token:
            return None
        try:
            claims = jwt_decode(token, JWT_SECRET)
        except Exception:  # noqa: BLE001
            return None
        return str(claims.get("sub"))

    def _result(self, inner: str, status: int = 200,
                extra_headers: dict | None = None) -> None:
        self._page(f"<div class='card'>{inner}</div>", status,
                   extra_headers=extra_headers)
        self._audit(status)

    # ── маршруты ──────────────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802
        params = self._params()
        route = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"

        if route == "/health":
            self._send("ok\n", 200, "text/plain; charset=utf-8"); return
        if route == "/":
            self._result(index_body()); return
        if route == "/jwks":
            self._send(json.dumps({"keys": [{"kty": "RSA", "alg": "RS256",
                                             "pem": PUBLIC_KEY_PEM}]}, ensure_ascii=False, indent=2),
                       200, "application/json; charset=utf-8"); return
        if route == "/logs":
            conn = connect()
            try:
                rows = [dict(r) for r in conn.execute(
                    "SELECT id, ts, method, path, query, status FROM audit_log "
                    "ORDER BY id DESC LIMIT 100")]
            finally:
                conn.close()
            self._send(json.dumps(rows, ensure_ascii=False, indent=2),
                       200, "application/json; charset=utf-8"); return

        handlers = {
            "/items": lambda: self.sql_items(params.get("id", "1"), safe=False),
            "/items_safe": lambda: self.sql_items(params.get("id", "1"), safe=True),
            "/notes": lambda: self.notes(params.get("id", "1"), safe=False),
            "/notes_safe": lambda: self.notes(params.get("id", "1"), safe=True),
            "/echo": lambda: self.echo(params.get("q", ""), safe=False),
            "/echo_safe": lambda: self.echo(params.get("q", ""), safe=True),
            "/fetch": lambda: self.fetch(params.get("url", ""), safe=False),
            "/fetch_safe": lambda: self.fetch(params.get("url", ""), safe=True),
            "/ping": lambda: self.ping(params.get("host", ""), safe=False),
            "/ping_safe": lambda: self.ping(params.get("host", ""), safe=True),
            "/read": lambda: self.read_file(params.get("file", "readme.txt"), safe=False),
            "/read_safe": lambda: self.read_file(params.get("file", "readme.txt"), safe=True),
            "/me": lambda: self.whoami(strict=False),
            "/me_safe": lambda: self.whoami(strict=True),
            "/admin": lambda: self.admin(),
        }
        handler = handlers.get(route)
        if handler:
            handler()
        else:
            self._page(f"<div class='card'><h2>404</h2><p>Путь "
                       f"<code>{html.escape(route)}</code> не найден.</p>"
                       "<p><a href='/'>Список эндпоинтов</a></p></div>", HTTPStatus.NOT_FOUND)
            self._audit(404)

    def do_POST(self) -> None:  # noqa: N802
        route = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
        raw_body = self._body().decode("utf-8", "replace")
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(raw_body, keep_blank_values=True).items()}
        if route == "/lookup":
            self.lookup(raw_body, safe=False)
        elif route == "/lookup_safe":
            self.lookup(raw_body, safe=True)
        elif route == "/login":
            self.login(form, strict=False)
        elif route == "/login_safe":
            self.login(form, strict=True)
        elif route == "/verify":
            self.verify(form, strict=False)
        elif route == "/verify_safe":
            self.verify(form, strict=True)
        else:
            self._page("<div class='card'>405</div>", HTTPStatus.METHOD_NOT_ALLOWED)
            self._audit(405)

    # ── SQLi / IDOR ───────────────────────────────────────────────────
    def sql_items(self, item_id: str, *, safe: bool) -> None:
        conn = connect()
        try:
            if safe:
                query = "SELECT id, name, price FROM items WHERE id = ?"
                rows = conn.execute(query, (item_id,)).fetchall()
            else:
                # УЯЗВИМО: конкатенация
                query = f"SELECT id, name, price, secret_note FROM items WHERE id = {item_id}"
                rows = conn.execute(query).fetchall()
        except sqlite3.Error as exc:
            self._result(f"<h2>/items{'_safe' if safe else ''}</h2><pre>{html.escape(query)}</pre>"
                         f"<div class='error'>SQL error\n{html.escape(str(exc))}</div>",
                         HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        finally:
            conn.close()
        if rows:
            head = "".join(f"<th>{k}</th>" for k in rows[0].keys())
            body = "".join("<tr>" + "".join(f"<td>{html.escape(str(r[k]))}</td>"
                                            for k in r.keys()) + "</tr>" for r in rows)
            self._result(f"<h2>/items{'_safe' if safe else ''}</h2><pre>{html.escape(query)}</pre>"
                         f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
        else:
            self._result(f"<h2>/items{'_safe' if safe else ''}</h2><pre>{html.escape(query)}</pre>"
                         "<p>Ничего не найдено.</p>")

    def notes(self, note_id: str, *, safe: bool) -> None:
        conn = connect()
        try:
            if safe:
                user = self._token_user() or "guest"
                row = conn.execute(
                    "SELECT id, owner, body FROM notes WHERE id = ? AND owner = ?",
                    (note_id, user)).fetchone()
            else:
                # УЯЗВИМО: проверка владельца отсутствует (IDOR)
                row = conn.execute("SELECT id, owner, body FROM notes WHERE id = ?",
                                   (note_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            self._result("<h2>Заметка</h2><div class='error'>Не найдено</div>",
                         HTTPStatus.NOT_FOUND)
            return
        self._result(f"<h2>Заметка #{row['id']}</h2><p>владелец: <code>{html.escape(row['owner'])}</code></p>"
                     f"<pre>{html.escape(row['body'])}</pre>")

    # ── XSS ───────────────────────────────────────────────────────────
    def echo(self, value: str, *, safe: bool) -> None:
        if safe:
            self._result(f"<h2>/echo_safe</h2><p>Вы сказали: {html.escape(value, quote=True)}</p>"
                         "<div class='ok'>Значение экранировано.</div>")
            return
        # УЯЗВИМО: сырое значение в HTML
        self._result(f"<h2>/echo</h2><p>Вы сказали: {value}</p>"
                     "<p><small>Значение выведено без экранирования.</small></p>")

    # ── SSRF ──────────────────────────────────────────────────────────
    def fetch(self, url: str, *, safe: bool) -> None:
        if not url:
            self._result("<h2>Fetch</h2><p>Передайте <code>?url=</code></p>")
            return
        try:
            if safe:
                validate_url_safe(url)
            else:
                parsed = urllib.parse.urlsplit(url)
                if parsed.scheme not in {"http", "https", "file"}:
                    raise ValueError(f"схема не поддерживается: {parsed.scheme}")
            if url.startswith("file://"):
                with open(url[7:], encoding="utf-8", errors="replace") as fh:
                    content = fh.read(4096)
                source = "file"
            else:
                request = urllib.request.Request(url, headers={"User-Agent": "hackbook-vuln-hub"})
                with urllib.request.urlopen(request, timeout=4) as response:  # noqa: S310
                    content = response.read(4096).decode("utf-8", "replace")
                    source = f"HTTP {response.status}"
        except Exception as exc:  # noqa: BLE001
            self._result(f"<h2>Fetch</h2><div class='error'>{html.escape(exc.__class__.__name__)}: "
                         f"{html.escape(str(exc))}</div>", HTTPStatus.BAD_GATEWAY)
            return
        self._result(f"<h2>Fetch: {html.escape(url)}</h2><p><small>источник: {html.escape(source)}</small></p>"
                     f"<pre>{html.escape(content)}</pre>")

    # ── Command injection ─────────────────────────────────────────────
    def ping(self, host: str, *, safe: bool) -> None:
        if not host:
            self._result("<h2>Ping</h2><p>Передайте <code>?host=</code></p>")
            return
        command = "ping -c 1 -W 2 " + host
        try:
            if safe:
                if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,120}", host):
                    raise ValueError("недопустимые символы в имени хоста")
                proc = subprocess.run(["ping", "-c", "1", "-W", "2", host],
                                      capture_output=True, text=True, timeout=6)
                command = f"ping -c 1 -W 2 {host}"
            else:
                # УЯЗВИМО: shell=True с пользовательскими данными
                command = f"ping -c 1 -W 2 {host} 2>&1; echo HB-CMD-MARKER"
                proc = subprocess.run(command, shell=True, capture_output=True,
                                      text=True, timeout=6)
            output = (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            output = "HB-CMD-MARKER (timeout)" if not safe else "timeout"
        except Exception as exc:  # noqa: BLE001
            output = f"{exc.__class__.__name__}: {exc}"
        self._result(f"<h2>Ping</h2><pre>{html.escape(command)}</pre>"
                     f"<pre>{html.escape(output[:4000])}</pre>")

    # ── LFI ───────────────────────────────────────────────────────────
    def read_file(self, name: str, *, safe: bool) -> None:
        try:
            if safe:
                base = os.path.realpath(DOCS_DIR)
                target = os.path.realpath(os.path.join(base, name))
                if not target.startswith(base + os.sep) and target != base:
                    raise ValueError("выход за пределы каталога документов")
            else:
                # УЯЗВИМО: путь собирается из параметра без нормализации
                target = os.path.join(DOCS_DIR, name)
            if not os.path.isfile(target):
                raise FileNotFoundError(target)
            with open(target, encoding="utf-8", errors="replace") as fh:
                content = fh.read(8192)
        except Exception as exc:  # noqa: BLE001
            self._result(f"<h2>Read</h2><div class='error'>{html.escape(exc.__class__.__name__)}: "
                         f"{html.escape(str(exc))}</div>", HTTPStatus.NOT_FOUND)
            return
        self._result(f"<h2>Read: {html.escape(name)}</h2>"
                     f"<p><small>путь: <code>{html.escape(target)}</code></small></p>"
                     f"<pre>{html.escape(content)}</pre>")

    # ── XXE ───────────────────────────────────────────────────────────
    def lookup(self, data: str, *, safe: bool) -> None:
        if not data.strip():
            self._result("<h2>Lookup</h2><p>Отправьте XML телом POST "
                         "(<code>Content-Type: application/xml</code>).</p>")
            return
        parsed = parse_xml_unsafe(data, allow_dtd=not safe)
        status = HTTPStatus.BAD_REQUEST if parsed["error"] and safe else HTTPStatus.OK
        entities = "".join(f"<li><code>{html.escape(str(e))}</code></li>"
                           for e in parsed["entities"]) or "<li>нет</li>"
        self._result(
            f"<h2>Lookup{'_safe' if safe else ''}</h2>"
            f"<p>Объявленные сущности:</p><ul>{entities}</ul>"
            f"<pre>{html.escape(' '.join(parsed['text'])[:4000])}</pre>"
            + (f"<div class='error'>{html.escape(parsed['error'])}</div>" if parsed["error"] else "")
            + ("<div class='ok'>DOCTYPE запрещён: внешние сущности не обрабатываются.</div>"
               if safe else ""), status)

    # ── JWT / 2FA ─────────────────────────────────────────────────────
    def login(self, form: dict, *, strict: bool) -> None:
        login = form.get("login", "")
        password = form.get("password", "")
        conn = connect()
        try:
            row = conn.execute(
                "SELECT id, login, role, totp_secret FROM users WHERE login = ? AND password_sha256 = ?",
                (login, sha256(password))).fetchone()
            if not row:
                self._result("<h2>Вход</h2><div class='error'>Неверный логин или пароль</div>",
                             HTTPStatus.UNAUTHORIZED)
                return
            claims = {
                "sub": row["login"],
                "role": row["role"],
                "mfa": False,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            }
            # УЯЗВИМО (strict=False): роль кладётся в токен, алгоритм не фиксируется,
            # секрет слабый и совпадает со словарным значением
            token = jwt_encode(claims, JWT_SECRET)
        finally:
            conn.close()
        self._result(f"<h2>Вход выполнен{'_safe' if strict else ''}</h2>"
                     f"<div class='ok'>sub=<code>{html.escape(login)}</code></div>"
                     f"<p>Токен:</p><pre>{html.escape(token)}</pre>"
                     "<p>Дальше: <code>POST /verify</code> (код 2FA), затем "
                     "<code>/me</code> и <code>/admin</code>.</p>"
                     f"<p><small>Секрет подписи лаборатории: <code>{html.escape(JWT_SECRET)}</code>"
                     "</small></p>",
                     extra_headers={"Set-Cookie": f"token={token}; Path=/; HttpOnly; SameSite=Lax"})

    def whoami(self, *, strict: bool) -> None:
        token = self._token()
        if not token:
            self._result("<h2>/me</h2><div class='error'>Нет токена</div>", HTTPStatus.UNAUTHORIZED)
            return
        try:
            claims = jwt_decode(token, JWT_SECRET, strict_alg=strict)
        except Exception as exc:  # noqa: BLE001
            self._result(f"<h2>/me{'_safe' if strict else ''}</h2>"
                         f"<div class='error'>Токен отклонён: {html.escape(str(exc))}</div>",
                         HTTPStatus.UNAUTHORIZED)
            return
        self._result(f"<h2>/me{'_safe' if strict else ''}</h2>"
                     f"<pre>{html.escape(json.dumps(claims, ensure_ascii=False, indent=2))}</pre>")

    def admin(self) -> None:
        token = self._token()
        if not token:
            self._result("<h2>/admin</h2><div class='error'>Нет токена</div>", HTTPStatus.FORBIDDEN)
            return
        try:
            claims = jwt_decode(token, JWT_SECRET)
        except Exception as exc:  # noqa: BLE001
            self._result(f"<h2>/admin</h2><div class='error'>{html.escape(str(exc))}</div>",
                         HTTPStatus.UNAUTHORIZED)
            return
        if claims.get("role") != "admin" or not claims.get("mfa"):
            self._result("<h2>/admin</h2><div class='error'>Нужны role=admin и mfa=true</div>"
                         f"<pre>{html.escape(json.dumps(claims, ensure_ascii=False))}</pre>",
                         HTTPStatus.FORBIDDEN)
            return
        conn = connect()
        try:
            users = [dict(r) for r in conn.execute("SELECT id, login, role FROM users")]
        finally:
            conn.close()
        self._result("<h2>/admin</h2><div class='ok'>Доступ разрешён</div>"
                     f"<pre>{html.escape(json.dumps(users, ensure_ascii=False, indent=2))}</pre>")

    def verify(self, form: dict, *, strict: bool) -> None:
        token = self._token() or form.get("token", "")
        code = form.get("code", "")
        if not token:
            self._result("<h2>2FA</h2><div class='error'>Нет токена</div>", HTTPStatus.UNAUTHORIZED)
            return
        try:
            claims = jwt_decode(token, JWT_SECRET, strict_alg=strict)
        except Exception as exc:  # noqa: BLE001
            self._result(f"<h2>2FA</h2><div class='error'>{html.escape(str(exc))}</div>",
                         HTTPStatus.UNAUTHORIZED)
            return

        if strict:
            # безопасная ветка: код проверяется по TOTP-секрету на сервере,
            # флаг mfa выдаётся только после успешной проверки и одноразово
            if code != "123456":     # учебный фиксированный код вместо TOTP
                self._result("<h2>2FA</h2><div class='error'>Неверный код</div>",
                             HTTPStatus.UNAUTHORIZED)
                return
        else:
            # УЯЗВИМО: флаг берётся из клиентского поля, код не проверяется
            if not form.get("mfa_passed") and code != "123456":
                self._result("<h2>2FA</h2><div class='error'>Требуется код или флаг "
                             "<code>mfa_passed=1</code></div>", HTTPStatus.UNAUTHORIZED)
                return

        claims["mfa"] = True
        new_token = jwt_encode(claims, JWT_SECRET)
        self._result(f"<h2>2FA пройдена{'_safe' if strict else ''}</h2>"
                     f"<div class='ok'>mfa=true</div><p>Новый токен:</p>"
                     f"<pre>{html.escape(new_token)}</pre><p><a href='/admin'>/admin</a></p>",
                     extra_headers={"Set-Cookie": f"token={new_token}; Path=/; HttpOnly; SameSite=Lax"})


def main() -> int:
    init()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[lab] vuln-hub слушает 0.0.0.0:{PORT}, db={DB_PATH}, docs={DOCS_DIR}, "
          f"ssrf_whitelist={sorted(ALLOWED_SSRF_HOSTS)}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
