#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP-запрос для tools/payload-tester.sh.

Отдельный файл (а не heredoc внутри bash) — потому что heredoc внутри
`$( ... )` конфликтует со stdin внешнего скрипта и молча возвращает пустоту.

Использование:
    tools/lib/http_fetch.py URL [TIMEOUT] [METHOD] [POSTDATA]

Коды выхода:
    0  — ответ получен (включая HTTP 4xx/5xx: тело печатается в stdout)
    7  — цель недоступна (таймаут, отказ соединения) — тестер считает это SKIP
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

USER_AGENT = "hackbook-payload-tester/1.0"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    url = argv[0]
    timeout = int(argv[1]) if len(argv) > 1 else 8
    method = (argv[2] if len(argv) > 2 else "GET").upper()
    post_data = argv[3].encode() if len(argv) > 3 else None

    request = urllib.request.Request(url, data=post_data, method=method,
                                     headers={"User-Agent": USER_AGENT})
    if post_data is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            sys.stdout.write(response.read().decode("utf-8", "replace"))
        return 0
    except urllib.error.HTTPError as exc:
        # 4xx/5xx — это тоже результат теста: тело часто содержит ошибку СУБД
        sys.stdout.write(exc.read().decode("utf-8", "replace"))
        return 0
    except Exception:  # noqa: BLE001
        return 7


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
