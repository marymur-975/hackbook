#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка ссылок в Markdown-файлах репозитория.

Что проверяется:
  * относительные ссылки `[text](path)` и `![img](path)` — файл существует;
  * якоря `[text](file.md#anchor)` — заголовок с таким слагом есть в файле;
  * пути в front-matter (`related_payloads`, `lab`, `references` локальные);
  * директивы `{{ include "..." }}` и `{! ... !}` — цель существует;
  * (опционально, `--external`) внешние http(s)-ссылки — HEAD/GET запросом.

Примеры:
    python tools/link-checker.py
    python tools/link-checker.py --external --timeout 8
    python tools/link-checker.py --paths book payloads docs --strict
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import ipaddress
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.mdparse import (  # noqa: E402
    FENCE_RE,
    extract_headings,
    extract_includes,
    iter_markdown_files,
    parse_front_matter,
    slugify,
)

ROOT = HERE.parent
LINK_RE = re.compile(r"!?\[[^\]]*\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
AUTO_LINK_RE = re.compile(r"(?<![\w\"'=])<(https?://[^>\s]+)>")
BARE_URL_RE = re.compile(r"(?<![\w\"'=(/`])(https?://[^\s\"'<>)\]`]+)")
SKIP_DIRS = {".git", "node_modules", "build", "site", ".venv", "__pycache__"}

# Адреса-примеры из RFC: в карточках payload'ов они используются как заглушки
# («ваш collaborator», «внутренний сервис»). Проверять их по сети бессмысленно.
PLACEHOLDER_HOST_RE = re.compile(
    r"(?:^|\.)("
    r"attacker\.tld|example\.(?:com|org|net)|legit\.com|notlegit\.com|"
    r"lab\.local|localhost|localtest\.me|test|invalid|collaborator|"
    r"expected\.com|data\.attacker\.tld|rb\.example\.tld"
    r")$", re.IGNORECASE)
RESERVED_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.168.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
    )
]
USER_AGENT = "hackbook-link-checker/1.0 (+https://github.com/hackbook)"


@dataclass
class Issue:
    path: str
    line: int
    target: str
    message: str
    external: bool = False

    def as_str(self) -> str:
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"{where} -> {self.target} : {self.message}"


@dataclass
class Report:
    issues: list[Issue] = field(default_factory=list)
    checked_files: int = 0
    checked_links: int = 0
    external_checked: int = 0

    def add(self, *args, **kwargs) -> None:
        self.issues.append(Issue(*args, **kwargs))


def anchors_of(path: Path) -> set[str]:
    """Множество якорей (слагов заголовков) файла."""
    try:
        _, body = parse_front_matter(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return set()
    return {slugify(text) for _, text in extract_headings(body)}


def is_external(target: str) -> bool:
    return bool(re.match(r"^[a-z][a-z0-9+.-]*://", target)) or target.startswith("mailto:")


def skip_target(target: str) -> bool:
    if not target or target.startswith(("#", "mailto:", "tel:")):
        return True
    return False


def check_local(target: str, source: Path, repo_root: Path,
                anchor_cache: dict[Path, set[str]]) -> str | None:
    """Возвращает текст проблемы или None, если ссылка валидна."""
    path_part, _, anchor = target.partition("#")
    if not path_part:
        # внутренняя ссылка на якорь того же файла
        if anchor and anchor not in anchor_cache.setdefault(source, anchors_of(source)):
            return f"якорь #{anchor} не найден в этом файле"
        return None

    candidate = (source.parent / path_part)
    if not candidate.exists():
        candidate = repo_root / path_part
    if not candidate.exists():
        return "файл не найден"

    if candidate.is_dir():
        # Каталог без README — не битая ссылка: GitHub и MkDocs показывают
        # листинг/индекс. Ошибкой считаем только пустой каталог.
        if not any(candidate.iterdir()):
            return "пустой каталог"
        return None

    if anchor:
        known = anchor_cache.setdefault(candidate, anchors_of(candidate))
        if anchor not in known:
            return f"якорь #{anchor} не найден в {candidate.name}"
    return None


def is_placeholder_host(host: str) -> bool:
    """True для адресов-заглушек и приватных/loopback-диапазонов."""
    host = host.strip("[]").lower()
    if PLACEHOLDER_HOST_RE.search(host):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in RESERVED_NETWORKS)


def check_external(url: str, timeout: int) -> str | None:
    # URL из примеров payload'ов может быть заведомо некорректным
    # (http://[::ffff:127.0.0.1]/ и т.п.) — не роняем проверку на нём
    try:
        parsed = urllib.parse.urlsplit(url)
        if not parsed.scheme or not parsed.netloc:
            return "некорректный URL (пропущен, пример из payload'а)"
    except ValueError:
        return "некорректный URL (пропущен, пример из payload'а)"
    host = (parsed.hostname or "")
    if is_placeholder_host(host):
        return "адрес-заглушка (пропущен намеренно)"
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            if response.status >= 400:
                return f"HTTP {response.status}"
            return None
    except urllib.error.HTTPError as exc:
        # многие сайты отдают 403/404/405 на HEAD, хотя GET работает —
        # перепроверяем любым другим методом, прежде чем считать ссылку битой
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                return None if response.status < 400 else f"HTTP {response.status}"
        except urllib.error.HTTPError as exc2:
            return f"HTTP {exc2.code}"
        except Exception as exc2:  # noqa: BLE001
            return f"HTTP {exc.code} (HEAD), GET: {exc2.__class__.__name__}"
    except Exception as exc:  # noqa: BLE001
        return exc.__class__.__name__


def collect_targets(text: str, source: Path) -> list[tuple[int, str]]:
    """Ссылки в теле документа. Содержимое code-fence игнорируется: там
    регулярно встречаются конструкции вида `<img src=x onerror=alert(1)>`,
    которые парсер принял бы за ссылки."""
    out: list[tuple[int, str]] = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in LINK_RE.finditer(line):
            out.append((number, match.group("target")))
        for match in AUTO_LINK_RE.finditer(line):
            out.append((number, match.group(1)))
        for match in BARE_URL_RE.finditer(line):
            out.append((number, match.group(1).rstrip(".,;:)`'\"")))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка ссылок в hackbook")
    parser.add_argument("--paths", nargs="*", default=None,
                        help="каталоги для проверки (по умолчанию весь репозиторий)")
    parser.add_argument("--external", action="store_true", help="проверять http(s)-ссылки")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--strict", action="store_true",
                        help="предупреждения (внешние ссылки) считаются ошибками")
    parser.add_argument("--include-frontmatter", action="store_true", default=True)
    args = parser.parse_args(argv)

    roots = [ROOT / p for p in args.paths] if args.paths else [ROOT]
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
            continue
        files.extend(f for f in iter_markdown_files(root)
                     if not any(part in SKIP_DIRS for part in f.parts))

    report = Report()
    anchor_cache: dict[Path, set[str]] = {}
    external: dict[str, list[tuple[Path, int]]] = {}

    for path in files:
        report.checked_files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            report.add(str(path.relative_to(ROOT)), 0, "-", f"не читается: {exc}")
            continue

        meta, body = parse_front_matter(text)

        # ссылки в теле
        for number, target in collect_targets(text, path):
            if skip_target(target):
                continue
            report.checked_links += 1
            if is_external(target):
                if args.external:
                    external.setdefault(target, []).append((path, number))
                continue
            problem = check_local(target, path, ROOT, anchor_cache)
            if problem:
                report.add(str(path.relative_to(ROOT)), number, target, problem)

        # пути из front-matter
        if args.include_frontmatter:
            for key in ("related_payloads", "lab", "prerequisites_files"):
                values = meta.get_list(key)
                for value in values:
                    value = str(value)
                    if not value or value.lower() in {"null", "none"}:
                        continue
                    if is_external(value):
                        continue
                    report.checked_links += 1
                    problem = check_local(value, path, ROOT, anchor_cache)
                    if problem:
                        report.add(str(path.relative_to(ROOT)), 0, f"{key}: {value}", problem)

            # внешние ссылки из front-matter (references)
            for value in meta.get_list("references"):
                value = str(value)
                if not is_external(value) or value.startswith("mailto:"):
                    continue
                report.checked_links += 1
                if args.external:
                    external.setdefault(value, []).append((path, 0))

        # include-директивы
        for inc in extract_includes(body):
            report.checked_links += 1
            problem = check_local(inc["path"], ROOT, ROOT, anchor_cache)
            if problem:
                report.add(str(path.relative_to(ROOT)), 0,
                           f'include "{inc["path"]}"', problem)

    # внешние ссылки — параллельно
    if external:
        print(f"Проверяю {len(external)} внешних ссылок (timeout={args.timeout} c)…")
        with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = dict(zip(external, pool.map(
                lambda u: check_external(u, args.timeout), external)))
        skipped = 0
        for url, problem in results.items():
            report.external_checked += 1
            if problem and problem.startswith(("некорректный URL", "адрес-заглушка")):
                skipped += 1
                continue
            if problem:
                for path, number in external[url]:
                    report.add(str(path.relative_to(ROOT)), number, url, problem, external=True)
        if skipped:
            print(f"Пропущено некорректных URL из примеров payload'ов: {skipped}")

    print(f"Файлов: {report.checked_files}, ссылок: {report.checked_links}"
          + (f", внешних проверено: {report.external_checked}" if args.external else ""))
    local_issues = [i for i in report.issues if not i.external]
    ext_issues = [i for i in report.issues if i.external]
    print(f"Битых локальных ссылок: {len(local_issues)}")
    for issue in local_issues[:60]:
        print("  " + issue.as_str())
    if len(local_issues) > 60:
        print(f"  … и ещё {len(local_issues) - 60}")

    if ext_issues:
        print(f"Проблемных внешних ссылок: {len(ext_issues)}")
        for issue in ext_issues[:30]:
            print("  " + issue.as_str())
        if len(ext_issues) > 30:
            print(f"  … и ещё {len(ext_issues) - 30}")

    failed = bool(local_issues) or (args.strict and bool(ext_issues))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
