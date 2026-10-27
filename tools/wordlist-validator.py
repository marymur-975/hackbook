#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Валидация словарей `wordlists/`.

Проверяет:
  * кодировку (только UTF-8/ASCII) и отсутствие управляющих символов;
  * дубликаты и пустые строки;
  * длину строк и размер файла против лимитов;
  * соответствие `wordlists/metadata.yaml`: путь существует, размер совпадает,
    обязательные поля заполнены;
  * «мусор» в списках: строки с пробелами по краям, CRLF, BOM.

Дополнительно (--secrets) ищет в словарях случайные утечки: строки, похожие на
ключи API, приватные ключи, JWT и connection strings — такие артефакты не должны
попадать в публичный репозиторий.

Примеры:
    python tools/wordlist-validator.py
    python tools/wordlist-validator.py --max-lines 100000 --strict
    python tools/wordlist-validator.py --secrets --json report.json
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.repo import build_index, load_yaml_sidecar  # noqa: E402

ROOT = HERE.parent

DEFAULT_MAX_LINES = 5_000_000
DEFAULT_MAX_BYTES = 200 * 1024 * 1024
DEFAULT_MAX_LINE = 256

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "generic-api-key": re.compile(r"\b(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*\S{12,}", re.I),
    "connection-string": re.compile(r"\b(?:mysql|postgres(?:ql)?|mongodb|redis)://\S+:\S+@\S+", re.I),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
}

REQUIRED_META_FIELDS = ("name", "path")
KNOWN_USE_CASES = {
    "bruteforce", "password-spray", "fuzzing", "directory-bruteforce",
    "username-enumeration", "subdomain", "parameter-discovery", "vhost",
    "snmp-community", "credential-stuffing", "ctf", "reference",
}


@dataclass
class Issue:
    path: str
    level: str          # error | warning
    message: str

    def as_str(self) -> str:
        return f"[{self.level.upper()}] {self.path}: {self.message}"


@dataclass
class Report:
    issues: list[Issue] = field(default_factory=list)
    checked: int = 0
    lines: int = 0
    bytes: int = 0

    def add(self, path, level: str, message: str) -> None:
        self.issues.append(Issue(str(path), level, message))

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning"]


def check_encoding(path: Path, report: Report) -> bytes | None:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        report.add(path, "error", "файл начинается с BOM — удалите его")
    if b"\r\n" in raw:
        report.add(path, "error", "найден CRLF — приведите переносы к LF")
    elif b"\r" in raw:
        report.add(path, "warning", "найден одиночный CR")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        report.add(path, "error", f"не UTF-8: {exc}")
        return None
    return raw


def check_content(path: Path, raw: bytes, report: Report, *,
                  max_lines: int, max_line: int, check_secrets: bool) -> tuple[int, int]:
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    else:
        report.add(path, "warning", "файл не заканчивается переводом строки")

    seen: dict[str, int] = {}
    dupes = 0
    empty = 0
    for number, line in enumerate(lines, start=1):
        if not line:
            empty += 1
            if empty <= 3:
                report.add(path, "error", f"строка {number}: пустая")
            continue
        if line != line.strip():
            report.add(path, "error", f"строка {number}: пробелы по краям ({line!r})")
        if CONTROL_CHARS.search(line):
            report.add(path, "error", f"строка {number}: управляющие символы")
        if len(line) > max_line:
            report.add(path, "warning", f"строка {number}: длина {len(line)} > {max_line}")
        if line in seen:
            dupes += 1
            if dupes <= 5:
                report.add(path, "warning",
                           f"строка {number}: дубликат строки {seen[line]} ({line!r})")
        else:
            seen[line] = number
        if check_secrets:
            for name, pattern in SECRET_PATTERNS.items():
                if pattern.search(line):
                    report.add(path, "error",
                               f"строка {number}: похож на секрет ({name}) — "
                               f"удалите из публичного словаря")
                    break

    if dupes > 5:
        report.add(path, "warning", f"всего дубликатов: {dupes}")
    if empty > 3:
        report.add(path, "warning", f"всего пустых строк: {empty}")
    if len(lines) > max_lines:
        report.add(path, "error", f"строк {len(lines)} > лимита {max_lines}")
    return len(lines), len(raw)


def check_metadata(repo, report: Report, *, require_meta: bool) -> dict[str, dict]:
    meta_path = repo.wordlists_dir / "metadata.yaml"
    entries: dict[str, dict] = {}
    if not meta_path.exists():
        report.add(meta_path, "error" if require_meta else "warning",
                   "metadata.yaml отсутствует")
        return entries

    data = load_yaml_sidecar(meta_path)
    items = data.get("wordlists") or data.get("_items") or []
    if not isinstance(items, list):
        report.add(meta_path, "error", "ключ `wordlists` должен быть списком")
        return entries

    # внешние наборы скачиваются по запросу — их отсутствие файлом не считается
    optional_paths: set[str] = set()
    for item in data.get("external") or []:
        if isinstance(item, dict) and item.get("path"):
            optional_paths.add(str(item["path"]))

    declared_paths: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            report.add(meta_path, "error", f"элемент #{index}: ожидается словарь")
            continue
        missing = [f for f in REQUIRED_META_FIELDS if not item.get(f)]
        if missing:
            report.add(meta_path, "error",
                       f"элемент #{index} ({item.get('name', '?')}): нет полей {missing}")
            continue
        rel = str(item["path"])
        declared_paths.add(rel)
        target = repo.root / "wordlists" / rel
        if not target.exists():
            target = repo.root / rel
        if not target.exists():
            if rel in optional_paths:
                report.add(rel, "warning",
                           "внешний набор не скачан — запустите wordlists/fetch-external.sh")
                continue
            report.add(meta_path, "error", f"{item['name']}: файл `{rel}` не найден")
            continue

        size = item.get("size")
        if size is not None:
            actual = sum(1 for _ in target.open(encoding="utf-8", errors="replace"))
            if int(size) != actual:
                report.add(rel, "warning",
                           f"в metadata.yaml size={size}, в файле строк={actual}")

        use_cases = item.get("use_cases") or []
        if isinstance(use_cases, str):
            use_cases = [use_cases]
        unknown = [uc for uc in use_cases if uc not in KNOWN_USE_CASES]
        if unknown:
            report.add(rel, "warning",
                       f"неизвестные use_cases {unknown}; допустимые: {sorted(KNOWN_USE_CASES)}")

        updated = str(item.get("last_updated") or "")
        if updated:
            try:
                datetime.date.fromisoformat(updated)
            except ValueError:
                report.add(rel, "warning", f"last_updated `{updated}` не в формате ISO-8601")

        if not item.get("source"):
            report.add(rel, "warning", "не указан `source` — добавьте происхождение списка")
        if not item.get("license"):
            report.add(rel, "warning", "не указан `license` — добавьте лицензию источника")

        entries[rel] = item

    # файлы, которых нет в metadata
    for path in repo.wordlists():
        rel = path.relative_to(repo.wordlists_dir).as_posix()
        if rel not in declared_paths and f"wordlists/{rel}" not in declared_paths:
            report.add(rel, "warning", "файл не описан в metadata.yaml")
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка словарей hackbook")
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--max-line", type=int, default=DEFAULT_MAX_LINE)
    parser.add_argument("--secrets", action="store_true",
                        help="искать в словарях утечки секретов")
    parser.add_argument("--strict", action="store_true",
                        help="считать предупреждения ошибками")
    parser.add_argument("--json", default=None, help="записать отчёт в JSON")
    parser.add_argument("--dedupe", action="store_true",
                        help="не только проверить, но и перезаписать файлы без дубликатов")
    args = parser.parse_args(argv)

    repo = build_index(ROOT)
    report = Report()
    paths = repo.wordlists()
    if not paths:
        print("Словари не найдены в wordlists/ — проверять нечего.")

    for path in paths:
        report.checked += 1
        if path.stat().st_size > args.max_bytes:
            report.add(path, "error",
                       f"размер {path.stat().st_size} больше лимита {args.max_bytes}")
        raw = check_encoding(path, report)
        if raw is None:
            continue
        lines, size = check_content(path, raw, report, max_lines=args.max_lines,
                                    max_line=args.max_line, check_secrets=args.secrets)
        report.lines += lines
        report.bytes += size
        if args.dedupe:
            text = raw.decode("utf-8", errors="replace")
            unique: list[str] = []
            seen: set[str] = set()
            for line in text.split("\n"):
                if line.strip() and line not in seen:
                    seen.add(line)
                    unique.append(line)
            path.write_text("\n".join(unique) + "\n", encoding="utf-8")

    check_metadata(repo, report, require_meta=True)

    problems = report.errors + (report.warnings if args.strict else [])
    print(f"Проверено файлов: {report.checked}, строк: {report.lines}, "
          f"объём: {report.bytes / 1024:.1f} КБ")
    print(f"Ошибок: {len(report.errors)}, предупреждений: {len(report.warnings)}")
    for issue in report.issues[:60]:
        print("  " + issue.as_str())
    if len(report.issues) > 60:
        print(f"  … и ещё {len(report.issues) - 60}")

    if args.json:
        out = Path(args.json)
        out.write_text(json.dumps({
            "checked": report.checked, "lines": report.lines, "bytes": report.bytes,
            "errors": [i.as_str() for i in report.errors],
            "warnings": [i.as_str() for i in report.warnings],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Отчёт: {out}")

    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
