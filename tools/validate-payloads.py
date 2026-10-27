#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Валидация payload'ов и глав `hackbook` (используется в CI).

Проверяет единый формат контента:
  * front-matter присутствует и парсится;
  * обязательные поля заполнены, значения — из разрешённых наборов;
  * `id` уникален во всём репозитории и совпадает с именем файла;
  * обязательные секции на месте (`## Payload`, `## Explanation`,
    `## Detection`, `## Remediation`);
  * первый code-блок без указания языка существует и непустой;
  * ссылки на файлы (`related_payloads`, `lab`, `{{ include }}`) существуют;
  * рёбра графа используют известные типы и указывают на существующие узлы;
  * `success_rate`, `risk`, `difficulty`, `cwe` — в допустимом формате;
  * в payload'е есть пометка об этике.

Примеры:
    python tools/validate-payloads.py
    python tools/validate-payloads.py --strict --type sqli
    python tools/validate-payloads.py --json report.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.mdparse import extract_code_blocks, extract_headings, extract_includes  # noqa: E402
from lib.repo import build_index  # noqa: E402

ROOT = HERE.parent

VALID_TYPES = {"sqli", "xss", "ssrf", "lfi", "rfi", "xxe", "cmdi", "ssti",
               "auth-bypass", "header", "network", "cloud", "ad"}
VALID_DIFFICULTY = {"beginner", "intermediate", "advanced", "expert"}
VALID_BYPASS = {"none", "waf", "filter", "encoding", "auth", "sandbox"}
VALID_RISK = {"low", "medium", "high", "critical"}
VALID_CATEGORIES = {"web", "network", "active-directory", "cloud",
                    "privilege-escalation", "general"}
VALID_EDGE_TYPES = {"leads_to", "instance_of", "related_to", "technique_of",
                    "covered_in", "practiced_in", "requires", "category_of", "uses"}
REQUIRED_PAYLOAD_FIELDS = ("id", "title", "type", "target", "difficulty", "tags", "tested_on")
REQUIRED_SECTIONS = ("Payload", "Explanation", "Detection", "Remediation")
CWE_RE = re.compile(r"^CWE-\d{2,5}$")
ETHICS_RE = re.compile(r"!!!\s+(?:warning|danger)\s+\"Этика\"|разрешени|авторизован", re.I)

# Понятийные узлы графа: создаются автоматически из рёбер payload'ов.
# Совпадает с CONCEPT_LABELS в tools/graph-generator.py.
KNOWN_CONCEPTS = {
    "sqli", "xss", "ssrf", "lfi-rfi", "xxe", "cmdi", "ssti", "auth-bypass", "headers",
    "rce", "privilege-escalation", "data-exfiltration", "info-disclosure", "waf-bypass",
    "oob", "enumeration", "bruteforce", "default-credentials", "credential-access",
    "session-hijacking", "cache-poisoning", "open-redirect", "http-request-smuggling",
    "admin-panel", "file-upload", "container-escape", "dos", "fingerprinting",
    "data-tampering", "client-side", "jwt", "csp", "network", "active-directory",
    "cloud", "web",
}


@dataclass
class Issue:
    path: str
    level: str
    message: str

    def as_str(self) -> str:
        return f"[{self.level.upper()}] {self.path}: {self.message}"


@dataclass
class Report:
    issues: list[Issue] = field(default_factory=list)

    def add(self, path, level: str, message: str) -> None:
        self.issues.append(Issue(str(path), level, message))

    @property
    def errors(self):
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self):
        return [i for i in self.issues if i.level == "warning"]


def check_front_matter(doc, report: Report, *, is_payload: bool) -> None:
    meta = doc.meta
    if not meta:
        report.add(doc.rel, "error", "нет YAML front-matter")
        return

    if is_payload:
        for key in REQUIRED_PAYLOAD_FIELDS:
            if key not in meta or meta.get(key) in ("", None, []):
                report.add(doc.rel, "error", f"не заполнено обязательное поле `{key}`")

    ptype = str(meta.get("type") or "")
    if is_payload and ptype not in VALID_TYPES:
        report.add(doc.rel, "error",
                   f"type=`{ptype}` вне списка {sorted(VALID_TYPES)}")

    difficulty = str(meta.get("difficulty") or "")
    if difficulty and difficulty not in VALID_DIFFICULTY:
        report.add(doc.rel, "error",
                   f"difficulty=`{difficulty}` вне списка {sorted(VALID_DIFFICULTY)}")

    bypass = str(meta.get("bypass") or "none")
    if bypass not in VALID_BYPASS:
        report.add(doc.rel, "error", f"bypass=`{bypass}` вне списка {sorted(VALID_BYPASS)}")

    risk = str(meta.get("risk") or "")
    if risk and risk not in VALID_RISK:
        report.add(doc.rel, "error", f"risk=`{risk}` вне списка {sorted(VALID_RISK)}")

    category = str(meta.get("category") or "")
    if category and category not in VALID_CATEGORIES:
        report.add(doc.rel, "error",
                   f"category=`{category}` вне списка {sorted(VALID_CATEGORIES)}")

    cwe = meta.get("cwe")
    if cwe not in (None, "", "null") and not CWE_RE.match(str(cwe)):
        report.add(doc.rel, "warning", f"cwe=`{cwe}` не в формате CWE-NNN")

    rate = meta.get("success_rate")
    if rate is not None:
        try:
            value = float(rate)
            if not 0.0 <= value <= 1.0:
                report.add(doc.rel, "error", f"success_rate={value} вне диапазона 0..1")
        except (TypeError, ValueError):
            report.add(doc.rel, "error", f"success_rate=`{rate}` не число")

    tags = meta.get_list("tags")
    if is_payload and not tags:
        report.add(doc.rel, "warning", "пустой список tags — узел не найдётся поиском")
    for tag in tags:
        if not re.fullmatch(r"[\w][\w._-]{0,40}", str(tag), re.UNICODE):
            report.add(doc.rel, "warning", f"тег `{tag}` не в kebab-case")

    tested = meta.get_list("tested_on")
    if is_payload and not tested:
        report.add(doc.rel, "warning",
                   "не заполнено tested_on — неизвестно, где payload проверялся")

    verified = str(meta.get("last_verified") or "")
    if verified and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", verified):
        report.add(doc.rel, "warning", f"last_verified=`{verified}` не в формате ISO-8601")

    refs = meta.get_list("references")
    for ref in refs:
        if not str(ref).startswith(("http://", "https://")):
            report.add(doc.rel, "warning", f"reference `{ref}` не является URL")


def check_body(doc, report: Report, *, is_payload: bool) -> None:
    headings = [text for _, text in extract_headings(doc.body)]
    if not headings:
        report.add(doc.rel, "error", "в теле нет ни одного заголовка")
    elif not headings[0]:
        report.add(doc.rel, "warning", "первый заголовок пустой")

    if is_payload:
        missing = [s for s in REQUIRED_SECTIONS if s not in headings]
        if missing:
            report.add(doc.rel, "error", f"нет обязательных секций: {missing}")

        blocks = extract_code_blocks(doc.body)
        bare = [b for b in blocks if not b["lang"]]
        if not bare:
            report.add(doc.rel, "error",
                       "нет code-блока без указания языка — канонический payload не определён")
        elif not bare[0]["code"].strip():
            report.add(doc.rel, "error", "первый code-блок (payload) пустой")
        elif len(bare[0]["code"]) > 4000:
            report.add(doc.rel, "warning",
                       f"payload длиной {len(bare[0]['code'])} символов — проверьте, "
                       "что это не дамп/скрипт целиком")

        if not ETHICS_RE.search(doc.body):
            report.add(doc.rel, "warning",
                       "нет блока об этике/разрешении на тестирование")

        if len(doc.body) < 400:
            report.add(doc.rel, "warning",
                       f"тело короче 400 символов — добавьте Explanation/Detection")


def check_links(doc, repo, report: Report, known_ids: set[str]) -> None:
    """Проверка ссылок на файлы и рёбер графа."""
    referenced: list[str] = []
    referenced += [str(p) for p in doc.meta.get_list("related_payloads")]
    lab = doc.meta.get_str("lab")
    if lab and lab.lower() not in {"null", "none", ""}:
        referenced.append(lab)
    for inc in extract_includes(doc.body):
        referenced.append(inc["path"])

    for rel in referenced:
        if rel.startswith(("http://", "https://", "mailto:")):
            continue
        target = repo.root / rel
        if not target.exists():
            report.add(doc.rel, "error", f"ссылка на несуществующий путь: `{rel}`")

    for spec in doc.meta.get_list("graph"):
        if not isinstance(spec, dict):
            report.add(doc.rel, "warning", f"элемент graph должен быть словарём: {spec!r}")
            continue
        target = str(spec.get("target") or "")
        etype = str(spec.get("type") or "related_to")
        if not target:
            report.add(doc.rel, "error", "у ребра graph нет `target`")
        if etype not in VALID_EDGE_TYPES:
            report.add(doc.rel, "error",
                       f"неизвестный тип ребра `{etype}`; допустимые: {sorted(VALID_EDGE_TYPES)}")
        if target and target not in known_ids and target not in KNOWN_CONCEPTS:
            report.add(doc.rel, "warning",
                       f"ребро ведёт на узел `{target}`, которого нет ни среди "
                       "payload'ов, ни среди известных понятий графа")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Валидация payload'ов и глав hackbook")
    parser.add_argument("--strict", action="store_true",
                        help="предупреждения считаются ошибками")
    parser.add_argument("--type", dest="ptype", default=None,
                        help="проверять только payload'ы указанного типа")
    parser.add_argument("--json", default=None, help="записать отчёт в JSON")
    parser.add_argument("--skip-chapters", action="store_true")
    args = parser.parse_args(argv)

    repo = build_index(ROOT)
    report = Report()

    payloads = repo.payloads()
    if args.ptype:
        payloads = [p for p in payloads if p.type == args.ptype]
    chapters = [] if args.skip_chapters else repo.chapters()

    # уникальность id
    ids = [p.meta.get_str("id") for p in payloads] + [c.meta.get_str("id") for c in chapters]
    ids = [i for i in ids if i]
    for duplicate, count in Counter(ids).items():
        if count > 1:
            report.add("<repo>", "error", f"дублирующийся id `{duplicate}` ({count} шт.)")

    known_ids = set(ids)
    for payload in payloads:
        known_ids.add(payload.type)
        known_ids.update(str(t) for t in payload.tags)

    for payload in payloads:
        pid = payload.meta.get_str("id")
        stem = payload.path.stem
        if not pid:
            report.add(payload.rel, "error", "нет `id` в front-matter")
        elif not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,64}", pid):
            report.add(payload.rel, "warning",
                       f"id `{pid}` не в kebab-case (допустимы a-z, 0-9, '-', '_', '.')")
        elif not pid.startswith((stem, payload.type)):
            # соглашение STYLE-GUIDE: `<тип>-<имя файла>`; не блокируем, но подсказываем
            report.add(payload.rel, "warning",
                       f"id `{pid}` не согласован с именем файла `{stem}.md` "
                       f"(соглашение: `{payload.type}-{stem}`)")
        check_front_matter(payload, report, is_payload=True)
        check_body(payload, report, is_payload=True)
        check_links(payload, repo, report, known_ids)

    for chapter in chapters:
        check_front_matter(chapter, report, is_payload=False)
        check_body(chapter, report, is_payload=False)
        check_links(chapter, repo, report, known_ids)
        if chapter.number is None:
            report.add(chapter.rel, "warning", "не удалось определить номер главы")

    problems = report.errors + (report.warnings if args.strict else [])
    print(f"Проверено: payload'ов {len(payloads)}, глав {len(chapters)}")
    print(f"Ошибок: {len(report.errors)}, предупреждений: {len(report.warnings)}")
    for issue in report.issues[:80]:
        print("  " + issue.as_str())
    if len(report.issues) > 80:
        print(f"  … и ещё {len(report.issues) - 80}")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "payloads": len(payloads), "chapters": len(chapters),
            "errors": [i.as_str() for i in report.errors],
            "warnings": [i.as_str() for i in report.warnings],
        }, ensure_ascii=False, indent=2), encoding="utf-8")

    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
