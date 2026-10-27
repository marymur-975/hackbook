#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Генератор графа знаний hackbook.

Источники данных (всё из Markdown-метаданных — вручную граф не правится):
  * `payloads/**/*.md`      -> узлы payload'ов + рёбра из front-matter `graph:`
  * `book/src/*/chapter.md` -> узлы глав + рёбра «глава -> payload/лаба»
  * `labs/**/docker-compose*` -> узлы лабораторий
  * `wordlists/metadata.yaml`  -> узлы словарей

Выход:
  * payloads/graph/graph.json  — данные для визуализации и для поиска по книге
  * payloads/graph/index.html  — интерактивная карта (D3 v7 с CDN + встроенный
                                 offline-рендер, если CDN недоступен)

Примеры:
    python tools/graph-generator.py
    python tools/graph-generator.py --pretty --min-difficulty 2
    python tools/graph-generator.py --check   # только валидация связей
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.repo import DIFFICULTY_SCALE, build_index  # noqa: E402

ROOT = HERE.parent
GRAPH_DIR = ROOT / "payloads" / "graph"
TEMPLATE = HERE / "templates" / "graph.html"

# Метки «понятийных» узлов, которые упоминаются в payload'ах, но не являются файлами.
CONCEPT_LABELS = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "ssrf": "Server-Side Request Forgery",
    "lfi-rfi": "LFI / RFI",
    "xxe": "XML External Entity",
    "cmdi": "Command Injection",
    "ssti": "Server-Side Template Injection",
    "auth-bypass": "Обход аутентификации",
    "headers": "HTTP-заголовки",
    "rce": "Выполнение кода (RCE)",
    "privilege-escalation": "Эскалация привилегий",
    "data-exfiltration": "Эксфильтрация данных",
    "info-disclosure": "Раскрытие информации",
    "waf-bypass": "Обход WAF/фильтров",
    "oob": "Out-of-Band каналы",
    "enumeration": "Перечисление (recon)",
    "bruteforce": "Перебор учётных данных",
    "default-credentials": "Учётные данные по умолчанию",
    "credential-access": "Доступ к учётным данным",
    "session-hijacking": "Перехват сессии",
    "cache-poisoning": "Отравление кеша",
    "open-redirect": "Открытый редирект",
    "http-request-smuggling": "HTTP request smuggling",
    "admin-panel": "Административная панель",
    "file-upload": "Загрузка файлов",
    "container-escape": "Выход из контейнера",
    "dos": "Отказ в обслуживании",
    "fingerprinting": "Определение стека",
    "data-tampering": "Подмена данных",
    "client-side": "Клиентская сторона",
    "jwt": "JWT / токены",
    "csp": "Content-Security-Policy",
    "network": "Сетевые сервисы",
    "active-directory": "Active Directory",
    "cloud": "Облачные платформы",
    "web": "Web Security",
}

EDGE_LABELS = {
    "leads_to": "ведёт к",
    "instance_of": "пример",
    "technique_of": "техника",
    "related_to": "связано с",
    "covered_in": "разобрано в",
    "practiced_in": "практика в",
    "uses": "использует",
    "category_of": "категория",
    "requires": "требует",
}

CATEGORY_OF_TYPE = {
    "sqli": "web", "xss": "web", "ssrf": "web", "lfi": "web", "rfi": "web",
    "xxe": "web", "cmdi": "web", "ssti": "web", "auth-bypass": "web", "header": "web",
    "network": "network", "cloud": "cloud", "ad": "active-directory",
}


def difficulty_rank(value) -> int:
    if isinstance(value, int):
        return max(1, min(4, value))
    return DIFFICULTY_SCALE.get(str(value or "").lower(), 2)


def collect(repo, *, min_difficulty: int = 1) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def add_node(node_id: str, **fields) -> dict:
        node = nodes.setdefault(node_id, {"id": node_id})
        for key, value in fields.items():
            if value in (None, "", [], {}):
                continue
            if key == "tags":
                merged = set(node.get("tags", [])) | {str(t) for t in value}
                node["tags"] = sorted(merged)
            else:
                node.setdefault(key, value)
        return node

    def add_edge(source: str, target: str, etype: str, description: str = "") -> None:
        if not source or not target or source == target:
            return
        key = (source, target, etype)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edge = {"source": source, "target": target, "type": etype}
        if description:
            edge["description"] = description
        edges.append(edge)

    payloads = repo.payloads()

    # карта «любая форма ссылки -> канонический id payload'а»
    alias: dict[str, str] = {}
    for payload in payloads:
        alias[payload.id] = payload.id
        alias[Path(payload.rel).stem] = payload.id
        alias[payload.rel] = payload.id
        alias[Path(payload.rel).name] = payload.id
    # имена payload-файлов, упомянутые в главах без каталога
    for payload in payloads:
        alias.setdefault(Path(payload.path).stem, payload.id)

    # ── payload'ы и их понятия ────────────────────────────────────────
    per_type: dict[str, list] = defaultdict(list)
    for payload in payloads:
        rank = difficulty_rank(payload.difficulty)
        if rank < min_difficulty:
            continue
        pid = payload.id
        per_type[payload.type].append(payload)
        add_node(
            pid,
            label=payload.meta.get_str("title") or payload.title,
            kind="payload",
            category=payload.category,
            ptype=payload.type,
            target=payload.target,
            difficulty=rank,
            difficulty_label=payload.difficulty,
            bypass=payload.meta.get_str("bypass", "none"),
            risk=payload.meta.get_str("risk", "medium"),
            tags=payload.tags,
            payloads_count=1,
            path=payload.rel,
            cwe=payload.meta.get_str("cwe") or None,
            success_rate=payload.meta.get("success_rate"),
            lab=payload.meta.get_str("lab") or None,
        )

        for edge_spec in payload.meta.get_list("graph"):
            if isinstance(edge_spec, dict):
                target = str(edge_spec.get("target") or "").strip()
                etype = str(edge_spec.get("type") or "related_to").strip()
                description = str(edge_spec.get("description") or "").strip()
                if target:
                    target = alias.get(target, target)
                    add_edge(pid, target, etype, description)

        # неявная связь payload -> техника (по типу)
        add_edge(pid, payload.type, "instance_of")

    # ── узлы-понятия ──────────────────────────────────────────────────
    referenced: set[str] = {e["target"] for e in edges} | {e["source"] for e in edges}
    for node_id in sorted(referenced):
        if node_id in nodes:
            continue
        members = per_type.get(node_id, [])
        add_node(
            node_id,
            label=CONCEPT_LABELS.get(node_id, node_id.replace("-", " ").title()),
            kind="technique" if members or node_id in CATEGORY_OF_TYPE else "concept",
            category=CATEGORY_OF_TYPE.get(node_id, "general"),
            payloads_count=len(members),
            difficulty=max((difficulty_rank(p.difficulty) for p in members), default=2),
            tags=sorted({t for p in members for t in p.tags}),
        )

    # ── главы ─────────────────────────────────────────────────────────
    for chapter in repo.chapters():
        cid = f"chapter-{chapter.slug}"
        add_node(
            cid,
            label=chapter.meta.get_str("title") or chapter.title,
            kind="chapter",
            category=chapter.meta.get_str("category", "general"),
            difficulty=difficulty_rank(chapter.meta.get_str("difficulty")),
            tags=chapter.meta.get_list("tags"),
            path=chapter.rel,
            chapter_number=chapter.number,
            prerequisites=chapter.prerequisites,
        )
        for prereq in chapter.prerequisites:
            add_edge(cid, prereq, "requires", "необходимые знания")
        for rel in chapter.related_payloads:
            target_id = alias.get(rel) or alias.get(Path(rel).stem) or Path(rel).stem
            add_edge(cid, target_id, "covered_in")
            if target_id not in nodes:
                add_node(target_id, label=target_id, kind="payload", category="web")
        if chapter.lab:
            lab_id = Path(chapter.lab).name
            add_edge(cid, lab_id, "practiced_in")
            add_node(lab_id, label=lab_id, kind="lab", category="lab", path=chapter.lab)
        for key in ("related_nodes", "graph"):
            for spec in chapter.meta.get_list(key):
                if isinstance(spec, dict) and spec.get("target"):
                    add_edge(cid, alias.get(str(spec["target"]), str(spec["target"])),
                             str(spec.get("type") or "related_to"),
                             str(spec.get("description") or ""))
                elif isinstance(spec, str) and spec:
                    add_edge(cid, alias.get(spec, spec), "related_to")

    # ── лаборатории и словари ─────────────────────────────────────────
    for lab in repo.labs():
        lab_id = Path(lab).name
        if lab_id in nodes:
            continue
        add_node(lab_id, label=lab_id, kind="lab", category="lab", path=lab)

    return {"nodes": list(nodes.values()), "edges": edges}


def prune(graph: dict) -> dict:
    """Убирает висячие узлы-понятия без рёбер и dangling-ссылки."""
    connected = {e["source"] for e in graph["edges"]} | {e["target"] for e in graph["edges"]}
    nodes = [n for n in graph["nodes"] if n["id"] in connected or n.get("kind") in
             ("chapter", "payload", "lab")]
    ids = {n["id"] for n in nodes}
    edges = [e for e in graph["edges"] if e["source"] in ids and e["target"] in ids]
    return {"nodes": nodes, "edges": edges}


def stats(graph: dict, repo) -> dict:
    kinds = Counter(n.get("kind", "?") for n in graph["nodes"])
    categories = Counter(n.get("category", "?") for n in graph["nodes"])
    types = Counter(e["type"] for e in graph["edges"])
    payloads = repo.payloads()
    return {
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "generator": "tools/graph-generator.py",
        "totals": {
            "nodes": len(graph["nodes"]),
            "edges": len(graph["edges"]),
            "payloads": len(payloads),
            "chapters": len(repo.chapters()),
            "labs": len(repo.labs()),
            "wordlists": len(repo.wordlists()),
        },
        "by_kind": dict(kinds.most_common()),
        "by_category": dict(categories.most_common()),
        "payloads_by_type": dict(Counter(p.type for p in payloads).most_common()),
        "payloads_by_target": dict(Counter(p.target for p in payloads).most_common(12)),
        "edges_by_type": dict(types.most_common()),
        "labels": {"nodes": CONCEPT_LABELS, "edges": EDGE_LABELS},
    }


def render_html(graph: dict, meta: dict, out_path: Path) -> Path:
    data = {"graph": graph, "meta": meta}
    payload_json = json.dumps(data, ensure_ascii=False)
    if TEMPLATE.exists():
        template = TEMPLATE.read_text(encoding="utf-8")
    else:
        raise SystemExit(f"Не найден шаблон {TEMPLATE}")
    
    marker = "__HACKBOOK_GRAPH_DATA__"
    if marker not in template:
        raise SystemExit(f"В шаблоне {TEMPLATE} нет маркера {marker}")
    
    # --- ЗАЩИТА ОТ ПАДЕНИЯ JS ---
    # Принудительно заменяем функцию radius на безопасную версию
    bad_radius = "function radius(n) {\n          var base = KIND_R[n.kind] || 7;\n          var extra = Math.min(6, Math.log2(1 + (n.payloads_count || 0)));\n          return base + extra;\n        }"
    good_radius = """function radius(n) {
          var kind = (n && n.kind) ? String(n.kind) : "concept";
          var base = KIND_R[kind] || 7;
          var count = (n && typeof n.payloads_count === 'number') ? n.payloads_count : 0;
          var extra = Math.min(6, Math.log2(1 + count));
          return base + extra;
        }"""
    
    # Если точного совпадения нет, ищем более гибко
    if bad_radius in template:
        template = template.replace(bad_radius, good_radius)
    else:
        # Пытаемся найти любую функцию radius и заменить её
        import re
        template = re.sub(r'function radius\(n\) \{.*?\n        \}', good_radius, template, flags=re.DOTALL)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(template.replace(marker, payload_json), encoding="utf-8")
    return out_path


def check(graph: dict) -> list[str]:
    """Возвращает список проблем в связях (используется в CI)."""
    problems: list[str] = []
    ids = {n["id"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        for key in ("source", "target"):
            if edge[key] not in ids:
                problems.append(f"ребро {edge['source']} -> {edge['target']}: "
                                f"узел '{edge[key]}' отсутствует")
    dupes = [i for i, c in Counter(n["id"] for n in graph["nodes"]).items() if c > 1]
    for dupe in dupes:
        problems.append(f"дублирующийся id узла: {dupe}")
    known = set(EDGE_LABELS)
    for edge in graph["edges"]:
        if edge["type"] not in known:
            problems.append(f"неизвестный тип ребра '{edge['type']}' "
                            f"({edge['source']} -> {edge['target']})")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Генерация графа знаний hackbook")
    parser.add_argument("--out-dir", default=str(GRAPH_DIR))
    parser.add_argument("--min-difficulty", type=int, default=1, choices=[1, 2, 3, 4])
    parser.add_argument("--pretty", action="store_true", help="человекочитаемый JSON")
    parser.add_argument("--no-html", action="store_true", help="не собирать index.html")
    parser.add_argument("--check", action="store_true", help="только проверить связи")
    args = parser.parse_args(argv)

    repo = build_index(ROOT)
    graph = prune(collect(repo, min_difficulty=args.min_difficulty))
    meta = stats(graph, repo)

    problems = check(graph)
    if problems:
        print(f"Проблем в графе: {len(problems)}", file=sys.stderr)
        for problem in problems[:20]:
            print(f"  - {problem}", file=sys.stderr)
        if args.check:
            return 1

    if args.check:
        print(f"OK: узлов {len(graph['nodes'])}, рёбер {len(graph['edges'])}")
        return 0

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "graph.json"
    indent = 2 if args.pretty else None
    json_path.write_text(
        json.dumps({"meta": meta, **graph}, ensure_ascii=False, indent=indent) + "\n",
        encoding="utf-8")
    print(f"Записано {json_path.relative_to(ROOT)}: "
          f"{len(graph['nodes'])} узлов, {len(graph['edges'])} рёбер")
    print("  по типам узлов: " + ", ".join(f"{k}={v}" for k, v in meta["by_kind"].items()))

    if not args.no_html:
        html_path = render_html(graph, meta, out_dir / "index.html")
        print(f"Записано {html_path.relative_to(ROOT)} "
              f"({html_path.stat().st_size / 1024:.1f} КБ)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
