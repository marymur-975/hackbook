"""Модель репозитория hackbook: главы, payload'ы, словари и связи между ними.

Единый источник правды для `graph-generator.py`, `pdf-builder.py`,
`validate-payloads` (CI) и поиска по книге.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .mdparse import (
    FrontMatter,
    extract_headings,
    extract_includes,
    iter_markdown_files,
    parse_front_matter,
    parse_yaml_subset,
    slugify,
)

CATEGORIES = {
    "web": "Web Security",
    "network": "Network",
    "active-directory": "Active Directory",
    "cloud": "Cloud",
    "privilege-escalation": "Privilege Escalation",
    "general": "General",
}

DIFFICULTY_SCALE = {"beginner": 1, "easy": 1, "intermediate": 2, "medium": 2,
                    "advanced": 3, "hard": 3, "expert": 4}


def load_yaml_sidecar(path) -> FrontMatter:
    """Читает `meta.yaml`/`metadata.yaml` рядом с главой или словарём."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    try:  # pragma: no cover - зависит от наличия PyYAML
        import yaml  # type: ignore

        loaded = yaml.safe_load(text) or {}
        return FrontMatter(loaded if isinstance(loaded, dict) else {})
    except Exception:
        return parse_yaml_subset(text)


@dataclass
class Doc:
    path: Path            # абсолютный путь
    rel: str              # путь от корня репозитория (posix)
    meta: FrontMatter = field(default_factory=FrontMatter)
    body: str = ""

    @property
    def id(self) -> str:
        explicit = self.meta.get("id")
        if explicit:
            return str(explicit)
        return slugify(Path(self.rel).stem)

    @property
    def title(self) -> str:
        for level, text in extract_headings(self.body):
            if level == 1:
                return text
        return str(self.meta.get_str("title") or Path(self.rel).stem)


@dataclass
class Payload(Doc):
    """Файл из `payloads/**` — единый формат с type/target/bypass/tested_on."""

    @property
    def type(self) -> str:
        return self.meta.get_str("type") or Path(self.rel).parent.name

    @property
    def target(self) -> str:
        return self.meta.get_str("target", "generic")

    @property
    def category(self) -> str:
        parts = Path(self.rel).parts
        return parts[1] if len(parts) > 2 else "general"

    @property
    def difficulty(self) -> str:
        return self.meta.get_str("difficulty", "intermediate")

    @property
    def difficulty_rank(self) -> int:
        return DIFFICULTY_SCALE.get(self.difficulty.lower(), 2)

    @property
    def tags(self) -> list[str]:
        return [str(t) for t in self.meta.get_list("tags")]

    @property
    def code(self) -> str:
        """Первый code-блок без языка — канонический текст payload'а."""
        from .mdparse import extract_code_blocks

        for block in extract_code_blocks(self.body):
            if not block["lang"]:
                return block["code"]
        blocks = extract_code_blocks(self.body)
        return blocks[0]["code"] if blocks else ""


@dataclass
class Chapter(Doc):
    """Глава книги: `book/src/<NN-slug>/chapter.md` + `meta.yaml`."""

    @property
    def number(self) -> int | None:
        value = self.meta.get("chapter")
        try:
            return int(value)
        except (TypeError, ValueError):
            prefix = Path(self.rel).parts[2] if len(Path(self.rel).parts) > 2 else ""
            digits = "".join(ch for ch in prefix.split("-")[0] if ch.isdigit())
            return int(digits) if digits else None

    @property
    def slug(self) -> str:
        parts = Path(self.rel).parts
        return parts[2] if len(parts) > 3 else Path(self.rel).parent.name

    @property
    def related_payloads(self) -> list[str]:
        explicit = [str(p) for p in self.meta.get_list("related_payloads")]
        explicit += [inc["path"] for inc in extract_includes(self.body)]
        return explicit

    @property
    def lab(self) -> str:
        return self.meta.get_str("lab")

    @property
    def prerequisites(self) -> list[str]:
        return [str(p) for p in self.meta.get_list("prerequisites")]


@dataclass
class Wordlist(Doc):
    pass


@dataclass
class GraphEdge:
    source: str
    target: str
    type: str = "related_to"
    description: str = ""

    def as_dict(self) -> dict:
        data = {"source": self.source, "target": self.target, "type": self.type}
        if self.description:
            data["description"] = self.description
        return data


class Repo:
    """Индекс всего репозитория."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    # -- базовые пути -------------------------------------------------
    @property
    def book_src(self) -> Path:
        return self.root / "book" / "src"

    @property
    def payloads_dir(self) -> Path:
        return self.root / "payloads"

    @property
    def wordlists_dir(self) -> Path:
        return self.root / "wordlists"

    @property
    def labs_dir(self) -> Path:
        return self.root / "labs"

    def rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    @staticmethod
    def _read(path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    # -- загрузка -----------------------------------------------------
    def load_doc(self, path: Path) -> Doc:
        meta, body = parse_front_matter(self._read(path))
        return Doc(path=path, rel=self.rel(path), meta=meta, body=body)

    def chapters(self) -> list[Chapter]:
        out: list[Chapter] = []
        for chapter_dir in sorted(p for p in self.book_src.glob("*") if p.is_dir()):
            main = chapter_dir / "chapter.md"
            if not main.exists():
                candidates = sorted(chapter_dir.glob("*.md"))
                if not candidates:
                    continue
                main = candidates[0]
            meta, body = parse_front_matter(self._read(main))
            sidecar = chapter_dir / "meta.yaml"
            if sidecar.exists():
                side_meta = load_yaml_sidecar(sidecar)
                merged = FrontMatter(side_meta)
                merged.update(meta)  # front-matter главы приоритетнее meta.yaml
                meta = merged
            out.append(Chapter(path=main, rel=self.rel(main), meta=meta, body=body))
        out.sort(key=lambda c: (c.number if c.number is not None else 999, c.rel))
        return out

    def payloads(self, *, include_templates: bool = False) -> list[Payload]:
        out: list[Payload] = []
        for path in iter_markdown_files(self.payloads_dir):
            rel = self.rel(path)
            if not include_templates and "/templates/" in f"/{rel}":
                continue
            if "/graph/" in f"/{rel}":
                continue
            if path.name.upper() in {"README.MD"}:
                continue
            meta, body = parse_front_matter(self._read(path))
            out.append(Payload(path=path, rel=rel, meta=meta, body=body))
        return out

    def wordlists(self) -> list[Path]:
        if not self.wordlists_dir.exists():
            return []
        return sorted(
            p for p in self.wordlists_dir.rglob("*.txt")
            if not p.name.startswith(".")
        )

    def labs(self) -> list[str]:
        """Каталоги лабораторий.

        Лаборатория = каталог с артефактом запуска (docker-compose*, Dockerfile,
        app.py или tests.yaml). Оркестратор `labs/setup` лабораторией не
        считается: в графе он даёт лишний узел.
        """
        if not self.labs_dir.exists():
            return []
        markers = ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml",
                   "compose*.yaml", "Dockerfile", "app.py", "tests.yaml", "Vagrantfile")
        found: set[str] = set()
        for path in self.labs_dir.rglob("*"):
            if not path.is_file():
                continue
            if not any(path.match(pattern) for pattern in markers):
                continue
            parts = self.rel(path).split("/")
            # labs/<категория>/<лаба>/<файл> — узел графа это каталог лабы
            if len(parts) < 4:
                continue
            candidate = "/".join(parts[:3])
            if candidate in {"labs/setup", "labs/db-init"}:
                continue
            found.add(candidate)
        return sorted(found)

    def all_docs(self) -> list[Doc]:
        docs: list[Doc] = list(self.chapters()) + list(self.payloads())
        docs += [self.load_doc(p) for p in iter_markdown_files(self.root / "docs")]
        return docs


def build_index(root: str | Path) -> Repo:
    """Точка входа: `repo = build_index(Path.cwd())`."""
    return Repo(root)
