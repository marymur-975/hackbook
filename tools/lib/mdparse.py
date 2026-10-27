"""Минимальный парсер Markdown + YAML front-matter без внешних зависимостей.

PyYAML в CI может отсутствовать (минимальные образы), поэтому реализован
подмножество-парсер, покрывающий формат метаданных hackbook:

    ---
    title: "SQL Injection: Полное руководство"
    chapter: 1
    difficulty: intermediate
    tags: [sqli, web, injection]
    prerequisites: ["HTTP Basics", "SQL Fundamentals"]
    related_payloads: ["payloads/web/sqli/mysql.md"]
    lab: "labs/web-labs/sqli-lab"
    nested:
      key: value
    ---

Если PyYAML установлен — используется он (строже и быстрее).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
INLINE_LIST_RE = re.compile(r"^\[(.*)\]$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE_RE = re.compile(r"^(```|~~~)\s*([\w+-]*)\s*$")
INCLUDE_RE = re.compile(r"{{\s*include\s+\"(?P<path>[^\"]+)\"\s*(?:section=\"(?P<section>[^\"]*)\")?\s*}}")


@dataclass
class FrontMatter(dict):
    """Словарь метаданных с удобным доступом по умолчанию."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_list(self, key: str, default: list | None = None) -> list:
        value = self.get(key, default if default is not None else [])
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return list(value)
        return [value]

    def get_str(self, key: str, default: str = "") -> str:
        value = self.get(key, default)
        return default if value is None else str(value)


COMMENT_RE = re.compile(r"(?<!\S)#.*$|\s+#.*$")


def _strip_comment(text: str) -> str:
    """Убирает inline-комментарий ` # ...` из некавычечного скаляра."""
    if text and text[0] in "\"'":
        return text
    match = re.search(r"(?:^|\s)#", text)
    if not match:
        return text
    return text[:match.start()].rstrip()


def _coerce_scalar(raw: str) -> Any:
    text = _strip_comment(raw.strip())
    if not text:
        return ""
    if text.lower() in {"null", "~", "none"}:
        return None
    if text.lower() in {"true", "yes", "on"}:
        return True
    if text.lower() in {"false", "no", "off"}:
        return False
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    inline = INLINE_LIST_RE.match(text)
    if inline:
        inner = inline.group(1).strip()
        if not inner:
            return []
        return [_coerce_scalar(part) for part in _split_top_level(inner)]
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    if text.endswith("%"):
        try:
            return float(text[:-1]) / 100.0
        except ValueError:
            return text
    return text


def _split_top_level(text: str) -> list[str]:
    """Режет строку по запятым вне кавычек и скобок."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            continue
        if char in "[{(":
            depth += 1
        elif char in "]})":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def parse_yaml_subset(text: str) -> FrontMatter:
    """Парсит подмножество YAML: скаляры, inline-списки, блочные списки
    (`- key: value`), одноуровневая вложенность словарей и блочные скаляры
    (`|`, `>`, `|-`, `>-`). Этого достаточно для meta.yaml, metadata.yaml
    и front-matter глав/payload'ов."""
    data: FrontMatter = FrontMatter()
    # Стек: (indent, container, parent, key). Первый элемент списка имеет тот же
    # отступ, что и сам список, поэтому контейнеры кладём с отступом (indent - 1).
    stack: list[list[Any]] = [[-1, data, None, None]]

    def container_at(indent: int) -> Any:
        """Контейнер для элемента с данным отступом.

        Стек хранит [indent, container, parent, key, list_indent]. Для списков
        `list_indent` — отступ самого списка, поэтому последующие `- item` с тем
        же отступом возвращаются к списку, а не «залипают» в предыдущем элементе.
        """
        while len(stack) > 1:
            top = stack[-1]
            top_indent, top_container = top[0], top[1]
            if isinstance(top_container, list):
                list_indent = top[4] if len(top) > 4 else top_indent
                if indent <= list_indent:
                    stack.pop()
                    continue
                return top_container
            if indent <= top_indent:
                stack.pop()
                continue
            return top_container
        return stack[-1][1]

    def as_mapping(indent: int) -> dict:
        """Возвращает словарь-контейнер; при необходимости превращает
        placeholder-список (пустой блок `key:`) в словарь."""
        container_at(indent)
        entry = stack[-1]
        if isinstance(entry[1], dict):
            return entry[1]
        if isinstance(entry[1], list) and not entry[1]:
            mapping: dict[str, Any] = {}
            entry[1] = mapping
            if entry[2] is not None and isinstance(entry[2], dict):
                entry[2][entry[3]] = mapping
            return mapping
        return data

    lines = text.splitlines()
    i = 0
    total = len(lines)

    while i < total:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = stripped

        if line.startswith("- "):
            item_text = line[2:].strip()
            container = container_at(indent)
            if not isinstance(container, list):
                container = data.setdefault("_items", [])
            if ":" in item_text and not item_text.startswith(("[", '"', "'")):
                key, _, value = item_text.partition(":")
                mapping: dict[str, Any] = {key.strip().strip("\"'"): _coerce_scalar(value)}
                container.append(mapping)
                # continuation-ключи элемента имеют больший отступ,
                # следующий `- item` — тот же отступ, что и сам список
                list_indent = stack[-1][4] if len(stack[-1]) > 4 else indent
                stack.append([indent, mapping, container, None, list_indent])
            else:
                container.append(_coerce_scalar(item_text))
            i += 1
            continue

        if ":" not in line:
            i += 1
            continue

        key, _, value = line.partition(":")
        key = key.strip().strip("\"'")
        value = value.strip()
        container = as_mapping(indent)

        if value in {"|", ">", "|-", ">-", "|+", ">+"}:
            folded = value.startswith(">")
            keep_trailing = value.endswith("+")
            block: list[str] = []
            j = i + 1
            while j < total:
                nxt = lines[j]
                if not nxt.strip():
                    block.append("")
                    j += 1
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= indent:
                    break
                block.append(nxt.strip() if folded else nxt[indent + 2:])
                j += 1
            while block and not block[-1].strip():
                block.pop()
            if folded:
                joined = " ".join(b.strip() for b in block if b.strip())
            else:
                joined = "\n".join(block)
            container[key] = joined + ("\n" if keep_trailing else "")
            i = j
            continue

        if value == "":
            # Начало словаря или блочного списка: кладём placeholder-список
            # с отступом (indent - 1), чтобы `- item` на том же уровне
            # продолжил этот блок.
            placeholder: list[Any] = []
            container[key] = placeholder
            stack.append([indent, placeholder, container, key, indent])
        else:
            container[key] = _coerce_scalar(value)
        i += 1

    return data


def parse_front_matter(text: str) -> tuple[FrontMatter, str]:
    """Возвращает (метаданные, тело документа)."""
    match = FRONT_MATTER_RE.match(text)
    if not match:
        return FrontMatter(), text
    raw = match.group(1)
    try:  # pragma: no cover - зависит от окружения
        import yaml  # type: ignore

        loaded = yaml.safe_load(raw) or {}
        meta = FrontMatter(loaded if isinstance(loaded, dict) else {})
    except Exception:
        meta = parse_yaml_subset(raw)
    body = text[match.end():]
    return meta, body


def strip_front_matter(text: str) -> str:
    """Убирает front-matter, оставляя только тело Markdown."""
    return parse_front_matter(text)[1]


def parse_markdown(path: str | Path) -> tuple[FrontMatter, str]:
    return parse_front_matter(Path(path).read_text(encoding="utf-8", errors="replace"))


def extract_headings(body: str) -> list[tuple[int, str]]:
    """Список (уровень, текст) для всех заголовков вне code-fence."""
    headings: list[tuple[int, str]] = []
    in_fence = False
    for line in body.splitlines():
        if FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(line)
        if match:
            headings.append((len(match.group(1)), match.group(2).strip()))
    return headings


def extract_code_blocks(body: str) -> list[dict[str, str]]:
    """Извлекает fenced-блоки: [{'lang': ..., 'code': ...}]."""
    blocks: list[dict[str, str]] = []
    current: list[str] | None = None
    lang = ""
    for line in body.splitlines():
        fence = FENCE_RE.match(line.strip())
        if fence:
            if current is None:
                current = []
                lang = fence.group(2)
            else:
                blocks.append({"lang": lang, "code": "\n".join(current).strip("\n")})
                current = None
                lang = ""
            continue
        if current is not None:
            current.append(line)
    if current:
        blocks.append({"lang": lang, "code": "\n".join(current).strip("\n")})
    return blocks


def extract_includes(body: str) -> list[dict[str, str]]:
    """Находит директивы `{{ include "path" }}` из спецификации формата глав."""
    return [
        {"path": m.group("path"), "section": m.group("section") or ""}
        for m in INCLUDE_RE.finditer(body)
    ]


def iter_markdown_files(root: str | Path, *, recursive: bool = True) -> Iterator[Path]:
    root = Path(root)
    pattern = "**/*.md" if recursive else "*.md"
    for path in sorted(root.glob(pattern)):
        if any(part in {"node_modules", ".git", "build", "site"} for part in path.parts):
            continue
        yield path


def section_of(body: str, name: str) -> str:
    """Возвращает содержимое раздела `## name` (используется в include section=)."""
    lines = body.splitlines()
    out: list[str] = []
    capturing = False
    level = 0
    target = name.strip().lower()
    for line in lines:
        match = HEADING_RE.match(line)
        if match:
            heading_level = len(match.group(1))
            heading_text = match.group(2).strip().lower()
            if capturing and heading_level <= level:
                break
            if heading_text == target:
                capturing = True
                level = heading_level
                out.append(line)
                continue
        if capturing:
            out.append(line)
    return "\n".join(out).strip()


def expand_includes(body: str, root: Path, *, depth: int = 0, max_depth: int = 3) -> str:
    """Раскрывает `{{ include }}`, чтобы глава собиралась в единый документ."""
    if depth >= max_depth:
        return body

    def _replace(match: re.Match[str]) -> str:
        rel = match.group("path")
        want_section = match.group("section") or ""
        target = (root / rel).resolve()
        try:
            if target.is_dir():
                target = target / "index.md"
            _, included_body = parse_front_matter(target.read_text(encoding="utf-8", errors="replace"))
        except (OSError, UnicodeDecodeError):
            return f"> [!WARNING]\n> Не удалось подключить `{rel}` — файл не найден."
        if want_section:
            included_body = section_of(included_body, want_section) or included_body
        return expand_includes(included_body, root, depth=depth + 1, max_depth=max_depth)

    return INCLUDE_RE.sub(_replace, body)


def slugify(text: str) -> str:
    """ASCII-безопасный слаг (кириллица транслитерируется)."""
    table = {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
        "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
        "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "c",
        "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu",
        "я": "ya",
    }
    lowered = text.strip().lower()
    out = "".join(table.get(ch, ch) for ch in lowered)
    out = re.sub(r"[^\w\s-]", "", out, flags=re.UNICODE)
    out = re.sub(r"[\s_]+", "-", out)
    return re.sub(r"-+", "-", out).strip("-") or "untitled"


def words(body: str) -> Iterable[str]:
    return re.findall(r"[A-Za-zА-Яа-яЁё0-9_./-]+", body)
