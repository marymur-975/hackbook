"""Общая библиотека утилит hackbook.

Все инструменты проекта (`pdf-builder.py`, `graph-generator.py`,
`wordlist-validator.py`, `link-checker.py`, `payload-tester.sh`) используют
один и тот же парсер Markdown + YAML front-matter, чтобы метаданные нигде
не разъезжались.
"""

from .mdparse import (
    FrontMatter,
    parse_markdown,
    iter_markdown_files,
    strip_front_matter,
    extract_headings,
    extract_code_blocks,
    extract_includes,
)
from .repo import Repo, Payload, Chapter, Wordlist, GraphEdge, build_index

__all__ = [
    "FrontMatter",
    "parse_markdown",
    "iter_markdown_files",
    "strip_front_matter",
    "extract_headings",
    "extract_code_blocks",
    "extract_includes",
    "Repo",
    "Payload",
    "Chapter",
    "Wordlist",
    "GraphEdge",
    "build_index",
]
