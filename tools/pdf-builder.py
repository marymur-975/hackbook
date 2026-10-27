#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сборка книги `hackbook` из Markdown-глав.

Возможности:
  * HTML-бандл (один файл, работает везде) — формат по умолчанию;
  * EPUB 3 — чистый Python (zip + XHTML), внешних зависимостей нет;
  * PDF — WeasyPrint (если установлен) либо fpdf2 как fallback.

Главы берутся из `book/src/<NN-slug>/chapter.md` (+ `meta.yaml`), директивы
`{{ include "payloads/..." }}` и `{! path !}` раскрываются автоматически,
в начало добавляется оглавление.

Примеры:
    python tools/pdf-builder.py                          # HTML-бандл в book/build/
    python tools/pdf-builder.py --format pdf             # PDF (weasyprint/fpdf2)
    python tools/pdf-builder.py --format epub            # EPUB
    python tools/pdf-builder.py --format all             # всё сразу
    python tools/pdf-builder.py --chapters 0,1,2         # только выбранные главы
"""

from __future__ import annotations

import argparse
import datetime
import html
import os
import re
import sys
import uuid
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.md2html import BASE_CSS, convert, page  # noqa: E402
from lib.mdparse import slugify  # noqa: E402
from lib.repo import build_index  # noqa: E402

ROOT = HERE.parent
DEFAULT_TITLE = "hackbook — практическая кибербезопасность"


# ──────────────────────────────────────────────────────────────── helpers
def expand_includes(body: str, root: Path, depth: int = 0, max_depth: int = 4) -> str:
    """Раскрывает `{{ include "path" }}` и mkdocs-стиль `{! path !}`."""
    if depth >= max_depth:
        return body

    pattern = re.compile(
        r"\{\{\s*include\s+\"(?P<p1>[^\"]+)\"\s*\}\}|\{!\s*(?P<p2>[^\s!][^!]*?)\s*!\}")

    def _sub(match: re.Match[str]) -> str:
        rel = (match.group("p1") or match.group("p2") or "").strip()
        if not rel:
            return match.group(0)
        target = (root / rel)
        if target.is_dir():
            target = target / "index.md"
        if not target.exists():
            return f'> **⚠ Не подключено:** `{rel}`'
        text = target.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r"^---\s*\n.*?\n---\s*\n", "", text, flags=re.DOTALL)
        return expand_includes(text, root, depth + 1, max_depth)

    return pattern.sub(_sub, body)


def chapter_html(chapter, root: Path) -> tuple[str, str, str]:
    """Возвращает (anchor, title, html) для главы."""
    number = chapter.number
    title = chapter.meta.get_str("title") or chapter.title
    if number is not None:
        title = f"{number}. {title}"
    anchor = chapter.slug or slugify(title)
    body = expand_includes(chapter.body, root)
    inner = convert(body)

    badges = []
    for key in ("difficulty", "category"):
        value = chapter.meta.get_str(key)
        if value:
            badges.append(f'<span class="badge badge-{key}">{html.escape(value)}</span>')
    tags = chapter.meta.get_list("tags")
    if tags:
        badges.append(" ".join(f"<code>#{html.escape(str(t))}</code>" for t in tags))
    meta_line = ""
    if badges:
        meta_line = '<p class="chapter-meta">' + " ".join(badges) + "</p>"

    return anchor, title, (
        f'<section class="chapter" id="{anchor}">\n'
        f'<h1>{html.escape(title)}</h1>\n{meta_line}\n{inner}\n</section>'
    )


def build_toc(entries: list[tuple[str, str]]) -> str:
    items = "\n".join(f'<li><a href="#{anchor}">{html.escape(title)}</a></li>'
                      for anchor, title in entries)
    return f'<nav class="toc"><h2>Содержание</h2><ol>\n{items}\n</ol></nav>'


def collect_chapters(repo, wanted: set[int] | None):
    chapters = []
    for chapter in repo.chapters():
        if wanted is not None and (chapter.number not in wanted):
            continue
        chapters.append(chapter)
    if not chapters:
        raise SystemExit("Не найдено ни одной главы в book/src — добавьте chapter.md")
    return chapters


# ──────────────────────────────────────────────────────────────── HTML
def render_html(chapters, repo, out_path: Path, title: str) -> Path:
    entries, sections = [], []
    for chapter in chapters:
        anchor, ctitle, chtml = chapter_html(chapter, repo.root)
        entries.append((anchor, ctitle))
        sections.append(chtml)
    toc = build_toc(entries)
    cover = (
        '<header class="cover">\n'
        f'<h1>{html.escape(title)}</h1>\n'
        f'<p class="chapter-meta">Собрано {datetime.date.today().isoformat()} · '
        f'{len(chapters)} глав(ы) · {len(repo.payloads())} payload\'ов · '
        f'{len(repo.wordlists())} словарей · {len(repo.labs())} лабораторий</p>\n'
        '<p>Материалы предназначены для обучения, лабораторных работ и тестирования '
        'систем, на которые у вас есть разрешение.</p>\n</header>'
    )
    body = "<main>\n" + cover + "\n" + toc + "\n" + "\n".join(sections) + "\n</main>"
    css = BASE_CSS + """
.cover { border-bottom:3px solid var(--accent); padding-bottom:1rem; margin-bottom:2rem; }
.badge { display:inline-block; padding:.1em .55em; border-radius:999px; font-size:.8rem;
         border:1px solid var(--border); background:#fff; margin-right:.3em; }
.badge-difficulty-beginner { background:#e6fcf5; border-color:#63e6be; }
.badge-difficulty-intermediate { background:#fff9db; border-color:#ffe066; }
.badge-difficulty-advanced { background:#fff0f6; border-color:#ffa8a8; }
.chapter { break-before: page; }
"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page(title, body, extra_css=css), encoding="utf-8")
    return out_path


# ──────────────────────────────────────────────────────────────── EPUB
def render_epub(chapters, repo, out_path: Path, title: str) -> Path:
    entries, sections = [], []
    for chapter in chapters:
        anchor, ctitle, chtml = chapter_html(chapter, repo.root)
        entries.append((anchor, ctitle))
        sections.append((anchor, ctitle, chtml))

    book_id = "urn:uuid:" + str(uuid.uuid4())
    today = datetime.date.today().isoformat()
    nav_items = "\n".join(
        f'<li><a href="chap-{i:02d}.xhtml">{html.escape(entry[1])}</a></li>'
        for i, entry in enumerate(sections))

    opf_manifest = ['<item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>',
                    '<item id="css" href="style.css" media-type="text/css"/>']
    opf_spine = ['<itemref idref="nav"/>']
    for i in range(len(sections)):
        opf_manifest.append(
            f'<item id="chap-{i:02d}" href="chap-{i:02d}.xhtml" media-type="application/xhtml+xml"/>')
        opf_spine.append(f'<itemref idref="chap-{i:02d}"/>')

    opf = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="book-id" xml:lang="ru">\n'
        '  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
        f'    <dc:identifier id="book-id">{book_id}</dc:identifier>\n'
        f'    <dc:title>{html.escape(title)}</dc:title>\n'
        '    <dc:language>ru</dc:language>\n'
        '    <dc:creator>hackbook contributors</dc:creator>\n'
        f'    <meta property="dcterms:modified">{today}T00:00:00Z</meta>\n'
        '  </metadata>\n  <manifest>\n    ' + "\n    ".join(opf_manifest) +
        '\n  </manifest>\n  <spine>\n    ' + "\n    ".join(opf_spine) + '\n  </spine>\n</package>\n')

    nav = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<!DOCTYPE html>\n<html xmlns="http://www.w3.org/1999/xhtml" '
        'xmlns:epub="http://www.idpf.org/2007/ops" lang="ru">\n<head><title>Содержание</title>'
        '<link rel="stylesheet" href="style.css"/></head>\n<body>\n'
        f'<nav epub:type="toc" id="toc"><h1>Содержание</h1><ol>\n{nav_items}\n</ol></nav>\n'
        '</body>\n</html>\n')

    container = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">\n'
        '  <rootfiles>\n    <rootfile full-path="OEBPS/content.opf" '
        'media-type="application/oebps-package+xml"/>\n  </rootfiles>\n</container>\n')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", "application/epub+zip", compress_type=zipfile.ZIP_STORED)
        zf.writestr("META-INF/container.xml", container)
        zf.writestr("OEBPS/content.opf", opf)
        zf.writestr("OEBPS/nav.xhtml", nav)
        zf.writestr("OEBPS/style.css", BASE_CSS)
        for i, (_, ctitle, chtml) in enumerate(sections):
            doc = ('<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE html>\n'
                   '<html xmlns="http://www.w3.org/1999/xhtml" lang="ru">\n<head>'
                   f'<title>{html.escape(ctitle)}</title><link rel="stylesheet" href="style.css"/></head>\n'
                   f'<body>\n{chtml}\n</body>\n</html>\n')
            zf.writestr(f"OEBPS/chap-{i:02d}.xhtml", doc)
    return out_path


# ──────────────────────────────────────────────────────────────── PDF
FONT_CANDIDATES = [
    "DejaVuSans.ttf", "DejaVuSansCondensed.ttf", "LiberationSans-Regular.ttf",
    "NotoSans-Regular.ttf", "FreeSans.ttf", "Verdana.ttf", "Arial.ttf",
]
FONT_BOLD_CANDIDATES = [
    "DejaVuSans-Bold.ttf", "DejaVuSansCondensed-Bold.ttf", "LiberationSans-Bold.ttf",
    "NotoSans-Bold.ttf", "FreeSansBold.ttf", "Verdana Bold.ttf", "Arial Bold.ttf",
]
FONT_MONO_CANDIDATES = [
    "DejaVuSansMono.ttf", "LiberationMono-Regular.ttf", "NotoSansMono-Regular.ttf",
    "FreeMono.ttf", "Courier New.ttf",
]


def find_font(names: list[str]) -> str | None:
    roots = ["/usr/share/fonts", "/usr/local/share/fonts", str(Path.home() / ".fonts"),
             "/Library/Fonts", "C:/Windows/Fonts", "/usr/share/fonts/truetype"]
    # шрифты, которые лежат внутри python-пакетов (matplotlib и т.п.)
    try:
        import matplotlib  # type: ignore

        roots.append(str(Path(matplotlib.get_data_path()) / "fonts" / "ttf"))
    except Exception:
        pass
    try:
        import site

        for sp in site.getsitepackages():
            cand = Path(sp)
            if cand.exists():
                roots.append(str(cand))
    except Exception:
        pass

    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        for name in names:
            try:
                for path in base.rglob(name):
                    return str(path)
            except OSError:
                continue
    return None


def render_pdf_weasyprint(html_path: Path, out_path: Path) -> bool:
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:
        return False
    HTML(filename=str(html_path)).write_pdf(str(out_path))
    return True


def render_pdf_fpdf(chapters, repo, out_path: Path, title: str) -> bool:
    """PDF без WeasyPrint: простой текстовый рендер Markdown через fpdf2."""
    try:
        from fpdf import FPDF  # type: ignore
    except Exception:
        return False

    regular = find_font(FONT_CANDIDATES)
    bold = find_font(FONT_BOLD_CANDIDATES) or regular
    mono = find_font(FONT_MONO_CANDIDATES) or regular
    if not regular:
        print("  [pdf] не найден Unicode TTF-шрифт — fpdf2 не может отрисовать кириллицу.\n"
              "        Установите шрифты (apt install fonts-dejavu-core) или WeasyPrint.",
              file=sys.stderr)
        return False

    pdf = FPDF(format="A4", unit="mm")
    pdf.set_margins(18, 18, 18)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_font("body", "", regular)
    if bold != regular:
        pdf.add_font("body", "B", bold)
    pdf.add_font("mono", "", mono)
    pdf.add_page()

    content_w = pdf.w - pdf.l_margin - pdf.r_margin

    def text(value: str, height: float, **kwargs) -> None:
        """multi_cell с гарантированной шириной и возвратом курсора на левый край."""
        value = value or " "
        try:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(kwargs.pop("w", content_w), height, value, **kwargs)
        except Exception as exc:  # одна «сломанная» строка не должна ронять сборку
            print(f"  [pdf] пропущен фрагмент ({exc.__class__.__name__}): "
                  f"{value[:60]!r}", file=sys.stderr)
            pdf.set_x(pdf.l_margin)

    pdf.set_font("body", "B", 22)
    text(title, 11)
    pdf.set_font("body", "", 10)
    pdf.set_text_color(110, 110, 110)
    text(f"Собрано {datetime.date.today().isoformat()} · "
                         f"{len(chapters)} глав(ы) · {len(repo.payloads())} payload'ов", 6)
    pdf.set_text_color(0, 0, 0)

    def clean(value: str) -> str:
        value = re.sub(r"`([^`]*)`", r"\1", value)
        value = re.sub(r"\*\*(.+?)\*\*", r"\1", value)
        value = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r"\1", value)
        value = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", value)
        return value

    # оглавление
    pdf.ln(4)
    pdf.set_font("body", "B", 14)
    text("Содержание", 8)
    pdf.set_font("body", "", 11)
    for chapter in chapters:
        number = chapter.number
        ctitle = chapter.meta.get_str("title") or chapter.title
        label = f"{number}. {ctitle}" if number is not None else ctitle
        text("  " + clean(label), 6.5)

    for chapter in chapters:
        _, ctitle, _html = chapter_html(chapter, repo.root)
        pdf.add_page()
        pdf.set_font("body", "B", 17)
        text(clean(ctitle), 9)
        pdf.ln(1)

        body = expand_includes(chapter.body, repo.root)
        in_fence = False
        fence_lang = ""
        buffer: list[str] = []
        for raw in body.split("\n"):
            fence = re.match(r"^(```|~~~)\s*([\w+#.-]*)\s*$", raw.strip())
            if fence:
                if in_fence:
                    pdf.set_font("mono", "", 8.4)
                    pdf.set_fill_color(244, 246, 249)
                    text("\n".join(buffer) or " ", 4.4, border=0, fill=True)
                    pdf.ln(1.2)
                    buffer = []
                    in_fence = False
                else:
                    in_fence = True
                    fence_lang = fence.group(2)
                continue
            if in_fence:
                buffer.append(raw)
                continue
            if not raw.strip():
                pdf.ln(1.6)
                continue
            heading = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", raw)
            if heading:
                level = len(heading.group(1))
                sizes = {1: 17, 2: 14, 3: 12.5, 4: 11.5, 5: 11, 6: 10.5}
                pdf.ln(2 if level > 1 else 3)
                pdf.set_font("body", "B", sizes.get(level, 11))
                size = sizes.get(level, 11)
                text(clean(heading.group(2)), size * 0.52)
                continue
            if raw.startswith("|"):
                pdf.set_font("mono", "", 8.6)
                text(raw, 4.6)
                continue
            if raw.startswith(">") or raw.startswith("!!!"):
                pdf.set_font("body", "", 10)
                pdf.set_text_color(90, 90, 90)
                text("   " + clean(raw.lstrip(">! ")), 5.6)
                pdf.set_text_color(0, 0, 0)
                continue
            bullet = re.match(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$", raw)
            if bullet:
                indent = len(bullet.group(1)) // 2
                marker = "•" if bullet.group(2) in "-*+" else bullet.group(2)
                pdf.set_font("body", "", 10.5)
                text("  " * indent + f"{marker} " + clean(bullet.group(3)), 5.6)
                continue
            pdf.set_font("body", "", 10.5)
            text(clean(raw), 5.6)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out_path))
    return True


def render_pdf(chapters, repo, html_path: Path, out_path: Path, title: str) -> Path:
    engine = "weasyprint"
    try:
        ok = render_pdf_weasyprint(html_path, out_path)
    except Exception as exc:  # noqa: BLE001
        print(f"  [pdf] WeasyPrint не справился ({exc}) — переключаюсь на fpdf2", file=sys.stderr)
        ok = False
    if not ok:
        engine = "fpdf2"
        if not render_pdf_fpdf(chapters, repo, out_path, title):
            raise SystemExit("Не удалось собрать PDF: нет ни WeasyPrint, ни fpdf2 со шрифтами.")
    print(f"  [pdf] движок: {engine}")
    return out_path


# ──────────────────────────────────────────────────────────────── main
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Сборка книги hackbook (HTML/PDF/EPUB)")
    parser.add_argument("--format", choices=["html", "pdf", "epub", "all"], default="all")
    parser.add_argument("--src", default=None, help="каталог глав (по умолчанию book/src)")
    parser.add_argument("--out-dir", default=None, help="каталог вывода (по умолчанию book/build)")
    parser.add_argument("--title", default=DEFAULT_TITLE)
    parser.add_argument("--chapters", default=None,
                        help="список номеров глав через запятую, например 0,1,2")
    parser.add_argument("--check", action="store_true",
                        help="не собирать, только проверить, что главы находятся и парсятся")
    args = parser.parse_args(argv)

    repo = build_index(ROOT)
    wanted = None
    if args.chapters:
        wanted = {int(x) for x in re.split(r"[,\s]+", args.chapters.strip()) if x.strip()}

    chapters = collect_chapters(repo, wanted)
    out_dir = Path(args.out_dir) if args.out_dir else ROOT / "book" / "build"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Глав: {len(chapters)} | payload'ов: {len(repo.payloads())} | "
          f"словарей: {len(repo.wordlists())} | лабораторий: {len(repo.labs())}")
    for chapter in chapters:
        print(f"  · {chapter.number if chapter.number is not None else '-'}: "
              f"{chapter.meta.get_str('title') or chapter.title}  ({chapter.rel})")

    if args.check:
        return 0

    stem = "hackbook"
    html_path = out_dir / f"{stem}.html"
    formats = ["html", "pdf", "epub"] if args.format == "all" else [args.format]

    produced: list[Path] = []
    if "html" in formats or "pdf" in formats:
        produced.append(render_html(chapters, repo, html_path, args.title))
    if "epub" in formats:
        produced.append(render_epub(chapters, repo, out_dir / f"{stem}.epub", args.title))
    if "pdf" in formats:
        produced.append(render_pdf(chapters, repo, html_path, out_dir / f"{stem}.pdf", args.title))

    print("Готово:")
    for path in produced:
        size = path.stat().st_size
        print(f"  {path.relative_to(ROOT)}  ({size / 1024:.1f} КБ)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
