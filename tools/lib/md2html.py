"""Конвертер Markdown -> HTML для сборки книги.

Мини-реализация без внешних зависимостей, покрывающая подмножество, которое
используется в `hackbook`: заголовки, fenced-код, таблицы, списки, цитаты,
admonition-блоки Material (`!!! type "Title"`), инлайн-разметка и ссылки.

Если в окружении есть пакет `markdown` (+ `pymdown-extensions`) — `pdf-builder.py`
может использовать его вместо этого модуля: формат совместим.
"""

from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass

from .mdparse import slugify

FENCE_RE = re.compile(r"^(```|~~~)\s*([\w+#.-]*)\s*$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
HR_RE = re.compile(r"^\s{0,3}([-*_])(\s*\1){2,}\s*$")
UL_RE = re.compile(r"^(\s*)[-*+]\s+(.*)$")
OL_RE = re.compile(r"^(\s*)(\d+)[.)]\s+(.*)$")
BLOCKQUOTE_RE = re.compile(r"^\s{0,3}>\s?(.*)$")
ADMONITION_RE = re.compile(r"^!!!\s+([\w+-]+)(?:\s+\"(.*?)\")?\s*$")
TABLE_SEP_RE = re.compile(r"^\s*\|?[\s:|-]+\|[\s:|-]*$")
INCLUDE_HINT_RE = re.compile(r"^\s*\{\{\s*include\s+\"(?P<path>[^\"]+)\"[^}]*\}\}\s*$")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

INLINE_CODE_RE = re.compile(r"`([^`]+)`")
BOLD_RE = re.compile(r"\*\*(?!\s)(.+?)(?<!\s)\*\*")
ITALIC_RE = re.compile(r"(?<!\*)\*(?!\s)([^*]+?)(?<!\s)\*(?!\*)")
LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)\s]+)(?:\s+\"([^\"]*)\")?\)")
IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)(?:\s+\"([^\"]*)\")?\)")
AUTOLINK_RE = re.compile(r"(?<![\w\"'=/])((?:https?://)[^\s<>\"')]+)")


def escape(text: str) -> str:
    return _html.escape(text, quote=False)


def _image_sub(match: re.Match[str]) -> str:
    title = f' title="{match.group(3)}"' if match.group(3) else ""
    return f'<img src="{match.group(2)}" alt="{match.group(1)}"{title}">'


def _link_sub(match: re.Match[str]) -> str:
    title = f' title="{match.group(3)}"' if match.group(3) else ""
    return f'<a href="{match.group(2)}"{title}>{match.group(1)}</a>'


def inline(text: str) -> str:
    """Инлайн-разметка. Работает по «защищённым» placeholder'ам кода,
    чтобы содержимое `code` не экранировалось дважды."""
    stash: list[str] = []

    def _protect(match: re.Match[str]) -> str:
        stash.append(f"<code>{escape(match.group(1))}</code>")
        return f"\x00{len(stash) - 1}\x00"

    text = INLINE_CODE_RE.sub(_protect, text)
    text = escape(text)
    text = IMAGE_RE.sub(_image_sub, text)
    text = LINK_RE.sub(_link_sub, text)
    text = AUTOLINK_RE.sub(lambda m: f'<a href="{m.group(0)}">{m.group(0)}</a>', text)
    text = BOLD_RE.sub(r"<strong>\1</strong>", text)
    text = ITALIC_RE.sub(r"<em>\1</em>", text)
    text = re.sub(r"~~(.+?)~~", r"<del>\1</del>", text)
    text = re.sub(r"\x00(\d+)\x00", lambda m: stash[int(m.group(1))], text)
    return text


def split_row(line: str) -> list[str]:
    """Режет строку таблицы на ячейки с учётом экранированного `|`."""
    cells: list[str] = []
    current: list[str] = []
    in_code = False
    i = 0
    while i < len(line):
        char = line[i]
        if char == "`":
            in_code = not in_code
        if char == "\\" and i + 1 < len(line) and line[i + 1] == "|" and not in_code:
            current.append("|")
            i += 2
            continue
        if char == "|" and not in_code:
            cells.append("".join(current))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    cells.append("".join(current))
    if cells and not cells[0].strip():
        cells.pop(0)
    if cells and not cells[-1].strip():
        cells.pop()
    return [c.strip() for c in cells]


def table_alignment(sep_line: str) -> list[str]:
    aligns: list[str] = []
    for cell in split_row(sep_line):
        left = cell.startswith(":")
        right = cell.endswith(":")
        aligns.append("center" if left and right else "left" if left else "right" if right else "")
    return aligns


@dataclass
class ConvertOptions:
    add_anchors: bool = True
    admonitions: bool = True
    highlight_theme: str = "material"


def _render_list(items: list[tuple[int, str, str]], start_idx: int) -> tuple[str, int]:
    """Рекурсивный рендер списка. items: (indent, marker, text)."""
    if start_idx >= len(items):
        return "", start_idx
    indent, marker, _ = items[start_idx]
    ordered = marker != "-"
    tag = "ol" if ordered else "ul"
    out = [f"<{tag}>"]
    i = start_idx
    while i < len(items):
        cur_indent, cur_marker, text = items[i]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            nested, i = _render_list(items, i)
            if out[-1].endswith("</li>"):
                out[-1] = out[-1][:-5] + nested + "</li>"
            else:
                out.append(nested)
            continue
        if (cur_marker != "-") != ordered:
            break
        out.append(f"<li>{inline(text)}</li>")
        i += 1
    out.append(f"</{tag}>")
    return "\n".join(out), i


def convert(md: str, options: ConvertOptions | None = None) -> str:
    """Markdown -> HTML-фрагмент (без <html>/<body>)."""
    options = options or ConvertOptions()
    md = HTML_COMMENT_RE.sub("", md)
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]

        # fenced code
        fence = FENCE_RE.match(line.strip())
        if fence:
            closer = fence.group(1)
            lang = fence.group(2)
            code: list[str] = []
            i += 1
            while i < n and not lines[i].strip().startswith(closer):
                code.append(lines[i])
                i += 1
            i += 1  # закрывающая линия
            cls = f' class="language-{lang}"' if lang else ""
            data = f' data-lang="{lang}"' if lang else ""
            out.append(f"<pre><code{cls}{data}>{escape(chr(10).join(code))}</code></pre>")
            continue

        # include-директива (если не была раскрыта до конвертации)
        hint = INCLUDE_HINT_RE.match(line)
        if hint:
            out.append(
                f'<div class="include-missing"><p>⚠ Не подключено: <code>{escape(hint.group("path"))}</code></p></div>')
            i += 1
            continue

        # admonition
        admonition = ADMONITION_RE.match(line) if options.admonitions else None
        if admonition:
            kind = admonition.group(1)
            title = admonition.group(2) or kind.capitalize()
            body: list[str] = []
            i += 1
            while i < n and (lines[i].startswith("    ") or not lines[i].strip()):
                body.append(lines[i][4:] if lines[i].startswith("    ") else "")
                i += 1
            while body and not body[-1].strip():
                body.pop()
            out.append(
                f'<div class="admonition {kind}"><p class="admonition-title">{inline(title)}</p>'
                + convert("\n".join(body), options) + "</div>")
            continue

        # headings
        heading = HEADING_RE.match(line)
        if heading:
            level = len(heading.group(1))
            text = heading.group(2).strip()
            anchor = slugify(text)
            attrs = f' id="{anchor}"' if options.add_anchors else ""
            out.append(f"<h{level}{attrs}>{inline(text)}</h{level}>")
            i += 1
            continue

        # horizontal rule
        if HR_RE.match(line):
            out.append("<hr>")
            i += 1
            continue

        # table
        if "|" in line and i + 1 < n and TABLE_SEP_RE.match(lines[i + 1]) and "-" in lines[i + 1]:
            header = split_row(line)
            aligns = table_alignment(lines[i + 1])
            i += 2
            rows: list[list[str]] = []
            while i < n and "|" in lines[i] and lines[i].strip():
                rows.append(split_row(lines[i]))
                i += 1
            t = ["<table>", "<thead><tr>"]
            for idx, cell in enumerate(header):
                align = aligns[idx] if idx < len(aligns) else ""
                style = f' style="text-align:{align}"' if align else ""
                t.append(f"<th{style}>{inline(cell)}</th>")
            t.append("</tr></thead><tbody>")
            for row in rows:
                t.append("<tr>")
                for idx, cell in enumerate(row):
                    align = aligns[idx] if idx < len(aligns) else ""
                    style = f' style="text-align:{align}"' if align else ""
                    t.append(f"<td{style}>{inline(cell)}</td>")
                t.append("</tr>")
            t.append("</tbody></table>")
            out.append("\n".join(t))
            continue

        # blockquote
        if BLOCKQUOTE_RE.match(line):
            quote: list[str] = []
            while i < n and BLOCKQUOTE_RE.match(lines[i]):
                quote.append(BLOCKQUOTE_RE.match(lines[i]).group(1))  # type: ignore[union-attr]
                i += 1
            out.append("<blockquote>" + convert("\n".join(quote), options) + "</blockquote>")
            continue

        # lists
        if UL_RE.match(line) or OL_RE.match(line):
            items: list[tuple[int, str, str]] = []
            while i < n:
                ul = UL_RE.match(lines[i])
                ol = OL_RE.match(lines[i])
                if ul:
                    items.append((len(ul.group(1)), "-", ul.group(2)))
                    i += 1
                elif ol:
                    items.append((len(ol.group(1)), "1", ol.group(3)))
                    i += 1
                elif lines[i].startswith("  ") and items:
                    items[-1] = (items[-1][0], items[-1][1], items[-1][2] + "\n" + lines[i].strip())
                    i += 1
                elif not lines[i].strip():
                    # пустая строка внутри списка — смотрим, продолжается ли он
                    if i + 1 < n and (UL_RE.match(lines[i + 1]) or OL_RE.match(lines[i + 1])
                                       or lines[i + 1].startswith("  ")):
                        i += 1
                        continue
                    break
                else:
                    break
            rendered, _ = _render_list(items, 0)
            out.append(rendered)
            continue

        # пустая строка
        if not line.strip():
            i += 1
            continue

        # абзац
        para: list[str] = [line]
        i += 1
        while i < n and lines[i].strip() and not any(
                r.match(lines[i]) for r in (FENCE_RE, HEADING_RE, ADMONITION_RE, UL_RE, OL_RE,
                                            BLOCKQUOTE_RE, HR_RE, INCLUDE_HINT_RE)):
            para.append(lines[i])
            i += 1
        out.append("<p>" + inline(" ".join(para)) + "</p>")

    return "\n".join(out)


def page(title: str, body: str, *, extra_css: str = "") -> str:
    """Полный HTML-документ (используется для HTML/EPUB/PDF-рендеров)."""
    css = BASE_CSS + ("\n" + extra_css if extra_css else "")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="ru">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{escape(title)}</title>\n<style>\n{css}\n</style>\n</head>\n"
        f"<body>\n{body}\n</body>\n</html>\n"
    )


BASE_CSS = """
:root { --fg:#1c1e21; --bg:#ffffff; --muted:#5b6472; --accent:#0b7285; --code-bg:#f5f7fa;
        --border:#dfe3e8; --warn-bg:#fff6e6; --warn-bd:#f0a020; --tip-bg:#e7f5ff; --tip-bd:#1c7ed6;
        --danger-bg:#fff0f0; --danger-bd:#e03131; }
* { box-sizing: border-box; }
body { margin:0; padding:2.5rem 1.5rem; color:var(--fg); background:var(--bg);
       font:16px/1.65 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", "Noto Sans", Arial, sans-serif; }
main { max-width: 52rem; margin: 0 auto; }
h1,h2,h3,h4 { line-height:1.25; font-weight:650; margin:1.8em 0 .6em; }
h1 { font-size:2rem; border-bottom:2px solid var(--border); padding-bottom:.35em; margin-top:.4em; }
h2 { font-size:1.5rem; border-bottom:1px solid var(--border); padding-bottom:.25em; }
h3 { font-size:1.2rem; } h4 { font-size:1.05rem; color:var(--muted); }
a { color:var(--accent); text-decoration:none; } a:hover { text-decoration:underline; }
p { margin:.75em 0; }
code { background:var(--code-bg); border:1px solid var(--border); border-radius:4px;
       padding:.1em .35em; font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
       font-size:.88em; }
pre { background:var(--code-bg); border:1px solid var(--border); border-left:3px solid var(--accent);
      border-radius:6px; padding:.85rem 1rem; overflow-x:auto; line-height:1.45; }
pre code { background:none; border:0; padding:0; font-size:.85rem; white-space:pre; }
blockquote { margin:1em 0; padding:.4em 1em; border-left:4px solid var(--border); color:var(--muted); }
hr { border:0; border-top:1px solid var(--border); margin:2em 0; }
table { border-collapse:collapse; width:100%; margin:1.2em 0; font-size:.93rem; display:block; overflow-x:auto; }
th,td { border:1px solid var(--border); padding:.45rem .65rem; text-align:left; vertical-align:top; }
th { background:var(--code-bg); font-weight:600; }
tbody tr:nth-child(even) { background:#fbfcfd; }
ul,ol { padding-left:1.5em; } li { margin:.28em 0; }
.admonition { border:1px solid var(--border); border-left-width:4px; border-radius:6px;
              padding:.7rem 1rem; margin:1.1em 0; background:#fafbfc; }
.admonition-title { font-weight:650; margin:0 0 .35em; }
.admonition.warning { border-left-color:var(--warn-bd); background:var(--warn-bg); }
.admonition.danger  { border-left-color:var(--danger-bd); background:var(--danger-bg); }
.admonition.tip, .admonition.success { border-left-color:var(--tip-bd); background:var(--tip-bg); }
.admonition.info, .admonition.note { border-left-color:var(--accent); background:var(--tip-bg); }
.include-missing { border:1px dashed var(--warn-bd); background:var(--warn-bg); padding:.5rem .8rem;
                   border-radius:6px; font-size:.9rem; }
.chapter-meta { color:var(--muted); font-size:.9rem; margin:-.4em 0 1.4em; }
.toc { border:1px solid var(--border); border-radius:8px; padding:1rem 1.4rem; background:#fafbfc; }
.toc h2 { border:0; margin-top:0; } .toc ol { margin:0; }
.doc-nav { display:flex; justify-content:space-between; gap:1rem; margin-top:2.5rem;
           border-top:1px solid var(--border); padding-top:1rem; font-size:.95rem; }
@media print {
  body { padding:0; font-size:10.5pt; } main { max-width:none; }
  h1,h2,h3 { break-after:avoid; } pre,table,.admonition { break-inside:avoid; }
  pre { border-left-width:2px; } a { color:inherit; } .doc-nav { display:none; }
}
"""
