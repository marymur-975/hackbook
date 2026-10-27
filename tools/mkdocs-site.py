#!/usr/bin/env python3
"""Генератор дерева docs/ для MkDocs из book/src/."""
import argparse
import re
import shutil
import sys
import os
from pathlib import Path

def process_includes(content, base_dir):
    """Ищет {{ include "..." }} и заменяет на содержимое файла."""
    pattern = r'\{\{\s*include\s+["\'](.*?)["\']\s*\}\}'
    
    def replace_match(match):
        file_path = match.group(1)
        project_root = base_dir.parent.parent
        full_path = project_root / file_path
        
        if full_path.exists():
            try:
                return full_path.read_text(encoding='utf-8')
            except Exception as e:
                return f"\n> Ошибка чтения {file_path}: {e}\n"
        else:
            return f"\n> **Файл не найден:** `{file_path}`\n"
            
    return re.sub(pattern, replace_match, content)

def build_site(src_dir: Path, docs_dir: Path, clean: bool = False):
    if clean and docs_dir.exists():
        print(f"  Очистка {docs_dir}")
        shutil.rmtree(docs_dir)
    
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    # Копируем ассеты
    assets_src = src_dir.parent / "assets"
    if assets_src.exists():
        assets_dst = docs_dir / "assets"
        if assets_dst.exists(): shutil.rmtree(assets_dst)
        shutil.copytree(assets_src, assets_dst)
        print("  актив: assets/")
        
    chapters_count = 0
    
    # РЕКУРСИВНЫЙ ПОИСК ВСЕХ chapter.md
    for root, dirs, files in os.walk(src_dir):
        if "chapter.md" in files:
            chapter_file = Path(root) / "chapter.md"
            # Вычисляем относительный путь от src_dir
            rel_path = chapter_file.parent.relative_to(src_dir)
            
            # Читаем и обрабатываем директивы include
            raw_content = chapter_file.read_text(encoding='utf-8')
            processed_content = process_includes(raw_content, src_dir)
            
            # Создаем папку в docs (если вложенная)
            dst_chapter_dir = docs_dir / rel_path
            dst_chapter_dir.mkdir(parents=True, exist_ok=True)
            
            # Сохраняем обработанный текст
            dst_file = dst_chapter_dir / "index.md"
            dst_file.write_text(processed_content, encoding='utf-8')
            
            print(f"  глава: {rel_path}")
            chapters_count += 1
            
    # Копируем папки
    for folder_name in ["cheatsheets", "walkthroughs", "wordlists", "labs", "docs", "detections", "payloads"]:
        src_folder = src_dir.parent.parent / folder_name
        if src_folder.exists():
            dst_folder = docs_dir / folder_name
            if dst_folder.exists(): shutil.rmtree(dst_folder)
            shutil.copytree(src_folder, dst_folder)
            print(f"  актив: {folder_name}/")
            
    # Копируем Граф знаний
    graph_src = src_dir.parent.parent / "payloads" / "graph"
    if graph_src.exists():
        graph_dst = docs_dir / "graph"
        if graph_dst.exists(): shutil.rmtree(graph_dst)
        shutil.copytree(graph_src, graph_dst)
        print("  актив: graph/ (Граф знаний)")

    # Титульная страница
    index_file = src_dir / "index.md"
    if index_file.exists():
        shutil.copy(index_file, docs_dir / "index.md")
    else:
        (docs_dir / "index.md").write_text("# hackbook\n\nДобро пожаловать.", encoding='utf-8')
        
    print(f"Готово: {chapters_count} глав(ы)")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--src", default="book/src")
    parser.add_argument("--docs", default="book/docs")
    args = parser.parse_args()
    
    src_dir, docs_dir = Path(args.src), Path(args.docs)
    if not src_dir.exists():
        print(f"Ошибка: папка {src_dir} не найдена.", file=sys.stderr)
        sys.exit(1)
    build_site(src_dir, docs_dir, args.clean)

if __name__ == "__main__":
    main()