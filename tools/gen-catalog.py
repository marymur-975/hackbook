#!/usr/bin/env python3
"""Генерация сводного JSON-каталога для внешних интеграций."""
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
CATALOG_DIR = ROOT / "catalog"

def extract_yaml(text):
    """Очень простой парсер YAML (только для front-matter)."""
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    
    yaml_text = parts[1]
    data = {}
    for line in yaml_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            data[key] = val
    return data

def main():
    CATALOG_DIR.mkdir(exist_ok=True)
    
    payloads = []
    for root, dirs, files in os.walk(ROOT / "payloads"):
        for file in files:
            if file.endswith(".md") and file != "README.md":
                path = Path(root) / file
                content = path.read_text(encoding="utf-8")
                meta = extract_yaml(content)
                meta["path"] = str(path.relative_to(ROOT))
                payloads.append(meta)
                
    chapters = []
    for root, dirs, files in os.walk(ROOT / "book" / "src"):
        for file in files:
            if file == "chapter.md":
                path = Path(root) / file
                content = path.read_text(encoding="utf-8")
                meta = extract_yaml(content)
                meta["path"] = str(path.relative_to(ROOT))
                chapters.append(meta)

    with open(CATALOG_DIR / "payloads.json", "w", encoding="utf-8") as f:
        json.dump(payloads, f, ensure_ascii=False, indent=2)
        
    with open(CATALOG_DIR / "chapters.json", "w", encoding="utf-8") as f:
        json.dump(chapters, f, ensure_ascii=False, indent=2)
        
    print(f"Готово: {len(payloads)} карточек, {len(chapters)} глав.")

if __name__ == "__main__":
    main()