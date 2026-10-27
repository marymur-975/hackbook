@echo off
echo ==============================
echo  Сборка книги hackbook
echo ==============================

echo 1. Генерация графа знаний...
python tools/graph-generator.py --pretty

echo 2. Копирование глав и карточек...
python tools/mkdocs-site.py --clean

echo 3. Запуск локального сервера...
mkdocs serve --config-file book/mkdocs.yml