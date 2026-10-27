HB-DOC: учебный документ лаборатории vuln-hub.

Этот файл лежит в DOCS_DIR и используется эндпоинтами /read и /read_safe:

  * /read?file=readme.txt        — читается (путь из параметра, без нормализации)
  * /read?file=../../../../etc/passwd — УЯЗВИМО: выход за пределы DOCS_DIR
  * /read_safe?file=readme.txt   — читается
  * /read_safe?file=../...       — блокируется (realpath + проверка префикса)

Задание: добавьте сюда свой файл и проверьте, что /read_safe отдаёт его,
а traversal по-прежнему блокируется.
