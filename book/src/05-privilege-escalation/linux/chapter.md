---
title: "Эскалация привилегий в Linux"
chapter: 5.1
difficulty: intermediate
tags: [linux, privesc, sudo, suid]
---

# Эскалация привилегий в Linux

## Чтение файлов через LFI

Часто первой ступенью к эскалации становится чтение конфигурационных файлов. Классический пример — чтение `/etc/passwd` через уязвимость Local File Inclusion (LFI):

{{ include "payloads/web/lfi-rfi/traversal-etc-passwd.md" }}

## Docker Socket Escape

Если контейнер смонтирован с файлом `/var/run/docker.sock`, злоумышленник может создать новый привилегированный контейнер и получить доступ к файловой системе хоста:

{{ include "payloads/cloud/docker-socket-escape.md" }}

## Redis без аутентификации

Если Redis доступен без пароля, можно записать свой SSH-ключ или cron-задачу напрямую в файловую систему:

{{ include "payloads/network/redis-unauthenticated.md" }}
