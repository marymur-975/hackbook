---
title: "Сетевые сервисы"
chapter: 2.1
difficulty: beginner
tags: [network, smb, ftp, snmp]
---

# Сетевые сервисы

## Разведка сети

Первым шагом всегда является поиск открытых портов и сервисов. Если вы обнаружили DNS-сервер, проверьте, не отдаёт ли он всю зону целиком (AXFR):

{{ include "payloads/network/dns-zone-transfer.md" }}

## SMB (Windows)

Протокол SMB часто настроен небезопасно. Классическая атака — это null-сессия (подключение без пароля) для перечисления пользователей:

{{ include "payloads/network/smb-null-session.md" }}

## SNMP

Протокол SNMP с community-строкой `public` позволяет вытащить кучу информации о системе:

{{ include "payloads/network/snmp-community-enum.md" }}
