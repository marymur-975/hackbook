---
title: "Атаки на Active Directory"
chapter: 3.1
difficulty: advanced
tags: [active-directory, kerberos, smb]
---

# Атаки на Active Directory

## Релей-атаки (SMB Relay)

Если в сети отключена обязательная подпись SMB (SMB Signing), злоумышленник может перехватить NTLM-хэш и переслать его на другой сервер, чтобы получить доступ к нему.

{{ include "payloads/network/smb-signing-relay.md" }}

## Анонимный LDAP

Если LDAP-сервер разрешает анонимные запросы, можно вытащить список пользователей и структуру домена.

{{ include "payloads/network/ldap-anonymous-bind.md" }}
