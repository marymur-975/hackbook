@"
---

id: apk-decompile
title: "Android: Декомпиляция APK через JADX"
type: mobile
target: android
category: mobile
difficulty: beginner
bypass: none
tags: [android, apk, reverse-engineering, jadx]
tested_on: ["JADX 1.4.7"]
success_rate: 0.95
risk: low
cwe: "CWE-798"
status: draft
---

# Android: Декомпиляция APK через JADX

## Payload

```bash
jadx -d output_dir app.apk
```

Explanation
Утилита JADX декомпилирует Dalvik-байткод (classes.dex) обратно в читаемый Java-код.

Detection
Защита от декомпиляции: ProGuard/R8, обфускация строк.

Remediation
Используйте обфускацию и не храните секреты в коде.
"@ | Out-File -Encoding utf8 payloads\mobile\android\apk-decompile.md
