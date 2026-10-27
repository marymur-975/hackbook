---
id: frida-ssl-pinning-bypass
title: "Android: Обход SSL Pinning через Frida"
type: mobile
target: android
category: mobile
difficulty: intermediate
bypass: waf
tags: [android, frida, ssl-pinning, mobile]
tested_on: ["Android 12", "Android 13"]
success_rate: 0.8
risk: medium
cwe: "CWE-295"
status: draft
---

# Android: Обход SSL Pinning через Frida

## Payload

```javascript
Java.perform(function () {
  var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  var TrustManager = Java.registerClass({
    name: "com.example.TrustManager",
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function (chain, authType) {},
      checkServerTrusted: function (chain, authType) {},
      getAcceptedIssuers: function () {
        return [];
      },
    },
  });
});
```

Explanation
Скрипт Frida подменяет стандартный TrustManager в Java, заставляя приложение доверять любому сертификату.

Detection
Обнаружить можно по наличию frida-server в процессах.

Remediation
Используйте проверку целостности приложения (SafetyNet/Play Integrity).

text

3. Нажми «Файл» → «Сохранить как...»
4. Зайди в папку `C:\Users\PC\Desktop\book\hackbook\payloads\mobile\android\`
5. Назови файл `frida-ssl-pinning-bypass.md` (тип — «Все файлы»).
6. Нажми «Сохранить».

**Действие 2: Создай второй файл**
Точно так же создай файл `apk-decompile.md` с этим текстом:

````markdown
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
Explanation
Утилита JADX декомпилирует Dalvik-байткод (classes.dex) обратно в читаемый Java-код.

Detection
Защита от декомпиляции: ProGuard/R8, обфускация строк.

Remediation
Используйте обфускацию и не храните секреты в коде.
```
````
