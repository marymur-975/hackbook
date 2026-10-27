---
title: "Безопасность Android"
chapter: 7.1
difficulty: intermediate
tags: [mobile, android, apk, frida]
---

# Безопасность Android

## Введение

Мобильные приложения (APK) часто хранят чувствительные данные в открытом виде или имеют слабую защиту от модификации. В этом разделе мы разберем базовые шаги по анализу Android-приложений.

## Шаги анализа

1. **Декомпиляция:** Используйте `apktool` или `jadx` для распаковки APK и чтения `AndroidManifest.xml`.
2. **Анализ хранилища:** Проверьте, не хранятся ли токены или пароли в `SharedPreferences` (файлы `.xml` в `/data/data/<package>/shared_prefs/`).
3. **Динамический анализ:** Используйте `Frida` для перехвата методов и обхода проверок рута (root detection).

## Пример кода (Frida)

```javascript
// Обход простой проверки на root
Java.perform(function () {
  var RootCheck = Java.use("com.example.app.RootCheck");
  RootCheck.isDeviceRooted.implementation = function () {
    return false;
  };
});
```
