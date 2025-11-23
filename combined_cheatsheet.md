# 🌐 Networking – HTB Cybersecurity Summary

A concise summary of core networking concepts used in cybersecurity, pentesting, and HTB Labs.

## 📘 Networking Models

### 🔹 OSI Model (7 Layers)
| Layer | Name | Function |
|------|------|-----------|
|7|Application|User protocols (HTTP, FTP)|
|6|Presentation|Format/encrypt data (TLS)|
|5|Session|Manage sessions|
|4|Transport|TCP/UDP|
|3|Network|IP routing|
|2|Data Link|MAC addressing|
|1|Physical|Cables, signals|

### 🔹 TCP/IP Model (4 Layers)
|Layer|Purpose|
|-----|-------|
|Application|HTTP, DNS, SSH|
|Transport|TCP/UDP|
|Internet|IP addressing|
|Network Access|Ethernet/Wi-Fi|


# 🛠️ Local File Inclusion (LFI) — Cheat Sheet

Basic LFI:
/index.php?language=/etc/passwd
...
