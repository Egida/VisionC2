## ☾℣☽ VisionC2 Changelog 

### v1.7 — Feb 2026

**Full TUI Control Panel**
* Complete interactive terminal UI (default mode via `./cnc`)
* Real-time bot dashboard with shell access & management commands
* Consolidated Attack Center with live countdowns & progress
* SOCKS5 proxy manager with status controls
* Toast notifications & connection history logs

**Optimizations & Docs**
* HTTP/L7 improvements: connection pooling & keep-alive
* Rewritten documentation (USAGE.md, COMMANDS.md) for TUI
* Improved Setup.py flow and helper text

### v1.6 — Feb 2026
**Core Improvements**
* DNS: Prioritizes Cloudflare DoH over system DNS
* Persistence: Cron-based auto-restart on bot death
* Proxies: Validated in parallel before attacks
* Reduced bot-to-CNC status chatter

**UI Updates**
* Redesigned login screen with animations & lockout
* Streamlined command menus (`attack`/`methods` split)

---

### v1.5 — February 2026

#### 🔧 Build & Tooling

* **Automatic UPX Signature Stripping**

  * `deUPX.py` added and integrated into `build.sh`
  * Runs automatically post-setup to reduce static detection

#### 📚 Documentation

* **Full Code Documentation**

  * CNC and Bot functions fully commented
* **Command Reference**

  * Moved to `cnc/COMMANDS.md`
* **Setup Summary**

  * Configuration summary printed after setup

#### 🤖 Bot Enhancements

* **+50 User-Agents**

  * Expanded Layer 7 fingerprints
* **DoH-First C2 Resolution**

  * Resolution order: DoH TXT → DNS TXT → A → Direct IP

---

### v1.4 — January 2026

#### 🚀 Features

* **Proxy List Support (Layer 7)**

  * Commands: `!http`, `!https`, `!tls`, `!cfbypass`
  * Formats: `ip:port`, `ip:port:user:pass`, `http://`, `socks5://`
  * Example:

    ```
    !http target.com 443 60 -p https://example.com/proxies.txt
    ```

---

### v1.3 — January 2026

#### 🚀 Features

* **RAM Tracking**

  * Bots report total RAM on registration
* **Debug Logging**

  * Connection, TLS, auth, registration, command flow
* **CF / TLS Bypass Improvements**

  * Stability and reliability updates

---

### v1.2 — January 2026

#### 🔒 Security

* **C2 Address Obfuscation**

  * RC5 → RC4
  * XOR → RC4 → MD5 → Base64

#### 🛠️ Tooling

* **Automated `setup.py`**
* **RCE & Proxy Modules**
* **Early CF/TLS bypass support**

---

### v1.1 — December 2025

#### 🎉 Initial Release

* **TLS 1.3 Encrypted Communications**
* **14-Architecture Cross-Compilation**

  * amd64, 386, arm, arm64, mips, mipsle, mips64, mips64le
* **HMAC Challenge-Response Authentication**

---

## Version History Summary

| Version | Date     | Highlights                                         |
| ------- | -------- | ---------------------------------------------------|
| v1.7    | Feb 2026 | Full TUI panel, HTTP optimizations, consolidated UI|
| v1.6    | Feb 2026 | DoH-first target resolve, persist fix, UI overhaul |
| v1.5    | Feb 2026 | UPX stripping, docs, +50 user agents               |
| v1.4    | Jan 2026 | Proxy support for Layer 7                          |
| v1.3    | Jan 2026 | RAM tracking, debug logging                        |
| v1.2    | Jan 2026 | RC4 obfuscation, setup automation                  |
| v1.1    | Dec 2025 | Initial release                                    |

---

---
