# Phantom Mesh Architecture

> Detailed technical documentation of the system architecture.

---

## Table of Contents

- [Overview](#overview)
- [Node Types](#node-types)
- [Network Topology](#network-topology)
- [Protocol Specification](#protocol-specification)
- [Bootstrap Mechanism](#bootstrap-mechanism)
- [Stealth Subsystem](#stealth-subsystem)

---

## Overview

Phantom Mesh implements a **two-tier distributed architecture** with a hidden operator node:

```
┌────────────────────────────────────────────────────────────────────────┐
│                            CONTROL PLANE                               │
│                       Cloud P2P Mesh (UDP 31337)                       │
│                                                                        │
│   ┌───────────┐       ┌───────────┐       ┌───────────────────┐        │
│   │   Cloud   │◄─────►│   Cloud   │◄─────►│      PHANTOM      │        │
│   │   Node    │  P2P  │   Node    │  P2P  │   (Hidden Master) │        │
│   │   (Zig)   │       │   (Zig)   │       │       (Rust)      │        │
│   └─────┬─────┘       └─────┬─────┘       └─────────┬─────────┘        │
│         │                   │                       │                  │
│   ┌─────┴─────┐       ┌─────┴─────┐       ┌─────────┴─────────┐        │
│   │  Verify   │       │  Verify   │       │    PRIVATE KEY    │        │
│   │  + Relay  │       │  + Relay  │       │    Sign + Send    │        │
│   └─────┬─────┘       └─────┬─────┘       └─────────┬─────────┘        │
│         │                   │                       │                  │
│         │                   │                       │ SSH (Operator)   │
│         │    (Identical P2P packets)                ▼                  │
│         │                   │             ┌───────────────┐            │
│         │                   │             │    Operator   │            │
│         │                   │             │    Terminal   │            │
│         │                   │             └───────────────┘            │
└─────────┼───────────────────┼──────────────────────────────────────────┘
          │                   │
          └─────────┬─────────┘
                    │ MQTT (Leader → Cloud)
                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           EXECUTION PLANE                              │
│                     Edge Nodes (Rust) — Agents                         │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      LAN CLUSTER                                 │  │
│  │   ┌──────────┐       ┌──────────┐       ┌──────────┐            │  │
│  │   │  Edge A  │◄─UDP─►│  Edge B  │◄─UDP─►│  Edge C  │            │  │
│  │   │  WORKER  │       │  LEADER  │       │  WORKER  │            │  │
│  │   └──────────┘       └────┬─────┘       └──────────┘            │  │
│  │                           │                                      │  │
│  │                           │ MQTT to Cloud (6 parallel)           │  │
│  │                           ▼                                      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

| Principle | Description |
|-----------|-------------|
| **Phantom Blending** | Phantom is indistinguishable from Cloud nodes |
| **Signature Asymmetry** | All nodes verify, only Phantom signs |
| **LAN Clustering** | Edge nodes elect leader, reduce Cloud traffic |
| **Multi-tier Bootstrap** | 5 fallback methods for resilience |

---

## Node Types

### Cloud Node (`crates/nodes/cloud`)
- **Language**: Zig
- **Role**: Mesh participant, signature verifier, Edge relay
- Participates in P2P gossip (UDP 31337)
- Maintains neighbor routing table
- **Verifies** Ed25519 signatures on commands
- Relays commands to connected Edge nodes

### Phantom Node (`crates/nodes/phantom`)
- **Language**: Rust
- **Role**: Hidden master within Cloud mesh
- Participates in **same P2P mesh** as Cloud nodes
- **Signs** commands with master private key
- Provides SSH shell for operator (port 12961)
- Can broadcast to Sepolia blockchain for fallback

### Edge Node (`crates/nodes/edge`)
- **Language**: Rust
- **Role**: Target agent, local cluster coordination
- Connects to any Cloud/Phantom node via MQTT (TCP 1883)
- Leader election within local network (UDP 31338)
- Executes plugins (DDoS, cryptominer, etc.)
- **Zero-Noise Discovery**: Passive sniffing + covert handshake

---

## LAN Cluster & Leader Election

### Overview

Edge nodes within the same LAN form a **self-organizing cluster**. This reduces Cloud traffic and provides resilience if some nodes lose external connectivity.

```
┌─────────────────────────────────────────────────────────────────┐
│                     LAN CLUSTER (192.168.1.0/24)                │
│                                                                 │
│   ┌────────────┐       ┌────────────┐       ┌────────────┐     │
│   │  Edge A    │       │  Edge B    │       │  Edge C    │     │
│   │  Rank: 100 │       │  Rank: 900 │←─────→│  Rank: 500 │     │
│   │  WORKER    │       │  LEADER    │       │  WORKER    │     │
│   └──────┬─────┘       └──────┬─────┘       └──────┬─────┘     │
│          │                    │                    │           │
│          │    ◄──── UDP Broadcast (31338) ────►   │           │
│          │                    │                    │           │
│          │    ◄──── TCP Bridge (31339) ────►      │           │
│          │                    │                    │           │
│          └────────────────────┼────────────────────┘           │
│                               │                                 │
│                               │ MQTT (1883) to Cloud            │
│                               ▼                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Election Protocol (Modified Bully Algorithm)

| Phase | Action | Description |
|-------|--------|-------------|
| **1. Discovery** | Broadcast `WhoIsLeader` | Node sends 3 UDP packets to 255.255.255.255:31338 |
| **2. Challenge** | Wait 3 seconds | Listen for `IAmLeader` responses |
| **3. Compare** | Rank comparison | Only accept Leaders with `(Rank, NodeID) > (MyRank, MyNodeID)` |
| **4. Promote** | Become Leader | If no stronger Leader found, self-promote and broadcast |
| **5. Heartbeat** | Periodic `IAmLeader` | Leader broadcasts every 5 seconds to maintain dominance |

**Rank Calculation**: `Rank = NodeID % 1000` (pseudo-random, deterministic)

**Tie-Breaker**: If Ranks are equal, higher NodeID wins. Prevents split-brain.

### Self-Healing Mechanisms

| Scenario | Detection | Recovery |
|----------|-----------|----------|
| **Leader Crash** | Worker TCP fails 5 times | Worker returns to Election, becomes new Leader |
| **Stronger Node Joins** | Leader receives `IAmLeader` with higher Rank | Current Leader exits (watchdog restarts as Worker) |
| **Network Partition** | Workers detect new Leader IP via UDP watcher | Workers break TCP loop, re-run Election |
| **Worker Stuck** | Background UDP listener detects Leader change | Immediate return to Election |

### Port Allocation (LAN)

| Port | Protocol | Purpose |
|------|----------|---------|
| 31338 | UDP | Leader Election (Broadcast) |
| 31339 | TCP | Worker-Leader Bridge (LIPC) |
| 9631 | TCP | Covert Handshake (Zero-Noise) |

## Network Topology

### Command Flow

```
1. OPERATOR → PHANTOM
   ssh admin@phantom -p 12961
   PhantomC2$ .attack 1.2.3.4 80 60

2. PHANTOM SIGNS & BROADCASTS
   - Creates P2PCommand packet
   - Signs payload with Ed25519 private key
   - Sends to neighbors (standard gossip)

3. CLOUD MESH PROPAGATION
   - Cloud nodes receive packet
   - Verify signature
   - Flood to 3 random neighbors
   - Forward to Edge subscribers

4. EDGE EXECUTION
   - Edge Leaders receive via MQTT
   - Dispatch to plugins
   - Bridge to Workers
```

### Port Allocation

| Port | Protocol | Used By | Purpose |
|------|----------|---------|---------|
| 31337 | UDP | Cloud | P2P gossip mesh |
| 31338 | UDP | Phantom | P2P to Cloud |
| 12961 | TCP/SSH | Phantom | Operator shell |
| 1883 | TCP | Cloud | Edge proxy (MQTT) |

---

## Protocol Specification

### P2P Wire Format

```
Packet Types:
┌────────────┬───────────────────────────────────────────────────────┐
│ GOSSIP     │ [Magic][Type=1][Count][IP:Port pairs...]              │
│ COMMAND    │ [Magic][Type=2][Nonce][Signature][Length][Payload]    │
│ COUNT_REQ  │ [Magic][Type=3][ReqID][TTL][OriginIP:Port]            │
│ COUNT_RESP │ [Magic][Type=4][ReqID][NodeCount]                     │
└────────────┴───────────────────────────────────────────────────────┘

Magic: Time-based rotating value (weekly)
Signature: 64 bytes Ed25519
Nonce: 4 bytes (replay protection)
```

---

## Bootstrap Mechanism

Edge discovers Cloud addresses via 5 tiers (ordered by stealth priority):

| Tier | Method | Mechanism | Stealth Level |
|------|--------|-----------|---------------|
| 0 | **Local Cache** | `~/.phantom/peers.json` | ✅ Silent (no network) |
| 1 | **DNS-over-HTTPS** | Query Cloudflare/Google DoH for TXT records | ✅ Encrypted |
| 2 | **Reddit Scraping** | Parse specific subreddit for tagged posts | ✅ Blends with normal traffic |
| 3 | **DGA** | Domain Generation Algorithm (date-seeded) | ⚠️ Detectable pattern |
| 4 | **Ethereum Sepolia** | Read from smart contract dead-drop | ✅ Immutable, decentralized |

All bootstrap payloads are signed with the master Ed25519 key.

---

## Zero-Noise Discovery

Edge nodes use passive discovery to find each other without generating suspicious traffic:

### Phase 1: Passive Sniffing
- Card in promiscuous mode via `libpnet`
- Capture broadcast traffic (MDNS, NetBIOS, DHCP)
- Filter by OUI (Intel, Realtek = real devices; VMware = skip)
- Build "Shadow Map" of candidate IPs

### Phase 2: Active Probe
- Select IPs with 3+ broadcast hits
- Connect to port 9631 (mimics IPP/CUPS printer)
- Send 4-byte rotating magic number
- Await XOR'd response confirming Phantom node

### Phase 3: Registration
- Verified peers added to internal routing
- Can now participate in Leader Election

```
[Sniff] → NetBIOS from 192.168.1.50 (OUI: Intel)
[Sniff] → Hits: 5, Candidate promoted
[Probe] → TCP 192.168.1.50:9631 → Magic sent
[Probe] → Response: XOR match! Peer confirmed.
```

---

## Security Model

### Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Command Signing | Ed25519 | Ensure only Phantom can issue commands |
| Magic Numbers | SHA256(date + seed) | Rotating identifiers, prevent replay |
| LIPC Framing | ChaCha20-Poly1305 | Worker-Leader encrypted channel |

### Trust Hierarchy

```
┌───────────────────────────────────────────────────────────────┐
│                      PHANTOM NODE                             │
│                 (Holds Private Key)                           │
│                         │                                     │
│            Signs all commands with Ed25519                    │
│                         │                                     │
│                         ▼                                     │
│   ┌─────────────────────────────────────────────────────┐    │
│   │                 CLOUD NODES                         │    │
│   │          (Hold only Public Key)                     │    │
│   │                                                     │    │
│   │  • Verify signatures before relaying               │    │
│   │  • Cannot forge commands                           │    │
│   │  • Cannot distinguish Phantom from peers           │    │
│   └─────────────────────────────────────────────────────┘    │
│                         │                                     │
│                         ▼                                     │
│   ┌─────────────────────────────────────────────────────┐    │
│   │                 EDGE NODES                          │    │
│   │          (Hold only Public Key)                     │    │
│   │                                                     │    │
│   │  • Verify signatures before execution              │    │
│   │  • Trust Leader for command forwarding             │    │
│   │  • Can verify directly if Leader is compromised    │    │
│   └─────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────┘
```

### Replay Protection

- **Nonce**: 4-byte incrementing counter per session
- **Timestamp**: Commands older than 5 minutes are rejected
- **Deduplication**: LRU cache of seen command hashes

---

## Stealth Subsystem

### Windows Evasion (Advanced)

The Windows stealth engine is built on a **Zero-Dependency, Native API** architecture. It avoids standard CRT functions where possible to minimize import table signatures.

| Technique | Implementation Details |
|-----------|------------------------|
| **Hybrid Architecture** | **EXE Drops DLL**: The initial executable is a "dropper" that installs a stealthy DLL (`EdgeUpdate.dll`) and establishes persistence. The DLL contains the core logic. |
| **Steganography** | **PNG Embedding**: The DLL is compressed (Deflate), encrypted (ChaCha20), and embedded into the `biLn` chunks of a valid PNG image (`logo.png`). The dropper extracts this payload at runtime, avoiding static analysis of the binary. |
| **COM Hijacking** | **Persistence**: The dropped DLL is registered as an `InprocServer32` for a user-mode CLSID. When standard Windows processes (like `explorer.exe` or `taskhostw.exe`) load this CLSID, they unknowingly load our DLL into their address space. |
| **Module Pinning** | **Anti-Unload**: Inside `DllMain`, we call `GetModuleHandleExW` with `GET_MODULE_HANDLE_EX_FLAG_PIN`. This increments the reference count, preventing the host process from unloading our DLL even if `DllGetClassObject` returns an error (which we do intentionally to remain stealthy). |
| **Ghost Protocol** | **AMSI/ETW Bypass**: We use **Indirect Syscalls** (resolving syscall numbers dynamically via "Hell's Gate" or "Halos Gate" techniques) to change the memory permission of `AmsiScanBuffer` to `RWX`, patch it to return `AMSI_RESULT_CLEAN`, and restore permissions to `RX`. This completely blinds Windows Defender. |
| **Scheduled Task** | **Fail-Safe**: Uses `rundll32.exe` to execute the DLL export `DllGetClassObject` as a secondary persistence mechanism. |
| **Obfuscated Sleep** | **Memory Encryption**: (Optional) During sleep cycles, `Ekko` or similar timers are used to encrypt the heap and stack, protecting the agent from memory scanners while dormant. |

### Linux Evasion

| Technique | Implementation |
|-----------|----------------|
| **Fileless Execution** | `memfd_create` + `fexecve` (no disk write) |
| **Process Hiding** | eBPF filter on `getdents64` syscall |
| **Anti-Kill** | eBPF blocks `kill/tkill` for our PID |
| **Persistence** | Systemd generator in `/run/systemd/generator` |
| **Log Suppression** | eBPF filters `syslog` writes |

### macOS Evasion

| Technique | Implementation |
|-----------|----------------|
| **Code Signing** | Ad-hoc signature for Gatekeeper bypass |
| **Persistence** | LaunchAgent plist in `~/Library/LaunchAgents` |
| **Transparency** | Disable TCC prompts via synthetic events |

---

## Build Pipeline

The build process is multi-stage to ensure the payload is correctly embedded and obfuscated:

1.  **Compile Core DLL**: `cargo build --lib --release` -> Generates `edge.dll`.
2.  **Steganography Packing**: `tools/steg_maker` reads `edge.dll`, encrypts it (ChaCha20), compresses it, and injects it into `src/assets/logo.png`.
3.  **Compile Dropper EXE**: `cargo build --bin edge --release` -> Generates `edge.exe`. This binary effectively contains the PNG, which implies it contains the DLL.
4.  **Strip & Optimize**: `llvm-strip` and LTO are applied to minimize size (target < 3MB).
