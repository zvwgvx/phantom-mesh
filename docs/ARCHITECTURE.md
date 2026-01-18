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
- Connects to any Cloud/Phantom node
- Leader election within local network
- Executes plugins and tasks

---

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

Edge discovers Cloud addresses via 5 tiers:

| Tier | Method | Stealth |
|------|--------|---------|
| 0 | Local cache | ✅ Silent |
| 1 | DNS-over-HTTPS | ✅ Encrypted |
| 2 | Reddit tags | ✅ Blends with traffic |
| 3 | DGA | ⚠️ Detectable pattern |
| 4 | Ethereum Sepolia | ✅ Immutable |

All bootstrap payloads signed with master key.

---

## Stealth Subsystem

### Windows
- Indirect syscalls via runtime resolution
- Process ghosting with transacted files
- ETW/AMSI patching at load time
- COM hijacking for persistence

### Linux
- memfd fileless execution
- eBPF-based process hiding
- Systemd generator persistence
- Anti-kill protection via syscall interception
