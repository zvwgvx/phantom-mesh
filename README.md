# Phantom Mesh: Advanced Decentralized Infrastructure

**STATUS**: ACTIVE DEVELOPMENT
**ARCHITECTURE**: Autonomous P2P Mesh (QUIC + DHT)
**VISIBILITY**: Stealth (Encrypted UDP, Parasitic Discovery)

## 1. System Overview

Phantom Mesh is a research-grade decentralized network architecture focusing on resilience, anonymity, and NAT traversal. Unlike traditional Tor-based botnets, Phantom utilizes a custom **QUIC-based P2P protocol** combined with **Parasitic DHT Discovery** (BitTorrent Mainline) to operate without static entry points or central C2 servers.

### The Component Architecture

1.  **Phantom Mesh (Infrastructure Node)**:
    *   **Role**: Stable relay and signaling arbiter.
    *   **Network**: Requires public IP or port forwarding (Full Cone NAT).
    *   **Function**:
        *   Acts as a **Bursting Arbiter** to coordinate NAT hole punching between Edge nodes.
        *   Announces presence to the global BitTorrent DHT (Parasitic Discovery).
        *   Relays Gossip messages across the network.

2.  **Phantom Edge (Worker Node)**:
    *   **Role**: Ephemeral worker operating behind strict NATs.
    *   **Network**: UDP/QUIC (Simulated Client Traffic).
    *   **Function**:
        *   **Parasitic Discovery**: Queries public DHTs (e.g., `router.bittorrent.com`) to find Mesh nodes without hardcoded IPs.
        *   **Bursting Arbiter**: executes synchronized UDP bursts to punch holes through firewalls/NATs upon command.
        *   Executes modular payloads (DDoS, Scanning, etc.).

## 2. Core Technologies

### Transport: Custom QUIC
*   **Implementation**: Built on `quinn` (IETF QUIC) and `rustls` (TLS 1.3).
*   **Security**:
    *   **Encryption**: ChaCha20Poly1305 (AEAD) for payload protection.
    *   **Authentication**: Ed25519 digital signatures for verifying command integrity.
    *   **Stealth**: Random packet padding to defeat traffic analysis.

### NAT Traversal: "Bursting Arbiter"
State-of-the-art hole punching technique to connect two nodes behind separate NATs:
1.  **Coordination**: Mesh node (Arbiter) measures Round-Trip Time (RTT) to both Edge nodes.
2.  **Synchronization**: Arbiter calculates a precise `fire_delay` and sends a `SignalMsg::ArbiterCommand` to both peers.
3.  **The Burst**: Both Edge nodes fire a high-frequency burst (50 packets/sec) of dummy UDP packets at each other's expected public endpoint simultaneously.
4.  **Connection**: NAT mapping is created, allowing the subsequent QUIC handshake to succeed.

### Parasitic Discovery
Leverages the global, immutable BitTorrent DHT infrastructure:
*   **Mesh Nodes**: Periodically announce their IP:Port to a rolling InfoHash derived from the current date.
*   **Edge Nodes**: Calculate the daily InfoHash and query standard DHT bootstraps to effect decentralized peer discovery.
*   **Result**: No central directory to seize; discovery logic is embedded in the public internet infrastructure.

## 3. Usage & building

### Requirements
*   Rust 2021 Edition (stable)
*   Build tools (`build-essential`, `cmake`)

### Build Command
Compile the entire workspace (Mesh + Edge + Tools):

```bash
cargo build --release --workspace
```

### Binaries
*   `target/release/phantom_mesh`: Infrastructure node (run on VPS/Server).
*   `target/release/phantom_edge`: Worker node (run on Client).
*   `target/release/loader`: Standalone module loader.

## 4. Technical Stack
*   **Language**: Rust
*   **Async Runtime**: `tokio`
*   **Transport**: `quinn`, `rustls`
*   **Discovery**: `mainline` (Kademlia/DHT)
*   **Crypto**: `ed25519-dalek`, `chacha20poly1305`
*   **Serialization**: `serde`, `serde_json`

---
**DISCLAIMER**: This software is for educational research into resilient network architectures only.
