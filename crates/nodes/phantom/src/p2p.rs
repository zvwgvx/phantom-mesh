use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use log::{info, warn, error, debug};
use ed25519_dalek::{SigningKey, Signer};
use rand::Rng;

use protocol::wire::{WireConstants, WireP2PGossip, WireP2PHeader};
use protocol::p2p::{P2PCommand, P2PMessage, P2P_MAGIC, P2P_TYPE_GOSSIP};

const P2P_PORT: u16 = 31338; // Phantom uses diff port to run on same machine as Cloud? Or same?
// If same machine, use 31338.

#[derive(Clone)]
struct Peer {
    addr: SocketAddr,
    last_seen: Instant,
}

pub struct P2PService {
    socket: Arc<UdpSocket>,
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    master_key: Arc<SigningKey>,
}

impl P2PService {
    pub async fn new(master_key: Arc<SigningKey>) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", P2P_PORT)).await?;
        info!("[P2P] Listening on {}", P2P_PORT);
        
        Ok(Self {
            socket: Arc::new(socket),
            peers: Arc::new(Mutex::new(HashMap::new())),
            master_key,
        })
    }

    pub async fn add_peer(&self, addr: SocketAddr) {
        let mut peers = self.peers.lock().unwrap();
        peers.insert(addr, Peer { addr, last_seen: Instant::now() });
        info!("[P2P] Added Peer: {}", addr);
    }

    pub async fn start(self: Arc<Self>) {
        let socket = self.socket.clone();
        let me = self.clone();

        // 1. Receive Loop
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        me.handle_packet(&buf[..len], src).await;
                    }
                    Err(e) => error!("[P2P] Recv Error: {}", e),
                }
            }
        });

        // 2. Gossip Loop (60s)
        let me_gossip = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                me_gossip.gossip().await;
            }
        });
    }

    async fn handle_packet(&self, buf: &[u8], src: SocketAddr) {
        if buf.len() < 5 { return; }
        // Magic Check (Big Endian)
        let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        if magic != WireConstants::P2P_MAGIC { return; }

        let type_ = buf[4];
        
        if type_ == WireConstants::P2P_TYPE_GOSSIP {
            // Update peer list logic
            self.add_peer(src).await;
            // Parse payload if needed
        }
    }

    async fn gossip(&self) {
        let peers: Vec<SocketAddr> = {
            let map = self.peers.lock().unwrap();
            map.keys().cloned().collect()
        };

        if peers.is_empty() { return; }

        // Construct Basic Gossip Packet
        // For simplicity using raw bytes construction to match wire
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&WireConstants::P2P_MAGIC.to_be_bytes()); // Magic
        pkt.push(WireConstants::P2P_TYPE_GOSSIP); // Type
        pkt.push(peers.len() as u8); // Count

        // Add peers...
        for peer in &peers {
             if let std::net::IpAddr::V4(ipv4) = peer.ip() {
                 pkt.extend_from_slice(&ipv4.octets());
                 pkt.extend_from_slice(&peer.port().to_be_bytes());
             }
        }

        // Send to random subsets
        let socket = self.socket.clone();
        for _ in 0..3 {
            if peers.is_empty() { break; }
            let target = peers[rand::thread_rng().gen_range(0..peers.len())];
            let _ = socket.send_to(&pkt, target).await;
        }
    }

    pub async fn broadcast_command(&self, cmd_payload: Vec<u8>) {
        // Create full P2P Command with Signature
        let nonce = rand::thread_rng().gen::<u32>();
        let cmd = P2PCommand::new(nonce, cmd_payload, &self.master_key);
        
        let packet_bytes = P2PMessage::Command(cmd).to_bytes();
        
        // Blast to all peers
        let peers: Vec<SocketAddr> = {
            let map = self.peers.lock().unwrap();
            map.keys().cloned().collect()
        };
        
        let socket = self.socket.clone();
        for peer in peers {
            let _ = socket.send_to(&packet_bytes, peer).await;
        }
        info!("[P2P] Broadcasted Command ({} bytes)", packet_bytes.len());
    }
}
