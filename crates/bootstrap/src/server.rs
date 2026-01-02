use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::net::SocketAddr;
use protocol::{MeshMsg, PeerInfo, Registration};
// For now, we use standard TcpListener, assuming Tor maps port 80 to this local port.
// In a real Arti integration, we would use TorClient::launch_onion_service().
use tokio::net::{TcpListener, TcpStream};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// Peer Storage: PubKey -> PeerInfo
type PeerMap = Arc<RwLock<HashMap<String, PeerInfo>>>;

pub async fn run_bootstrap_node(port: u16) {
    let peers: PeerMap = Arc::new(RwLock::new(HashMap::new()));
    let addr = format!("127.0.0.1:{}", port);
    
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    println!("Bootstrap (Onion Tracker) listening on: {}", addr);

    while let Ok((stream, addr)) = listener.accept().await {
        let peers = peers.clone();
        tokio::spawn(handle_connection(peers, stream, addr));
    }
}

async fn handle_connection(peers: PeerMap, stream: TcpStream, _addr: SocketAddr) {
    let mut ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(_) => return,
    };

    while let Some(msg) = ws_stream.next().await {
        if let Ok(Message::Text(text)) = msg {
            if let Ok(mesh_msg) = serde_json::from_str::<MeshMsg>(&text) {
                match mesh_msg {
                    MeshMsg::Register(reg) => {
                        // 0. Verify Proof-of-Work (Sybil Defense)
                        // Difficulty 4 (4 Hex Zeros == 2 Bytes 0x00)
                        use sha2::{Sha256, Digest};
                        let pow_input = format!("{}{}", reg.pub_key, reg.pow_nonce);
                        let hash = Sha256::digest(pow_input.as_bytes());
                        if hash[0] != 0 || hash[1] != 0 {
                             println!("[-] Invalid PoW from {} (Possible Sybil)", reg.pub_key);
                             return;
                        }

                        // 1. Verify Signature
                        // Signed Data = "Register:<onion_address>"
                        let data = format!("Register:{}", reg.onion_address);
                        if !protocol::verify_signature(&reg.pub_key, data.as_bytes(), &reg.signature) {
                             println!("[-] Invalid Signature from {}", reg.pub_key);
                             return;
                        }

                        let info = PeerInfo {
                            pub_key: reg.pub_key.clone(),
                            onion_address: reg.onion_address,
                            last_seen: chrono::Utc::now().timestamp(),
                        };
                        
                        println!("[+] New Node Registered: {} -> {}", info.pub_key, info.onion_address);
                        peers.write().await.insert(reg.pub_key, info);
                    }
                    MeshMsg::GetPeers => {
                        let reader = peers.read().await;
                        let list: Vec<PeerInfo> = reader.values().cloned().collect();
                        // Return random 50 (Mocking random selection for now)
                        let limit = std::cmp::min(list.len(), 50);
                        let sublist = list[..limit].to_vec();
                        
                        let resp = MeshMsg::Peers(sublist);
                        let json = serde_json::to_string(&resp).unwrap();
                        let _ = ws_stream.send(Message::Text(json.into())).await;
                    }
                    _ => {} // Bootstrap ignores Gossip/Other messages
                }
            }
        }
    }
}
