use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use log::{info, warn, error};

use crate::modules::eth_listener;
use crate::bootstrapper;

/// Timeout before activating blockchain fallback (5 minutes)
const NETWORK_DEAD_THRESHOLD_SECS: u64 = 300;

/// Interval between Sepolia polls in fallback mode
const FALLBACK_POLL_INTERVAL_SECS: u64 = 60;

/// Shared state for network health tracking
pub struct NetworkWatchdog {
    pub last_contact: AtomicU64, // Unix timestamp of last successful contact
}

impl NetworkWatchdog {
    pub fn new() -> Self {
        Self {
            last_contact: AtomicU64::new(Self::now()),
        }
    }
    
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    
    /// Call this whenever we receive/send successful P2P/Cloud message
    pub fn mark_alive(&self) {
        self.last_contact.store(Self::now(), Ordering::Relaxed);
    }
    
    /// Check if network is considered dead
    pub fn is_dead(&self) -> bool {
        let last = self.last_contact.load(Ordering::Relaxed);
        let elapsed = Self::now().saturating_sub(last);
        elapsed > NETWORK_DEAD_THRESHOLD_SECS
    }
    
    /// Get seconds since last contact
    pub fn seconds_since_contact(&self) -> u64 {
        let last = self.last_contact.load(Ordering::Relaxed);
        Self::now().saturating_sub(last)
    }
}

/// Background task that monitors network health and activates blockchain fallback
pub async fn run_fallback_monitor(watchdog: Arc<NetworkWatchdog>) {
    info!("[Watchdog] Network Health Monitor Started. Threshold: {}s", NETWORK_DEAD_THRESHOLD_SECS);
    
    let mut in_fallback_mode = false;
    
    loop {
        sleep(Duration::from_secs(30)).await;
        
        if watchdog.is_dead() {
            if !in_fallback_mode {
                warn!("[Watchdog] ⚠️ Network DEAD for {}s. Activating Blockchain Fallback...", 
                      watchdog.seconds_since_contact());
                in_fallback_mode = true;
            }
            
            // Poll Sepolia
            info!("[Watchdog] Polling Sepolia for recovery signal...");
            if let Some((peers, blob)) = eth_listener::check_sepolia_fallback().await {
                info!("[Watchdog] ✅ Recovered {} peers from Blockchain!", peers.len());
                
                // 1. Attempt reconnection
                for (ip, port) in &peers {
                    info!("[Watchdog] Recovery Peer: {}:{}", ip, port);
                    watchdog.mark_alive();
                }
                
                // 2. Reverse Propagation (Inject into Local Mesh)
                info!("[Watchdog] 💉 INJECTING Reverse Propagation Packet ({} bytes) into Local Mesh...", blob.len());
                propagate_to_mesh(&blob).await;
                
                in_fallback_mode = false;
            } else {
                warn!("[Watchdog] No valid signal on Sepolia. Retrying in {}s...", FALLBACK_POLL_INTERVAL_SECS);
            }
            
            // Wait before next poll
            sleep(Duration::from_secs(FALLBACK_POLL_INTERVAL_SECS)).await;
        } else {
            if in_fallback_mode {
                info!("[Watchdog] ✅ Network Recovered! Exiting Fallback Mode.");
                in_fallback_mode = false;
            }
        }
    }
}

/// Simulated Propagation to Local Mesh (IoT Layer)
async fn propagate_to_mesh(blob: &[u8]) {
    use std::net::UdpSocket;
    
    info!("[Propagation] Broadcasting Config Update to found neighbors...");
    
    // Attempt to bind a UDP socket for sending
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            warn!("[Propagation] Failed to bind UDP socket: {}", e);
            return;
        }
    };
    
    // Set non-blocking (optional) and enable broadcast
    let _ = socket.set_nonblocking(true);
    let _ = socket.set_broadcast(true);
    
    // Known local broadcast targets (Subnet Broadcast or Multicast)
    // For LAN recovery, we broadcast to common local addresses.
    // In real deployment, could use cached peer list or subnet scan.
    let targets = [
        "255.255.255.255:31337", // LAN Broadcast
        "192.168.1.255:31337",   // Common Home Subnet
        "10.0.0.255:31337",      // Alternative Subnet
    ];
    
    for target in &targets {
        match socket.send_to(blob, target) {
            Ok(n) => info!("[Propagation] Sent {} bytes to {}", n, target),
            Err(e) => warn!("[Propagation] Failed to send to {}: {}", target, e),
        }
    }
    
    info!("[Propagation] Config Update Broadcast Complete.");
}
