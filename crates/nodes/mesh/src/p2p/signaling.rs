//! NAT Hole Punch Arbiter - RTT measurement and burst synchronization

use std::collections::HashMap;
use protocol::SignalMsg;

#[derive(Debug, Clone)]
struct PeerRtt {
    last_ping_sent: u64,
    rtt_ms: Option<u64>,
}

pub struct PunchArbiter {
    rtt_cache: HashMap<String, PeerRtt>,
}

impl PunchArbiter {
    pub fn new() -> Self {
        Self { rtt_cache: HashMap::new() }
    }
    
    pub fn record_ping_sent(&mut self, peer_id: &str, timestamp: u64) {
        self.rtt_cache.insert(peer_id.to_string(), PeerRtt {
            last_ping_sent: timestamp,
            rtt_ms: None,
        });
    }
    
    pub fn process_pong(&mut self, peer_id: &str, _pong_timestamp: u64) -> Option<u64> {
        if let Some(entry) = self.rtt_cache.get_mut(peer_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let rtt = now.saturating_sub(entry.last_ping_sent);
            entry.rtt_ms = Some(rtt);
            return Some(rtt);
        }
        None
    }
    
    pub fn get_rtt(&self, peer_id: &str) -> Option<u64> {
        self.rtt_cache.get(peer_id).and_then(|p| p.rtt_ms)
    }
    
    /// Calculate synchronized fire commands with RTT compensation
    pub fn calculate_arbiter_commands(
        &self,
        peer_a_id: &str,
        peer_a_ip: &str,
        peer_a_port: u16,
        peer_b_id: &str,
        peer_b_ip: &str,
        peer_b_port: u16,
    ) -> Option<(SignalMsg, SignalMsg)> {
        let rtt_a = self.get_rtt(peer_a_id)?;
        let rtt_b = self.get_rtt(peer_b_id)?;
        
        let delay_a = rtt_a / 2;
        let delay_b = rtt_b / 2;
        let t_safe = std::cmp::max(rtt_a, rtt_b) * 3 + 500;
        
        let fire_delay_a = t_safe.saturating_sub(delay_a);
        let fire_delay_b = t_safe.saturating_sub(delay_b);
        let burst_duration = 1000u64;
        
        let cmd_a = SignalMsg::ArbiterCommand {
            target_ip: peer_b_ip.to_string(),
            target_port: peer_b_port,
            fire_delay_ms: fire_delay_a,
            burst_duration_ms: burst_duration,
        };
        
        let cmd_b = SignalMsg::ArbiterCommand {
            target_ip: peer_a_ip.to_string(),
            target_port: peer_a_port,
            fire_delay_ms: fire_delay_b,
            burst_duration_ms: burst_duration,
        };
        
        Some((cmd_a, cmd_b))
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn create_ping() -> SignalMsg {
    SignalMsg::Ping { timestamp: now_ms() }
}

pub fn create_pong(ping_timestamp: u64) -> SignalMsg {
    SignalMsg::Pong { timestamp: ping_timestamp }
}
