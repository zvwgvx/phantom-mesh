use mainline::{Dht, Id};
use std::net::SocketAddr;
use crate::oracle::Oracle;

pub struct ParasiticDiscovery {
    dht: Dht,
}

impl ParasiticDiscovery {
    pub fn new() -> Self {
        Self { dht: Dht::default() }
    }

    /// Unified Discovery Cycle: Iterate Active InfoHashes (Current, Prev, Next)
    pub async fn run_cycle(&self, announce_port: Option<u16>) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Get Active InfoHashes (TOTP Time-based)
        let hashes = Oracle::get_active_infohashes(); // Returns Vec<[u8; 20]>
        let mut all_peers = Vec::new();

        for hash_bytes in hashes {
             let info_hash_id = Id::from_bytes(&hash_bytes).unwrap();
             
             // 2. Announce Self if requested (Mesh Role)
             if let Some(port) = announce_port {
                  let _ = self.dht.announce_peer(info_hash_id, Some(port));
             }

             // 3. Find Peers
             let response = self.dht.get_peers(info_hash_id);
             
             // Collect closely related nodes as potential peers
             for peer in response.closest_nodes {
                  all_peers.push(peer.address);
             }
        }
        
        // Dedup
        all_peers.sort();
        all_peers.dedup();
        
        Ok(all_peers)
    }
}
