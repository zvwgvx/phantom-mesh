use mainline::{Dht, Id};

pub struct ParasiticDiscovery {
    dht: Dht,
    info_hash: [u8; 20],
    port: u16,
}

impl ParasiticDiscovery {
    pub fn new(info_hash: [u8; 20], port: u16) -> Self {
        Self { 
            dht: Dht::default(),
            info_hash,
            port,
        }
    }

    /// MESH ROLE: Announce self to the DHT network
    pub async fn announce(&self) -> Result<(), Box<dyn std::error::Error>> {
        let info_hash_id = Id::from_bytes(&self.info_hash).unwrap();

        println!("* Announcing Presence on InfoHash: {:?} Port: {}", hex::encode(self.info_hash), self.port);

        // 2. Announce
        // We use mainline dht to announce our port on this infohash
        self.dht.announce_peer(info_hash_id, Some(self.port))?;
        
        Ok(())
    }
}
