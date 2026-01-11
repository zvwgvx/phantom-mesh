use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use hex;

// Configuration: 4 hours
const SLOT_DURATION: u64 = 4 * 3600;

pub struct Oracle;

impl Oracle {
    /// Returns list of active InfoHashes (Current, +prev, +next for redundancy)
    /// Returns 20-byte truncated SHA256 hashes compatible with Mainline DHT.
    pub fn get_active_infohashes() -> Vec<[u8; 20]> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Time-based Slot (4 Hours)
        let current_slot = current_time / SLOT_DURATION;

        // Overlapping Windows: [Prev, Current, Next]
        let slots = vec![
            current_slot.saturating_sub(1),
            current_slot,
            current_slot + 1
        ];

        let mut hashes = Vec::new();
        for slot in slots {
            hashes.push(Self::generate_hash(slot));
        }
        
        hashes
    }

    /// Core Hash Generation
    fn generate_hash(slot: u64) -> [u8; 20] {
        let seed = Self::get_seed_obfuscated();
        let raw_input = format!("{}{}", seed, slot);
        
        // SHA256 as requested
        let mut hasher = Sha256::new();
        hasher.update(raw_input.as_bytes());
        let result = hasher.finalize(); // 32 bytes
        
        // Truncate to 20 bytes for Mainline DHT compatibility (160-bit)
        let mut truncated = [0u8; 20];
        truncated.copy_from_slice(&result[0..20]);
        truncated
    }
    
    /// Obfuscated Seed Retrieval (Runtime Reconstruction)
    fn get_seed_obfuscated() -> String {
        // Obfuscation to evade static string analysis
        let part1 = "Phantom_Protocol";
        let part2 = "_v3_Eternal_Seed";
        let part3 = "_99281";
        format!("{}{}{}", part1, part2, part3)
    }
}
