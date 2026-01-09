use chrono::prelude::*;
use sha1::{Digest, Sha1};
use crate::time::TimeKeeper;

pub struct Oracle;

impl Oracle {
    /// Generate daily InfoHash for Parasitic DHT Discovery
    pub fn generate_daily_info_hash() -> Result<[u8; 20], Box<dyn std::error::Error>> {
        // Use verified network time
        let utc: DateTime<Utc> = TimeKeeper::utc_now();
        let date_str = utc.format("%Y-%m-%d").to_string(); 

        let seed = format!("PHANTOM_TRINITY_V4_{}", date_str);
        
        let mut hasher = Sha1::new();
        hasher.update(seed.as_bytes());
        let result = hasher.finalize();

        Ok(result.into())
    }
}
