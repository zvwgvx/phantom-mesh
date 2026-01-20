//! Time-Based Magic Generation
//!
//! Generates rotating magic values to prevent static fingerprinting.
//! All nodes compute the same value for a given time slot.
//! SECURITY: Seed is derived from environment, not hardcoded.

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::OnceLock;

/// Master seed - derived from PHANTOM_SEED environment variable
/// Falls back to a hash of hostname if not set
fn get_master_seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        // Use PHANTOM_SEED from environment (operator-set)
        if let Ok(seed_str) = std::env::var("PHANTOM_SEED") {
            // FNV-1a hash of the seed string
            let mut h = 0x811c9dc5_u64;
            for b in seed_str.bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x01000193);
            }
            return h;
        }
        
        // Fallback: derive from hostname
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "phantom".to_string());
        
        let mut h = 0x811c9dc5_u64;
        for b in hostname.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x01000193);
        }
        h
    })
}

/// Original magic values (used as differentiators)
const P2P_SEED: u32 = 0x597B92A8;
const LIPC_SEED: u32 = 0xF4240D11;
const HANDSHAKE_SEED: u32 = 0xCDCECF6D;
const HANDSHAKE_XOR_SEED: u32 = 0xEFD5493C;

/// Rotation periods in seconds
const PERIOD_4_HOURS: u64 = 4 * 60 * 60;      // 14400 seconds
const PERIOD_1_WEEK: u64 = 7 * 24 * 60 * 60;  // 604800 seconds

/// Simple hash function (FNV-1a style)
fn hash_u64(value: u64) -> u32 {
    let mut h = 0x811c9dc5u32;
    for byte in value.to_le_bytes() {
        h ^= byte as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// Get current time slot for a given period
fn time_slot(period: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / period
}

/// Get P2P discovery magic (rotates weekly)
/// Formula: hash(SEED ^ time_slot) ^ P2P_SEED
pub fn p2p_magic() -> u32 {
    let slot = time_slot(PERIOD_1_WEEK);
    hash_u64(get_master_seed() ^ slot) ^ P2P_SEED
}

/// Get LIPC protocol magic (rotates weekly)
/// Formula: hash(SEED ^ time_slot) ^ LIPC_SEED
pub fn lipc_magic() -> u32 {
    let slot = time_slot(PERIOD_1_WEEK);
    hash_u64(get_master_seed() ^ slot) ^ LIPC_SEED
}

/// Get covert handshake magic (rotates every 4 hours)
/// Formula: hash(SEED ^ time_slot) ^ HANDSHAKE_SEED
pub fn handshake_magic() -> u32 {
    let slot = time_slot(PERIOD_4_HOURS);
    hash_u64(get_master_seed() ^ slot) ^ HANDSHAKE_SEED
}

/// Get handshake XOR response magic (rotates every 4 hours)
/// Formula: hash(SEED ^ time_slot) ^ HANDSHAKE_XOR_SEED
pub fn handshake_xor() -> u32 {
    let slot = time_slot(PERIOD_4_HOURS);
    hash_u64(get_master_seed() ^ slot) ^ HANDSHAKE_XOR_SEED
}

/// Get magic for previous time slot (for tolerance)
pub fn p2p_magic_prev() -> u32 {
    let slot = time_slot(PERIOD_1_WEEK).saturating_sub(1);
    hash_u64(get_master_seed() ^ slot) ^ P2P_SEED
}

pub fn lipc_magic_prev() -> u32 {
    let slot = time_slot(PERIOD_1_WEEK).saturating_sub(1);
    hash_u64(get_master_seed() ^ slot) ^ LIPC_SEED
}

pub fn handshake_magic_prev() -> u32 {
    let slot = time_slot(PERIOD_4_HOURS).saturating_sub(1);
    hash_u64(get_master_seed() ^ slot) ^ HANDSHAKE_SEED
}

pub fn handshake_xor_prev() -> u32 {
    let slot = time_slot(PERIOD_4_HOURS).saturating_sub(1);
    hash_u64(get_master_seed() ^ slot) ^ HANDSHAKE_XOR_SEED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magics_are_different() {
        // P2P and LIPC should be different even in same time slot
        assert_ne!(p2p_magic(), lipc_magic());
        assert_ne!(handshake_magic(), handshake_xor());
    }

    #[test]
    fn test_magics_are_deterministic() {
        // Same call should return same value
        assert_eq!(p2p_magic(), p2p_magic());
        assert_eq!(lipc_magic(), lipc_magic());
    }
}
