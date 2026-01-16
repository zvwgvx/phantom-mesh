use std::collections::HashMap;
use libloading::{Library, Symbol};
use log::{info, error};
use plugin_api::{PluginHandle, PluginCreate, HostContext};

/// Manages the lifecycle of dynamic plugins (FFI-Safe Version)
/// 
/// IMPORTANT: Field order matters for Drop!
/// - registry MUST be declared BEFORE libraries
/// - This ensures plugin handles are destroyed BEFORE library unload
pub struct PluginManager {
    /// Map of Opcode -> Plugin Handle (dropped FIRST)
    registry: HashMap<u8, PluginHandle>,
    /// Loaded libraries - kept alive until after handles are destroyed
    libraries: Vec<Library>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            libraries: Vec::new(),
            registry: HashMap::new(),
        }
    }

    /// Load a plugin from a file path (.dll / .so)
    pub unsafe fn load_plugin(&mut self, path: &str) -> Result<(), String> {
        info!("plugin: loading {}", path);
        
        let lib = Library::new(path).map_err(|e| format!("load: {}", e))?;
        
        // Find the constructor symbol
        let constructor: Symbol<PluginCreate> = lib.get(b"_create_plugin\0")
            .map_err(|e| format!("symbol: {}", e))?;

        // Create the plugin handle (FFI-safe struct)
        let handle = constructor();

        info!("plugin: '{}' -> 0x{:02X}", handle.name(), handle.opcode());
        
        // Register
        self.registry.insert(handle.opcode(), handle);
        self.libraries.push(lib);

        Ok(())
    }

    /// Dispatch a command to the appropriate plugin
    pub fn handle_command(&self, opcode: u8, payload: &[u8]) -> bool {
        if let Some(handle) = self.registry.get(&opcode) {
            info!("plugin: exec '{}' (0x{:02X})", handle.name(), opcode);
            
            let ctx = HostContext::default();

            match handle.execute(payload, &ctx) {
                Ok(_) => info!("plugin: ok"),
                Err(e) => error!("plugin: {}", e),
            }
            true
        } else {
            false 
        }
    }
}
