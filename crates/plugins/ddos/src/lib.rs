use plugin_api::HostContext;
use log::info;

/// DDoS Plugin Implementation
pub struct DdosPlugin {
    target_count: usize,
}

impl DdosPlugin {
    pub fn new() -> Self {
        Self { target_count: 0 }
    }

    pub fn opcode(&self) -> u8 {
        0x01
    }

    pub fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), String> {
        info!("plugin(ddos): payload {} bytes", cmd.len());
        Ok(())
    }
}

// Use the macro to generate FFI exports
plugin_api::declare_plugin!(DdosPlugin, "DDoS Plugin v2");
