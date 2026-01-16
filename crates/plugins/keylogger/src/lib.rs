use plugin_api::HostContext;
use log::info;

/// Keylogger Plugin Implementation
pub struct KeyloggerPlugin {
    buffer_size: usize,
}

impl KeyloggerPlugin {
    pub fn new() -> Self {
        Self { buffer_size: 4096 }
    }

    pub fn opcode(&self) -> u8 {
        0x07
    }

    pub fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), String> {
        info!("plugin(keylog): duration {} bytes", cmd.len());
        Ok(())
    }
}

plugin_api::declare_plugin!(KeyloggerPlugin, "Keylogger Plugin v2");
