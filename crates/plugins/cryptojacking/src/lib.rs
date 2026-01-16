use plugin_api::HostContext;
use log::info;

/// Cryptojacking Plugin Implementation
pub struct CryptoPlugin {
    wallet: String,
}

impl CryptoPlugin {
    pub fn new() -> Self {
        Self { wallet: String::new() }
    }

    pub fn opcode(&self) -> u8 {
        0x05
    }

    pub fn execute(&self, cmd: &[u8], _ctx: &HostContext) -> Result<(), String> {
        info!("plugin(crypto): config {} bytes", cmd.len());
        Ok(())
    }
}

plugin_api::declare_plugin!(CryptoPlugin, "Cryptojacking Plugin v2");
