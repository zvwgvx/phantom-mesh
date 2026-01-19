use plugin_api::HostContext;

struct DdosPlugin;

impl DdosPlugin {
    fn new() -> Self {
        Self
    }

    fn opcode(&self) -> u8 {
        0x01 // Magic opcode for DDoS, preserving it for now or changing to something valid?
             // Actually, the user wants it to be an "empty plugin".
             // Providing a valid opcode allows it to register, but execute does nothing.
    }

    fn execute(&self, _cmd: &[u8], _ctx: &HostContext) -> Result<(), ()> {
        // No-op execution
        Ok(())
    }
}

plugin_api::declare_plugin!(DdosPlugin, "ddos");
