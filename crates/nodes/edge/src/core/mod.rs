//! # Core Module
//!
//! Core logic for the Edge node.

pub mod dedup;
pub mod runtime;

pub use dedup::Deduplicator;
pub use runtime::{run_leader_mode, run_worker_mode};
