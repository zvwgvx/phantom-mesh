use tokio::net::UnixStream;
use tokio::sync::mpsc;
use std::sync::Arc;
use log::{info, error, debug, warn};
use crate::modules::local_comm::{LocalTransport, LipcMsgType};

pub struct BridgeService {
    cloud_tx: mpsc::Sender<Vec<u8>>,
}

impl BridgeService {
    pub fn new(cloud_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { cloud_tx }
    }

    /// Handle a new Worker connection (UDS) with LIPC Framing
    pub async fn handle_worker(&self, mut stream: UnixStream) {
        info!("[Bridge] New Worker Connected. Waiting for LIPC Handshake...");
        
        loop {
            // 1. Read LIPC Frame
            match LocalTransport::read_frame(&mut stream).await {
                Ok((header, payload)) => {
                    debug!("[Bridge] Recv Frame: Type={:?} ID={} Len={}", header.msg_type, header.worker_id, header.length);

                    match header.msg_type {
                        LipcMsgType::Hello => {
                            info!("[Bridge] Worker {} Registered via Hello", header.worker_id);
                        }
                        LipcMsgType::Heartbeat => {
                             debug!("[Bridge] Heartbeat from {}", header.worker_id);
                        }
                        LipcMsgType::Data => {
                            // 2. Multiplex & Forward to Cloud via Channel
                            let mut mux_payload = Vec::with_capacity(8 + payload.len());
                            mux_payload.extend_from_slice(&header.worker_id.to_be_bytes());
                            mux_payload.extend_from_slice(&payload);
                            
                            info!("[Bridge] Forwarding {} bytes for Worker {}", payload.len(), header.worker_id);
                            
                            if let Err(_) = self.cloud_tx.send(mux_payload).await {
                                error!("[Bridge] Failed to forward to Cloud: Channel Closed");
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("[Bridge] Worker Disconnected or Protocol Error: {}", e);
                    return;
                }
            }
        }
    }
}
