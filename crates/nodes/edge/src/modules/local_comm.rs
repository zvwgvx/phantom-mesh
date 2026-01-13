use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use log::{info, error};
use std::os::unix::fs::PermissionsExt;
use std::mem::size_of;

// On Windows this would be Named Pipe. On Mac/Linux, UDS.
const SOCK_PATH: &str = "/tmp/phantom_edge.sock";

// LIPC Protocol Constants
pub const LIPC_MAGIC: u32 = 0xCAFEBABE;
pub const HEADER_SIZE: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LipcMsgType {
    Hello = 0x01,
    Data = 0x02,
    Heartbeat = 0x03,
}

impl LipcMsgType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(LipcMsgType::Hello),
            0x02 => Some(LipcMsgType::Data),
            0x03 => Some(LipcMsgType::Heartbeat),
            _ => None,
        }
    }
}

pub struct LipcHeader {
    pub magic: u32,
    pub length: u32,
    pub worker_id: u64,
    pub msg_type: LipcMsgType,
}

pub struct LocalTransport;

impl LocalTransport {
    pub async fn bind_server() -> Result<UnixListener, Box<dyn Error + Send + Sync>> {
        // Clean up old socket
        let _ = std::fs::remove_file(SOCK_PATH);

        let listener = UnixListener::bind(SOCK_PATH)?;
        
        let mut perms = std::fs::metadata(SOCK_PATH)?.permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(SOCK_PATH, perms)?;

        info!("[LocalComm] Bound UDS Server at {}", SOCK_PATH);
        Ok(listener)
    }

    pub async fn connect_client() -> Result<UnixStream, Box<dyn Error + Send + Sync>> {
        let stream = UnixStream::connect(SOCK_PATH).await?;
        info!("[LocalComm] Connected to Leader via UDS");
        Ok(stream)
    }

    /// Reads a full LIPC frame from the stream
    pub async fn read_frame(stream: &mut UnixStream) -> Result<(LipcHeader, Vec<u8>), Box<dyn Error + Send + Sync>> {
        let mut head_buf = [0u8; HEADER_SIZE];
        stream.read_exact(&mut head_buf).await?;

        let magic = u32::from_be_bytes(head_buf[0..4].try_into()?);
        if magic != LIPC_MAGIC {
            return Err("Invalid LIPC Magic".into());
        }

        let length = u32::from_be_bytes(head_buf[4..8].try_into()?);
        let worker_id = u64::from_be_bytes(head_buf[8..16].try_into()?);
        let msg_type = LipcMsgType::from_u8(head_buf[16]).ok_or("Invalid MsgType")?;

        let mut payload = vec![0u8; length as usize];
        if length > 0 {
            stream.read_exact(&mut payload).await?;
        }

        Ok((
            LipcHeader {
                magic,
                length,
                worker_id,
                msg_type,
            },
            payload,
        ))
    }

    /// Writes a full LIPC frame to the stream
    pub async fn write_frame(
        stream: &mut UnixStream,
        worker_id: u64,
        msg_type: LipcMsgType,
        payload: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
        
        buf.extend_from_slice(&LIPC_MAGIC.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&worker_id.to_be_bytes());
        buf.push(msg_type as u8);
        buf.extend_from_slice(payload);

        stream.write_all(&buf).await?;
        Ok(())
    }
}
