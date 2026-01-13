use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use russh::{server, Channel, ChannelId, CryptoVec};
use russh_keys::key;
use log::{info, error};

// Shared State for the C2
pub struct ServerState {
    pub clients: HashMap<ChannelId, usize>, // Just tracking IDs for now
}

#[derive(Clone)]
pub struct PhantomServer {
    pub state: Arc<Mutex<ServerState>>,
    pub master_key: Arc<ed25519_dalek::SigningKey>,
}

impl PhantomServer {
    pub fn new(master_key: Arc<ed25519_dalek::SigningKey>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState { clients: HashMap::new() })),
            master_key,
        }
    }
}

pub struct PhantomSession {
    pub state: Arc<Mutex<ServerState>>,
    pub master_key: Arc<ed25519_dalek::SigningKey>,
}

#[async_trait]
impl server::Handler for PhantomSession {
    type Error = anyhow::Error;

    // Correct Signature: self (owned), channel (owned), session (owned) -> Result<(Self, bool, Session)>
    async fn channel_open_session(
        self,
        _channel: Channel<server::Msg>,
        session: server::Session,
    ) -> Result<(Self, bool, server::Session), Self::Error> {
        info!("SSH Session Opened!");
        Ok((self, true, session))
    }

    async fn auth_publickey(
        self,
        user: &str,
        _public_key: &key::PublicKey,
    ) -> Result<(Self, server::Auth), Self::Error> {
        info!("Auth Public Key: {}", user);
        // Accept all for prototype
        Ok((self, server::Auth::Accept))
    }

    async fn auth_password(
        self,
        user: &str,
        _password: &str,
    ) -> Result<(Self, server::Auth), Self::Error> {
        info!("Auth Password: {}", user);
         if user == "admin" {
             Ok((self, server::Auth::Accept))
         } else {
             // For simplicity in prototype, accept anyway or reject logging.
             // Usually returns Auth::Reject { proceed_with_methods: None }
             Ok((self, server::Auth::Reject { proceed_with_methods: None }))
         }
    }

    async fn data(
        self,
        channel: ChannelId,
        data: &[u8],
        mut session: server::Session,
    ) -> Result<(Self, server::Session), Self::Error> {
        let text = String::from_utf8_lossy(data);
        // We need to act on the session here.
        // Logic similar to previous, but session is owned mutably inside the scope?
        // Wait, argument is `mut session: Session`.
        
        let cmd = text.trim();
        if !cmd.is_empty() {
             info!("Example C2 Command: {}", cmd);
             let response = format!("PhantomC2> Received: {}\r\n", cmd);
             session.data(channel, CryptoVec::from_slice(response.as_bytes()));
             
             if cmd == "help" {
                  session.data(channel, CryptoVec::from_slice(b"Available: attack <ip> <port> <duration>\r\n"));
             } else if cmd.starts_with("attack ") {
                  session.data(channel, CryptoVec::from_slice(b"[+] Attack Injected (Simulation)\r\n"));
                  info!("Injected Attack via SSH Command");
             }
             
             session.data(channel, CryptoVec::from_slice(b"PhantomC2$ "));
        }
        
        Ok((self, session))
    }
}
