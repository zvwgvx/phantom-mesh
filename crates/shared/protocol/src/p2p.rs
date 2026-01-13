use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use std::io::{self, Write};

pub const P2P_MAGIC: u32 = 0x9A1D3F7C;
pub const P2P_TYPE_GOSSIP: u8 = 1;
pub const P2P_TYPE_CMD: u8 = 2;

#[derive(Debug, Clone)]
pub enum P2PMessage {
    Gossip(Vec<u8>), // Placeholder for Gossip List
    Command(P2PCommand),
}

#[derive(Debug, Clone)]
pub struct P2PCommand {
    pub nonce: u32,
    pub signature: [u8; 64],
    pub payload: Vec<u8>,
}

impl P2PCommand {
    pub fn new(nonce: u32, payload: Vec<u8>, key: &SigningKey) -> Self {
        let mut cmd = Self {
            nonce,
            signature: [0u8; 64],
            payload,
        };
        cmd.sign(key);
        cmd
    }

    pub fn sign(&mut self, key: &SigningKey) {
        // Sign Payload Only (Matches C logic usually, but verify!)
        // C struct: nonce, sig, len, payload.
        // If C verifies signature over payload, we sign payload.
        // Assuming sign(payload) for now.
        let sig = key.sign(&self.payload);
        self.signature = sig.to_bytes();
    }
}

impl P2PMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // 1. Magic
        buf.write_u32::<BigEndian>(P2P_MAGIC).unwrap(); // 0-3
        
        match self {
            P2PMessage::Command(cmd) => {
                // 2. Type (CMD)
                buf.write_u8(P2P_TYPE_CMD).unwrap(); // 4
                
                // 3. Nonce
                buf.write_u32::<BigEndian>(cmd.nonce).unwrap(); // 5-8
                
                // 4. Signature
                buf.write_all(&cmd.signature).unwrap(); // 9-73
                
                // 5. Payload Len (u16)
                let len = cmd.payload.len() as u16;
                buf.write_u16::<BigEndian>(len).unwrap(); // 73-75
                
                // 6. Payload
                buf.write_all(&cmd.payload).unwrap(); // 75...
            }
            P2PMessage::Gossip(data) => {
                // 2. Type (GOSSIP)
                buf.write_u8(P2P_TYPE_GOSSIP).unwrap();
                // Reserved/Count logic here...
                // (Stub for now as C implementation of Gossip isn't fully analyzed)
                buf.extend_from_slice(data);
            }
        }
        buf
    }
}
