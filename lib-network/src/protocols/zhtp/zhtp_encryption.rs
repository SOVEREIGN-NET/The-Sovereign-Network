//! ZHTP Post-Quantum Encryption for Mesh Connections
//!
//! Implements Kyber512 key exchange and ChaCha20Poly1305 AEAD encryption for secure mesh communication.
//! Uses lib-crypto's post-quantum cryptography and unified ProtocolEncryption trait.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use lib_crypto::post_quantum::kyber::{kyber512_keypair, kyber512_encapsulate, kyber512_decapsulate};
use crate::protocols::zhtp_mesh_encryption::ZhtpMeshEncryption;
use tracing::{info, debug};
use std::time::{SystemTime, UNIX_EPOCH};

/// ZHTP encryption session for a mesh connection
///
/// NOTE: No Clone or Debug derive because ZhtpMeshEncryption (ChaCha20Poly1305 state)
/// cannot be safely cloned or debugged. Use Arc<Mutex<>> if sharing across threads is needed.
pub struct ZhtpEncryptionSession {
    /// Kyber512 public key (for this node)
    pub local_kyber_public: Vec<u8>,
    /// Kyber512 secret key (for this node)
    local_kyber_secret: Vec<u8>,
    /// Shared secret derived from Kyber KEM
    shared_secret: Option<[u8; 32]>,
    /// ZHTP mesh encryption adapter with message-type domain separation
    encryption: Option<ZhtpMeshEncryption>,
    /// Session established timestamp
    pub session_start: u64,
    /// Total messages encrypted
    pub messages_encrypted: u64,
    /// Total messages decrypted
    pub messages_decrypted: u64,
}

/// Kyber key exchange initiation message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpKeyExchangeInit {
    /// Sender's Kyber512 public key
    pub kyber_public_key: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Session ID for tracking
    pub session_id: String,
}

/// Kyber key exchange response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpKeyExchangeResponse {
    /// Session ID being responded to
    pub session_id: String,
    /// Kyber512 ciphertext (encapsulated shared secret)
    pub kyber_ciphertext: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Encrypted ZHTP message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpEncryptedMessage {
    /// Session ID this message belongs to
    pub session_id: String,
    /// Encrypted payload (ChaCha20-Poly1305)
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
    /// Message sequence number (for replay protection)
    pub sequence: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl ZhtpEncryptionSession {
    /// Create new encryption session with fresh Kyber keypair
    pub fn new() -> Result<Self> {
        info!(" Creating new ZHTP encryption session with Kyber512 + ChaCha20Poly1305");

        // Generate Kyber512 keypair
        let (kyber_public, kyber_secret) = kyber512_keypair();

        debug!("Generated Kyber512 keypair (public: {} bytes, secret: {} bytes)",
               kyber_public.len(), kyber_secret.len());

        Ok(Self {
            local_kyber_public: kyber_public,
            local_kyber_secret: kyber_secret,
            shared_secret: None,
            encryption: None,
            session_start: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            messages_encrypted: 0,
            messages_decrypted: 0,
        })
    }
    
    /// Initiate key exchange with peer
    pub fn create_key_exchange_init(&self, session_id: String) -> Result<ZhtpKeyExchangeInit> {
        info!(" Creating Kyber key exchange initiation for session: {}", &session_id[..8]);
        
        Ok(ZhtpKeyExchangeInit {
            kyber_public_key: self.local_kyber_public.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            session_id,
        })
    }
    
    /// Respond to key exchange from peer (encapsulate shared secret)
    pub fn respond_to_key_exchange(
        &mut self,
        init: &ZhtpKeyExchangeInit,
    ) -> Result<ZhtpKeyExchangeResponse> {
        info!(" Responding to Kyber key exchange for session: {}", &init.session_id[..8]);

        // Encapsulate shared secret with peer's public key
        // NOTE: kdf_info must match the one used in complete_key_exchange by the initiator
        let kdf_info = b"ZHTP-KEM-v1.0";
        let (ciphertext, shared_secret) = kyber512_encapsulate(&init.kyber_public_key, kdf_info)?;

        debug!("Encapsulated shared secret (ciphertext: {} bytes)", ciphertext.len());

        // Store shared secret
        self.shared_secret = Some(shared_secret);

        // Initialize encryption adapter with shared secret and session_id
        let mut session_id_bytes = [0u8; 16];
        let session_bytes = init.session_id.as_bytes();
        let copy_len = std::cmp::min(session_bytes.len(), 16);
        session_id_bytes[..copy_len].copy_from_slice(&session_bytes[..copy_len]);

        self.encryption = Some(ZhtpMeshEncryption::new(&shared_secret, session_id_bytes)?);

        info!(" Shared secret established with ChaCha20Poly1305 AEAD (responder side)");

        Ok(ZhtpKeyExchangeResponse {
            session_id: init.session_id.clone(),
            kyber_ciphertext: ciphertext,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Complete key exchange (decapsulate shared secret)
    pub fn complete_key_exchange(
        &mut self,
        response: &ZhtpKeyExchangeResponse,
    ) -> Result<()> {
        info!("🔓 Completing Kyber key exchange for session: {}", &response.session_id[..8]);

        // Decapsulate shared secret with our secret key
        let kdf_info = b"ZHTP-KEM-v1.0";
        let shared_secret = kyber512_decapsulate(
            &response.kyber_ciphertext,
            &self.local_kyber_secret,
            kdf_info,
        )?;

        // Store shared secret
        self.shared_secret = Some(shared_secret);

        // Initialize encryption adapter with shared secret and session_id
        let mut session_id_bytes = [0u8; 16];
        let session_bytes = response.session_id.as_bytes();
        let copy_len = std::cmp::min(session_bytes.len(), 16);
        session_id_bytes[..copy_len].copy_from_slice(&session_bytes[..copy_len]);

        self.encryption = Some(ZhtpMeshEncryption::new(&shared_secret, session_id_bytes)?);

        info!(" Shared secret established with ChaCha20Poly1305 AEAD (initiator side)");

        Ok(())
    }
    
    /// Get the shared secret (if established)
    pub fn get_shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }
    
    /// Encrypt message with ChaCha20-Poly1305 AEAD via ZhtpMeshEncryption adapter
    pub fn encrypt_message(
        &mut self,
        session_id: String,
        plaintext: &[u8],
    ) -> Result<ZhtpEncryptedMessage> {
        let encryption = self.encryption
            .as_ref()
            .ok_or_else(|| anyhow!("Encryption session not established"))?;

        debug!(" Encrypting ZHTP mesh message ({} bytes) with ChaCha20-Poly1305", plaintext.len());

        // Encrypt with ChaCha20-Poly1305 via adapter with message-type aware AAD
        // Message type "mesh_payload" ensures domain separation from other ZHTP message types
        let ciphertext = encryption.encrypt_message(plaintext, "mesh_payload")?;

        self.messages_encrypted += 1;

        debug!(" ZHTP message encrypted (ciphertext: {} bytes)", ciphertext.len());

        Ok(ZhtpEncryptedMessage {
            session_id,
            ciphertext,
            nonce: vec![], // Nonce is embedded in wire format by adapter
            sequence: self.messages_encrypted,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Decrypt message with ChaCha20-Poly1305 AEAD via ZhtpMeshEncryption adapter
    pub fn decrypt_message(
        &mut self,
        encrypted_msg: &ZhtpEncryptedMessage,
    ) -> Result<Vec<u8>> {
        let encryption = self.encryption
            .as_ref()
            .ok_or_else(|| anyhow!("Encryption session not established"))?;

        debug!("🔓 Decrypting ZHTP mesh message ({} bytes) with ChaCha20-Poly1305",
               encrypted_msg.ciphertext.len());

        // Decrypt with ChaCha20-Poly1305 via adapter
        // Message type "mesh_payload" must match encryption, or decryption fails due to AAD mismatch
        let plaintext = encryption.decrypt_message(&encrypted_msg.ciphertext, "mesh_payload")?;

        self.messages_decrypted += 1;

        debug!(" ZHTP message decrypted ({} bytes)", plaintext.len());

        Ok(plaintext)
    }
    
    /// Check if encryption session is established
    pub fn is_established(&self) -> bool {
        self.shared_secret.is_some()
    }
    
    /// Get session statistics
    pub fn get_stats(&self) -> (u64, u64, u64) {
        (self.session_start, self.messages_encrypted, self.messages_decrypted)
    }
    
    /// Rotate session (generate new keypair, invalidate old shared secret and encryption)
    pub fn rotate_session(&mut self) -> Result<()> {
        info!(" Rotating ZHTP encryption session");

        // Generate new Kyber keypair
        let (kyber_public, kyber_secret) = kyber512_keypair();

        self.local_kyber_public = kyber_public;
        self.local_kyber_secret = kyber_secret;
        self.shared_secret = None; // Invalidate old shared secret
        self.encryption = None;    // Invalidate old encryption adapter

        info!(" Session rotated, new key exchange required");

        Ok(())
    }
}

impl std::fmt::Debug for ZhtpEncryptionSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZhtpEncryptionSession")
            .field("local_kyber_public", &format!("[{} bytes]", self.local_kyber_public.len()))
            .field("shared_secret", &self.shared_secret.as_ref().map(|_| "<secret>"))
            .field("encryption", &"<ChaCha20Poly1305>")
            .field("session_start", &self.session_start)
            .field("messages_encrypted", &self.messages_encrypted)
            .field("messages_decrypted", &self.messages_decrypted)
            .finish()
    }
}

/// ZHTP encryption manager for managing multiple sessions
#[derive(Debug)]
pub struct ZhtpEncryptionManager {
    /// Active encryption sessions (peer_address -> session)
    sessions: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, ZhtpEncryptionSession>>>,
}

impl ZhtpEncryptionManager {
    /// Create new encryption manager
    pub fn new() -> Self {
        Self {
            sessions: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }
    
    /// Create new session for peer
    pub async fn create_session(&self, peer_address: String) -> Result<ZhtpKeyExchangeInit> {
        let session = ZhtpEncryptionSession::new()?;
        let session_id = format!("{}:{}", peer_address, session.session_start);
        let init = session.create_key_exchange_init(session_id)?;
        
        self.sessions.write().await.insert(peer_address, session);
        
        Ok(init)
    }
    
    /// Respond to key exchange and store session
    pub async fn respond_to_key_exchange(
        &self,
        peer_address: String,
        init: &ZhtpKeyExchangeInit,
    ) -> Result<ZhtpKeyExchangeResponse> {
        let mut session = ZhtpEncryptionSession::new()?;
        let response = session.respond_to_key_exchange(init)?;
        
        self.sessions.write().await.insert(peer_address, session);
        
        Ok(response)
    }
    
    /// Complete key exchange for existing session
    pub async fn complete_key_exchange(
        &self,
        peer_address: &str,
        response: &ZhtpKeyExchangeResponse,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(peer_address)
            .ok_or_else(|| anyhow!("No session found for peer: {}", peer_address))?;
        
        session.complete_key_exchange(response)?;
        
        Ok(())
    }
    
    /// Encrypt message for peer
    pub async fn encrypt_for_peer(
        &self,
        peer_address: &str,
        plaintext: &[u8],
    ) -> Result<ZhtpEncryptedMessage> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(peer_address)
            .ok_or_else(|| anyhow!("No session found for peer: {}", peer_address))?;
        
        let session_id = format!("{}:{}", peer_address, session.session_start);
        session.encrypt_message(session_id, plaintext)
    }
    
    /// Decrypt message from peer
    pub async fn decrypt_from_peer(
        &self,
        peer_address: &str,
        encrypted_msg: &ZhtpEncryptedMessage,
    ) -> Result<Vec<u8>> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(peer_address)
            .ok_or_else(|| anyhow!("No session found for peer: {}", peer_address))?;
        
        session.decrypt_message(encrypted_msg)
    }
    
    /// Check if session exists for peer
    pub async fn has_session(&self, peer_address: &str) -> bool {
        self.sessions.read().await.contains_key(peer_address)
    }
    
    /// Remove session for peer
    pub async fn remove_session(&self, peer_address: &str) {
        self.sessions.write().await.remove(peer_address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[ignore] // Ignore crypto-library dependent test
    async fn test_zhtp_encryption_flow() -> Result<()> {
        // Create two sessions (Alice and Bob)
        let mut alice_session = ZhtpEncryptionSession::new()?;
        let mut bob_session = ZhtpEncryptionSession::new()?;

        // Alice initiates key exchange
        let session_id = "test-session".to_string();
        let init = alice_session.create_key_exchange_init(session_id.clone())?;

        // Bob responds and establishes shared secret
        let response = bob_session.respond_to_key_exchange(&init)?;
        assert!(bob_session.is_established());
        
        // Alice completes key exchange
        alice_session.complete_key_exchange(&response)?;
        assert!(alice_session.is_established());
        
        // Test encryption/decryption
        let plaintext = b"Hello from Alice to Bob via ZHTP!";
        let encrypted = alice_session.encrypt_message(session_id, plaintext)?;
        let decrypted = bob_session.decrypt_message(&encrypted)?;
        
        assert_eq!(plaintext, decrypted.as_slice());
        
        Ok(())
    }
}
