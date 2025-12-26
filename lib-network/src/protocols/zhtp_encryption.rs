//! ZHTP Post-Quantum Encryption for Mesh Connections
//!
//! Implements Kyber512 key exchange and AES-GCM encryption for secure mesh communication.
//! Uses lib-crypto's post-quantum cryptography and symmetric encryption.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use lib_crypto::post_quantum::kyber::{kyber512_keypair, kyber512_encapsulate, kyber512_decapsulate};
use lib_crypto::symmetric::chacha20::{encrypt_data, decrypt_data};
use tracing::{info, debug};
use std::time::{SystemTime, UNIX_EPOCH};

/// ZHTP encryption session for a mesh connection
#[derive(Debug, Clone)]
pub struct ZhtpEncryptionSession {
    /// Kyber512 public key (for this node)
    pub local_kyber_public: Vec<u8>,
    /// Kyber512 secret key (for this node)
    local_kyber_secret: Vec<u8>,
    /// Shared secret derived from Kyber KEM
    shared_secret: Option<[u8; 32]>,
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
        info!(" Creating new ZHTP encryption session with Kyber512");
        
        // Generate Kyber512 keypair
        let (kyber_public, kyber_secret) = kyber512_keypair();
        
        debug!("Generated Kyber512 keypair (public: {} bytes, secret: {} bytes)", 
               kyber_public.len(), kyber_secret.len());
        
        Ok(Self {
            local_kyber_public: kyber_public,
            local_kyber_secret: kyber_secret,
            shared_secret: None,
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
        
        info!(" Shared secret established (responder side)");
        
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
        
        info!(" Shared secret established (initiator side)");
        
        Ok(())
    }
    
    /// Get the shared secret (if established)
    pub fn get_shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }
    
    /// Encrypt message with ChaCha20-Poly1305 using shared secret
    pub fn encrypt_message(
        &mut self,
        session_id: String,
        plaintext: &[u8],
    ) -> Result<ZhtpEncryptedMessage> {
        let shared_secret = self.shared_secret
            .ok_or_else(|| anyhow!("Encryption session not established"))?;
        
        debug!(" Encrypting message ({} bytes) with ChaCha20-Poly1305", plaintext.len());

        // Encrypt with ChaCha20-Poly1305 using shared secret as key
        // Note: encrypt_data generates and prepends nonce internally
        let ciphertext = encrypt_data(plaintext, &shared_secret)?;

        self.messages_encrypted += 1;

        debug!(" Message encrypted (ciphertext: {} bytes)", ciphertext.len());

        Ok(ZhtpEncryptedMessage {
            session_id,
            ciphertext,
            nonce: vec![], // Nonce is embedded in ciphertext by encrypt_data
            sequence: self.messages_encrypted,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Decrypt message with ChaCha20-Poly1305 using shared secret
    pub fn decrypt_message(
        &mut self,
        encrypted_msg: &ZhtpEncryptedMessage,
    ) -> Result<Vec<u8>> {
        let shared_secret = self.shared_secret
            .ok_or_else(|| anyhow!("Encryption session not established"))?;
        
        debug!("🔓 Decrypting message ({} bytes) with ChaCha20-Poly1305",
               encrypted_msg.ciphertext.len());

        // Decrypt with ChaCha20-Poly1305
        // Note: decrypt_data extracts nonce from beginning of ciphertext
        let plaintext = decrypt_data(&encrypted_msg.ciphertext, &shared_secret)?;
        
        self.messages_decrypted += 1;
        
        debug!(" Message decrypted ({} bytes)", plaintext.len());
        
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
    
    /// Rotate session (generate new keypair, invalidate old shared secret)
    pub fn rotate_session(&mut self) -> Result<()> {
        info!(" Rotating ZHTP encryption session");
        
        // Generate new Kyber keypair
        let (kyber_public, kyber_secret) = kyber512_keypair();
        
        self.local_kyber_public = kyber_public;
        self.local_kyber_secret = kyber_secret;
        self.shared_secret = None; // Invalidate old shared secret
        
        info!(" Session rotated, new key exchange required");
        
        Ok(())
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
