//! ZHTP Blockchain Authentication Protocol
//!
//! Implements blockchain-based authentication for ZHTP mesh connections.
//! Uses post-quantum signatures (Dilithium) for challenge-response authentication.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use lib_crypto::{PublicKey, generate_nonce, hash_blake3};
use lib_crypto::post_quantum::dilithium::{dilithium_sign, dilithium_verify, dilithium2_keypair};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, debug, warn};

/// ZHTP authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpAuthChallenge {
    /// Random nonce to prevent replay attacks
    pub nonce: [u8; 32],
    /// Challenger's blockchain public key
    pub challenger_pubkey: Vec<u8>,
    /// Challenge timestamp
    pub timestamp: u64,
    /// Challenge ID for tracking
    pub challenge_id: String,
}

/// ZHTP authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpAuthResponse {
    /// Challenge ID being responded to
    pub challenge_id: String,
    /// Responder's blockchain public key
    pub responder_pubkey: Vec<u8>,
    /// Dilithium signature of (nonce + timestamp + challenger_pubkey)
    pub signature: Vec<u8>,
    /// Response timestamp
    pub timestamp: u64,
    /// Node capabilities advertised
    pub capabilities: NodeCapabilities,
}

/// Node capabilities for ZHTP mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Has DHT access
    pub has_dht: bool,
    /// Can relay traffic
    pub can_relay: bool,
    /// Maximum relay bandwidth (bytes/sec)
    pub max_bandwidth: u64,
    /// Supported protocols
    pub protocols: Vec<String>,
    /// Reputation score (0-100)
    pub reputation: u32,
    /// Post-quantum secure
    pub quantum_secure: bool,
}

/// ZHTP authentication verification result
#[derive(Debug, Clone)]
pub struct ZhtpAuthVerification {
    /// Authentication succeeded
    pub authenticated: bool,
    /// Peer's blockchain public key
    pub peer_pubkey: Vec<u8>,
    /// Peer's capabilities
    pub capabilities: NodeCapabilities,
    /// Trust score (0.0 - 1.0)
    pub trust_score: f64,
}

/// ZHTP Authentication Manager
#[derive(Debug)]
pub struct ZhtpAuthManager {
    /// This node's Dilithium keypair
    node_dilithium_keypair: (Vec<u8>, Vec<u8>), // (public_key, secret_key)
    /// This node's blockchain public key
    node_blockchain_pubkey: PublicKey,
    /// Active challenges (challenge_id -> challenge)
    active_challenges: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, ZhtpAuthChallenge>>>,
}

impl ZhtpAuthManager {
    /// Create new ZHTP authentication manager
    pub fn new(node_blockchain_pubkey: PublicKey) -> Result<Self> {
        info!(" Initializing ZHTP authentication manager with post-quantum security");
        
        // Generate Dilithium2 keypair for this node
        let dilithium_keypair = dilithium2_keypair();
        
        info!(" Generated Dilithium2 keypair (post-quantum secure)");
        debug!("   Public key length: {} bytes", dilithium_keypair.0.len());
        
        Ok(Self {
            node_dilithium_keypair: dilithium_keypair,
            node_blockchain_pubkey,
            active_challenges: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        })
    }
    
    /// Create authentication challenge for a peer
    pub async fn create_challenge(&self) -> Result<ZhtpAuthChallenge> {
        let nonce_12 = generate_nonce(); // Returns [u8; 12]
        // Extend to 32 bytes for challenge storage
        let mut nonce = [0u8; 32];
        nonce[..12].copy_from_slice(&nonce_12);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Generate unique challenge ID
        let challenge_id = hex::encode(hash_blake3(
            &[&nonce[..], &timestamp.to_le_bytes()].concat()
        ));
        
        let challenge = ZhtpAuthChallenge {
            nonce,
            challenger_pubkey: self.node_dilithium_keypair.0.clone(),
            timestamp,
            challenge_id: challenge_id.clone(),
        };
        
        // Store challenge for later verification
        self.active_challenges.write().await.insert(challenge_id.clone(), challenge.clone());
        
        info!(" Created ZHTP authentication challenge: {}", &challenge_id[..8]);
        
        Ok(challenge)
    }
    
    /// Sign arbitrary message with Dilithium2 (for PeerAnnouncement, etc.)
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        dilithium_sign(message, &self.node_dilithium_keypair.1)
    }
    
    /// Get this node's Dilithium2 public key
    pub fn get_dilithium_pubkey(&self) -> &[u8] {
        &self.node_dilithium_keypair.0
    }
    
    /// Respond to authentication challenge
    pub fn respond_to_challenge(
        &self,
        challenge: &ZhtpAuthChallenge,
        capabilities: NodeCapabilities,
    ) -> Result<ZhtpAuthResponse> {
        info!(" Responding to ZHTP authentication challenge: {}", &challenge.challenge_id[..8]);
        
        // Create message to sign: nonce + timestamp + challenger_pubkey
        let message = [
            challenge.nonce.as_slice(),
            &challenge.timestamp.to_le_bytes(),
            challenge.challenger_pubkey.as_slice(),
        ].concat();
        
        // Sign with Dilithium2
        let signature = dilithium_sign(&message, &self.node_dilithium_keypair.1)?;
        
        debug!(" Signed challenge with Dilithium2 (signature: {} bytes)", signature.len());
        
        let response = ZhtpAuthResponse {
            challenge_id: challenge.challenge_id.clone(),
            responder_pubkey: self.node_dilithium_keypair.0.clone(),
            signature,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            capabilities,
        };
        
        Ok(response)
    }
    
    /// Verify authentication response
    pub async fn verify_response(
        &self,
        response: &ZhtpAuthResponse,
    ) -> Result<ZhtpAuthVerification> {
        info!(" Verifying ZHTP authentication response: {}", &response.challenge_id[..8]);
        
        // Retrieve original challenge
        let challenge = {
            let challenges = self.active_challenges.read().await;
            challenges.get(&response.challenge_id)
                .cloned()
                .ok_or_else(|| anyhow!("Challenge not found or expired"))?
        };
        
        // Check timestamp freshness (5 minute window)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if current_time.saturating_sub(challenge.timestamp) > 300 {
            warn!(" Challenge expired (>5 minutes old)");
            return Ok(ZhtpAuthVerification {
                authenticated: false,
                peer_pubkey: response.responder_pubkey.clone(),
                capabilities: response.capabilities.clone(),
                trust_score: 0.0,
            });
        }
        
        // Recreate signed message
        let message = [
            challenge.nonce.as_slice(),
            &challenge.timestamp.to_le_bytes(),
            challenge.challenger_pubkey.as_slice(),
        ].concat();
        
        // Verify Dilithium2 signature
        let signature_valid = dilithium_verify(
            &message,
            &response.signature,
            &response.responder_pubkey,
        )?;
        
        if signature_valid {
            info!(" ZHTP authentication successful - post-quantum signature verified");
            
            // Calculate trust score based on capabilities
            let trust_score = self.calculate_trust_score(&response.capabilities);
            
            // Remove used challenge
            self.active_challenges.write().await.remove(&response.challenge_id);
            
            Ok(ZhtpAuthVerification {
                authenticated: true,
                peer_pubkey: response.responder_pubkey.clone(),
                capabilities: response.capabilities.clone(),
                trust_score,
            })
        } else {
            warn!(" ZHTP authentication failed - invalid signature");
            
            Ok(ZhtpAuthVerification {
                authenticated: false,
                peer_pubkey: response.responder_pubkey.clone(),
                capabilities: response.capabilities.clone(),
                trust_score: 0.0,
            })
        }
    }
    
    /// Calculate trust score based on capabilities and reputation
    fn calculate_trust_score(&self, capabilities: &NodeCapabilities) -> f64 {
        let mut score = 0.0;
        
        // Base reputation score (0-50)
        score += (capabilities.reputation as f64 / 100.0) * 0.5;
        
        // DHT capability (+20)
        if capabilities.has_dht {
            score += 0.2;
        }
        
        // Relay capability (+15)
        if capabilities.can_relay {
            score += 0.15;
        }
        
        // Post-quantum security (+15)
        if capabilities.quantum_secure {
            score += 0.15;
        }
        
        // Bandwidth capacity (0-10 based on bandwidth)
        let bandwidth_score = (capabilities.max_bandwidth as f64 / 10_000_000.0).min(1.0) * 0.1;
        score += bandwidth_score;
        
        score.min(1.0) // Cap at 1.0
    }
    
    /// Clean expired challenges (older than 5 minutes)
    pub async fn cleanup_expired_challenges(&self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut challenges = self.active_challenges.write().await;
        challenges.retain(|_, challenge| {
            current_time.saturating_sub(challenge.timestamp) <= 300
        });
    }
}

/// ZHTP authentication message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZhtpAuthMessage {
    /// Request authentication challenge
    ChallengeRequest {
        requester_pubkey: Vec<u8>,
    },
    /// Authentication challenge
    Challenge(ZhtpAuthChallenge),
    /// Authentication response
    Response(ZhtpAuthResponse),
    /// Authentication result
    Result {
        success: bool,
        reason: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_zhtp_authentication_flow() {
        // Create two auth managers (Node A and Node B)
        let node_a_pubkey = PublicKey::new(vec![1u8; 32]);
        let node_b_pubkey = PublicKey::new(vec![2u8; 32]);
        
        let node_a = ZhtpAuthManager::new(node_a_pubkey).unwrap();
        let node_b = ZhtpAuthManager::new(node_b_pubkey).unwrap();
        
        // Node A creates challenge
        let challenge = node_a.create_challenge().await.unwrap();
        
        // Node B responds to challenge
        let capabilities = NodeCapabilities {
            has_dht: true,
            can_relay: true,
            max_bandwidth: 5_000_000,
            protocols: vec!["bluetooth".to_string(), "wifi".to_string()],
            reputation: 75,
            quantum_secure: true,
        };
        
        let response = node_b.respond_to_challenge(&challenge, capabilities).unwrap();
        
        // Node A verifies response
        let verification = node_a.verify_response(&response).await.unwrap();
        
        assert!(verification.authenticated);
        assert!(verification.trust_score > 0.7); // Should have high trust score
        assert!(verification.capabilities.has_dht);
    }
}
