//! ZHTP Relay Protocol Implementation
//!
//! Secure DHT content relay through authenticated mesh peers.
//! Combines Dilithium2 signatures with Kyber-encrypted channels.

use anyhow::{Result, anyhow};
use lib_crypto::post_quantum::dilithium::{dilithium2_sign, dilithium2_verify};
use lib_crypto::hashing::hash_blake3;
use lib_crypto::Hash;
use tracing::{info, debug, warn};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocols::zhtp_auth::NodeCapabilities;
use crate::protocols::zhtp_encryption::ZhtpEncryptionManager;
use super::protocol::{
    ZhtpRelayQuery, ZhtpRelayResponse, ZhtpRelayQueryPayload, ZhtpRelayResponsePayload,
    ZhtpQueryOptions, CachePreference,
};

/// ZHTP Relay Protocol Handler
#[derive(Debug)]
pub struct ZhtpRelayProtocol {
    /// Encryption manager for secure channels
    encryption_manager: ZhtpEncryptionManager,
    /// This node's Dilithium signing key
    dilithium_secret_key: Vec<u8>,
    /// This node's Dilithium public key
    dilithium_public_key: Vec<u8>,
    /// This node's capabilities
    node_capabilities: NodeCapabilities,
}

impl ZhtpRelayProtocol {
    /// Create new ZHTP relay protocol handler
    pub fn new(
        dilithium_secret_key: Vec<u8>,
        dilithium_public_key: Vec<u8>,
        node_capabilities: NodeCapabilities,
    ) -> Self {
        info!(" Initializing ZHTP relay protocol with post-quantum security");
        
        Self {
            encryption_manager: ZhtpEncryptionManager::new(),
            dilithium_secret_key,
            dilithium_public_key,
            node_capabilities,
        }
    }
    
    /// Create relay query (Node B -> Node A: request content)
    pub async fn create_relay_query(
        &self,
        peer_address: &str,
        domain: &str,
        path: &str,
        options: ZhtpQueryOptions,
    ) -> Result<ZhtpRelayQuery> {
        info!(" Creating ZHTP relay query for {}:{} via peer {}", domain, path, peer_address);
        
        // Generate unique request ID
        let request_id = format!(
            "{}-{}",
            hex::encode(&hash_blake3(format!("{}{}{}", domain, path, peer_address).as_bytes())[..16]),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        );
        
        // Create query payload
        let query_payload = ZhtpRelayQueryPayload {
            domain: domain.to_string(),
            path: path.to_string(),
            options,
        };
        
        // Serialize and encrypt payload
        let payload_bytes = serde_json::to_vec(&query_payload)?;
        let encrypted_payload = self.encryption_manager
            .encrypt_for_peer(peer_address, &payload_bytes)
            .await?;
        
        // Create signature message: request_id + domain + path + timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let signature_message = [
            request_id.as_bytes(),
            domain.as_bytes(),
            path.as_bytes(),
            &timestamp.to_le_bytes(),
        ].concat();
        
        // Sign with Dilithium2
        let signature = dilithium2_sign(&signature_message, &self.dilithium_secret_key)?;
        
        debug!(" Relay query created and signed (request_id: {})", &request_id[..16]);
        
        Ok(ZhtpRelayQuery {
            request_id,
            domain: domain.to_string(),
            path: path.to_string(),
            requester_pubkey: self.dilithium_public_key.clone(),
            encrypted_payload,
            signature,
            timestamp,
        })
    }
    
    /// Verify and process relay query (Node A: receive request)
    pub async fn process_relay_query(
        &self,
        peer_address: &str,
        query: &ZhtpRelayQuery,
    ) -> Result<ZhtpRelayQueryPayload> {
        info!(" Processing ZHTP relay query from peer: {}", peer_address);
        
        // Verify signature
        let signature_message = [
            query.request_id.as_bytes(),
            query.domain.as_bytes(),
            query.path.as_bytes(),
            &query.timestamp.to_le_bytes(),
        ].concat();
        
        let signature_valid = dilithium2_verify(
            &signature_message,
            &query.signature,
            &query.requester_pubkey,
        )?;
        
        if !signature_valid {
            warn!(" Invalid signature on relay query from {}", peer_address);
            return Err(anyhow!("Invalid relay query signature"));
        }
        
        debug!(" Relay query signature verified");
        
        // Decrypt payload
        let payload_bytes = self.encryption_manager
            .decrypt_from_peer(peer_address, &query.encrypted_payload)
            .await?;
        
        let query_payload: ZhtpRelayQueryPayload = serde_json::from_slice(&payload_bytes)?;
        
        info!(" Relay query decrypted: {} {} (request: {})", 
              query_payload.domain, query_payload.path, &query.request_id[..16]);
        
        Ok(query_payload)
    }
    
    /// Create relay response (Node A -> Node B: return content)
    pub async fn create_relay_response(
        &self,
        peer_address: &str,
        request_id: String,
        response_payload: ZhtpRelayResponsePayload,
    ) -> Result<ZhtpRelayResponse> {
        info!(" Creating ZHTP relay response for request: {}", &request_id[..16]);
        
        // Serialize and encrypt response payload
        let payload_bytes = serde_json::to_vec(&response_payload)?;
        let encrypted_content = self.encryption_manager
            .encrypt_for_peer(peer_address, &payload_bytes)
            .await?;
        
        // Extract content hash for signature
        let content_hash = response_payload.content_hash.clone();
        
        // Create signature message: request_id + content_hash + timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut signature_message = Vec::new();
        signature_message.extend_from_slice(request_id.as_bytes());
        if let Some(ref hash) = content_hash {
            signature_message.extend_from_slice(hash.as_bytes());
        }
        signature_message.extend_from_slice(&timestamp.to_le_bytes());
        
        // Sign with Dilithium2
        let signature = dilithium2_sign(&signature_message, &self.dilithium_secret_key)?;
        
        debug!(" Relay response created and signed");
        
        Ok(ZhtpRelayResponse {
            request_id,
            found: response_payload.content.is_some(),
            content_hash,
            content_type: response_payload.content_type.clone(),
            responder_pubkey: self.dilithium_public_key.clone(),
            encrypted_content,
            signature,
            timestamp,
            relay_capabilities: self.node_capabilities.clone(),
        })
    }
    
    /// Verify and process relay response (Node B: receive content)
    pub async fn process_relay_response(
        &self,
        peer_address: &str,
        response: &ZhtpRelayResponse,
    ) -> Result<ZhtpRelayResponsePayload> {
        info!(" Processing ZHTP relay response from peer: {}", peer_address);
        
        // Verify signature
        let mut signature_message = Vec::new();
        signature_message.extend_from_slice(response.request_id.as_bytes());
        if let Some(ref hash) = response.content_hash {
            signature_message.extend_from_slice(hash.as_bytes());
        }
        signature_message.extend_from_slice(&response.timestamp.to_le_bytes());
        
        let signature_valid = dilithium2_verify(
            &signature_message,
            &response.signature,
            &response.responder_pubkey,
        )?;
        
        if !signature_valid {
            warn!(" Invalid signature on relay response from {}", peer_address);
            return Err(anyhow!("Invalid relay response signature"));
        }
        
        debug!(" Relay response signature verified");
        
        // Decrypt content
        let payload_bytes = self.encryption_manager
            .decrypt_from_peer(peer_address, &response.encrypted_content)
            .await?;
        
        let response_payload: ZhtpRelayResponsePayload = serde_json::from_slice(&payload_bytes)?;
        
        // Verify content hash if content present
        if let Some(ref content) = response_payload.content {
            if let Some(ref expected_hash) = response_payload.content_hash {
                let actual_hash = Hash::from_bytes(&hash_blake3(content));
                if actual_hash != *expected_hash {
                    warn!(" Content hash mismatch!");
                    return Err(anyhow!("Content integrity check failed"));
                }
            }
        }
        
        info!(" Relay response decrypted and verified (content: {} bytes)", 
              response_payload.content.as_ref().map(|c| c.len()).unwrap_or(0));
        
        Ok(response_payload)
    }
    
    /// Get encryption manager (for key exchange)
    pub fn get_encryption_manager(&self) -> &ZhtpEncryptionManager {
        &self.encryption_manager
    }
}

/// Default query options
impl Default for ZhtpQueryOptions {
    fn default() -> Self {
        Self {
            max_size: Some(10 * 1024 * 1024), // 10 MB default
            accept_compression: true,
            cache_preference: CachePreference::PreferCache,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::post_quantum::dilithium::dilithium2_keypair;
    
    #[tokio::test]
    async fn test_zhtp_relay_flow() -> Result<()> {
        // Create two relay protocol handlers (Node A and Node B)
        let (node_a_pubkey, node_a_secret) = dilithium2_keypair();
        let (node_b_pubkey, node_b_secret) = dilithium2_keypair();
        
        let node_a_caps = NodeCapabilities {
            has_dht: true,
            can_relay: true,
            max_bandwidth: 5_000_000,
            protocols: vec!["bluetooth".into()],
            reputation: 90,
            quantum_secure: true,
        };
        
        let node_b_caps = NodeCapabilities {
            has_dht: false,
            can_relay: false,
            max_bandwidth: 1_000_000,
            protocols: vec!["bluetooth".into()],
            reputation: 50,
            quantum_secure: true,
        };
        
        let node_a = ZhtpRelayProtocol::new(node_a_secret, node_a_pubkey, node_a_caps);
        let node_b = ZhtpRelayProtocol::new(node_b_secret, node_b_pubkey, node_b_caps);

        // Establish encryption session between nodes
        let peer_a = "node_a";
        let peer_b = "node_b";

        // Node B initiates key exchange with Node A
        let init = node_b.get_encryption_manager().create_session(peer_a.to_string()).await?;

        // Node A responds to key exchange
        let response = node_a.get_encryption_manager().respond_to_key_exchange(peer_b.to_string(), &init).await?;

        // Node B completes key exchange
        node_b.get_encryption_manager().complete_key_exchange(peer_a, &response).await?;

        // Now Node B can create encrypted relay query to Node A
        let query = node_b.create_relay_query(
            peer_a,
            "hello-world.zhtp",
            "/index.html",
            ZhtpQueryOptions::default(),
        ).await;
        
        // In implementation, this would work after key exchange
        // For now, test signature verification logic
        if let Err(e) = &query {
            eprintln!("Query error: {}", e);
        }
        assert!(query.is_ok());
        
        Ok(())
    }
}
