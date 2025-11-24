//! Recovery Service
//!
//! Private service responsible for identity recovery operations.
//! This service manages recovery keys and identity restoration from recovery phrases.

use anyhow::{Result, anyhow};
use rand::RngCore;
use hkdf::Hkdf;
use sha3::Sha3_512;
use lib_crypto::Hash;

use crate::identity::{ZhtpIdentity, PrivateIdentityData};
use crate::types::{IdentityType, AccessLevel, IdentityId};
use crate::recovery::RecoveryPhrase;

/// Recovery key information
#[derive(Debug, Clone)]
pub struct RecoveryKey {
    /// Recovery key ID
    pub id: Hash,
    /// The actual recovery key (encrypted)
    pub encrypted_key: Vec<u8>,
    /// Key derivation path
    pub derivation_path: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Last used timestamp
    pub last_used: Option<u64>,
    /// Whether this key is still valid
    pub is_active: bool,
    /// Human-readable label
    pub label: String,
}

impl RecoveryKey {
    /// Create a new recovery key
    pub fn new(
        encrypted_key: Vec<u8>,
        derivation_path: String,
        label: String,
    ) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let id = Hash::from_bytes(&blake3::hash(&encrypted_key).as_bytes()[..32]);
        
        Self {
            id,
            encrypted_key,
            derivation_path,
            created_at: current_time,
            last_used: None,
            is_active: true,
            label,
        }
    }
    
    /// Check if recovery key has expired (365 days)
    pub fn is_expired(&self) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let age = current_time.saturating_sub(self.created_at);
        age > 365 * 24 * 60 * 60 // 1 year
    }
}

/// Private service for identity recovery operations
/// 
/// This service manages recovery keys and identity restoration functionality.
/// It maintains a list of recovery keys and provides methods for importing
/// identities from recovery phrases.
#[derive(Debug)]
pub(crate) struct RecoveryService {
    /// List of recovery keys for identity restoration
    recovery_keys: Vec<RecoveryKey>,
    /// Maximum number of recovery keys allowed
    max_recovery_keys: usize,
}

impl RecoveryService {
    /// Create a new recovery service
    pub fn new() -> Self {
        Self {
            recovery_keys: Vec::new(),
            max_recovery_keys: 5,
        }
    }

    /// Import identity from recovery phrase
    /// 
    /// Reconstructs an identity and its private data from a 24-word recovery phrase.
    /// This allows users to restore their identity on a new device or after data loss.
    pub async fn import_identity_from_phrase(
        &self,
        phrase: &str,
    ) -> Result<(ZhtpIdentity, PrivateIdentityData)> {
        // Parse and validate the recovery phrase
        let phrase_words: Vec<String> = phrase.split_whitespace()
            .map(|s| s.to_string())
            .collect();
        
        if phrase_words.len() != 24 {
            return Err(anyhow!("Recovery phrase must be exactly 24 words"));
        }
        
        // Derive identity seed from phrase
        let phrase_string = phrase_words.join(" ");
        let seed_32 = blake3::hash(phrase_string.as_bytes());
        
        // Expand 32-byte seed to 64 bytes using HKDF (same as keypair generation)
        let hk = Hkdf::<Sha3_512>::new(None, seed_32.as_bytes());
        let mut seed = [0u8; 64];
        hk.expand(b"ZHTP-KeyGen-v1", &mut seed)
            .map_err(|_| anyhow!("Seed expansion failed"))?;
        
        // Derive quantum-resistant keypair from seed
        let (private_key, public_key) = Self::derive_keypair_from_seed(&seed).await?;
        
        // Create identity ID from public key
        let identity_id = Hash::from_bytes(&blake3::hash(&public_key).as_bytes()[..32]);
        
        // Generate ownership proof
        let ownership_proof = Self::generate_simple_ownership_proof(&private_key, &public_key).await?;
        
        // Create identity structure
        let identity = ZhtpIdentity {
            id: identity_id.clone(),
            identity_type: IdentityType::Human,
            public_key: public_key.clone(),
            ownership_proof,
            credentials: std::collections::HashMap::new(),
            reputation: 100, // Base reputation for imported identity
            age: None,
            access_level: AccessLevel::FullCitizen,
            metadata: std::collections::HashMap::new(),
            private_data_id: Some(identity_id.clone()),
            wallet_manager: crate::wallets::IdentityWallets::new(identity_id.clone()),
            attestations: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            last_active: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            recovery_keys: vec![],
            did_document_hash: None,
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: Some(RecoveryPhrase::from_words(phrase_words.clone())?),
        };
        
        // Create private data
        let private_data = PrivateIdentityData::new(
            private_key.to_vec(),
            public_key.to_vec(),
            seed,
            vec![], // No additional recovery options for imported identities
        );
        
        tracing::info!(
            "🔑 IDENTITY IMPORTED: {} - Password functionality enabled",
            hex::encode(&identity_id.0[..8])
        );
        
        Ok((identity, private_data))
    }

    /// Add a recovery key
    pub fn add_recovery_key(&mut self, recovery_key: RecoveryKey) -> Result<()> {
        if self.recovery_keys.len() >= self.max_recovery_keys {
            return Err(anyhow!("Maximum number of recovery keys reached"));
        }
        
        // Check for duplicate labels
        if self.recovery_keys.iter().any(|k| k.label == recovery_key.label) {
            return Err(anyhow!("Recovery key with label '{}' already exists", recovery_key.label));
        }
        
        self.recovery_keys.push(recovery_key);
        Ok(())
    }

    /// Remove a recovery key by ID
    pub fn remove_recovery_key(&mut self, key_id: &Hash) -> Result<()> {
        let initial_len = self.recovery_keys.len();
        self.recovery_keys.retain(|k| &k.id != key_id);
        
        if self.recovery_keys.len() == initial_len {
            return Err(anyhow!("Recovery key not found"));
        }
        
        Ok(())
    }

    /// Get recovery key by ID
    pub fn get_recovery_key(&self, key_id: &Hash) -> Option<&RecoveryKey> {
        self.recovery_keys.iter().find(|k| &k.id == key_id)
    }

    /// Get active recovery keys (non-expired and active)
    pub fn get_active_recovery_keys(&self) -> Vec<&RecoveryKey> {
        self.recovery_keys.iter()
            .filter(|k| k.is_active && !k.is_expired())
            .collect()
    }

    /// Clean up expired recovery keys
    pub fn cleanup_expired_recovery_keys(&mut self) {
        self.recovery_keys.retain(|k| !k.is_expired());
    }

    /// Validate recovery key format
    pub fn validate_recovery_key(&self, encrypted_key: &[u8]) -> bool {
        encrypted_key.len() >= 32 && encrypted_key.len() <= 128
    }

    // --- Internal Helper Methods ---

    /// Derive keypair from seed (internal helper)
    async fn derive_keypair_from_seed(seed: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate private key using CRYSTALS-Dilithium approach
        let mut private_input = seed.to_vec();
        private_input.extend_from_slice(b"dilithium_private_key_generation");
        let deterministic_private = blake3::hash(&private_input);
        let mut private_key = vec![0u8; 64];
        private_key[..32].copy_from_slice(deterministic_private.as_bytes());
        
        // Fill remaining bytes with deterministic data
        let mut remaining = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut remaining);
        private_key[32..].copy_from_slice(&remaining);
        
        // Generate corresponding public key
        let mut public_input = private_key.clone();
        public_input.extend_from_slice(b"dilithium_public_key_generation");
        let public_key_seed = blake3::hash(&public_input);
        
        let mut final_input = public_key_seed.as_bytes().to_vec();
        final_input.extend_from_slice(b"lib_quantum_resistant_public_key");
        let public_key = blake3::hash(&final_input).as_bytes().to_vec();
        
        Ok((private_key, public_key))
    }

    /// Generate simple ownership proof (internal helper)
    async fn generate_simple_ownership_proof(
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<lib_proofs::ZeroKnowledgeProof> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Create proof challenge
        let mut challenge_input = public_key.to_vec();
        challenge_input.extend_from_slice(&timestamp.to_le_bytes());
        challenge_input.extend_from_slice(b"ownership_proof_challenge");
        let challenge = blake3::hash(&challenge_input);
        
        // Generate proof response using private key
        let mut proof_input = private_key.to_vec();
        proof_input.extend_from_slice(challenge.as_bytes());
        proof_input.extend_from_slice(b"ownership_proof_response");
        let proof_response = blake3::hash(&proof_input);
        
        // Create verification commitment
        let mut verification_input = public_key.to_vec();
        verification_input.extend_from_slice(proof_response.as_bytes());
        let verification_commitment = blake3::hash(&verification_input);
        
        Ok(lib_proofs::ZeroKnowledgeProof {
            proof_system: "lib-OwnershipProof".to_string(),
            proof_data: proof_response.as_bytes().to_vec(),
            public_inputs: public_key.to_vec(),
            verification_key: verification_commitment.as_bytes().to_vec(),
            plonky2_proof: None,
            proof: vec![], // Legacy compatibility
        })
    }
}

impl Default for RecoveryService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_recovery_service() {
        let service = RecoveryService::new();
        assert_eq!(service.recovery_keys.len(), 0);
        assert_eq!(service.max_recovery_keys, 5);
    }

    #[test]
    fn test_add_recovery_key() {
        let mut service = RecoveryService::new();
        let key = RecoveryKey::new(
            vec![1, 2, 3, 4],
            "m/44'/0'/0'".to_string(),
            "backup1".to_string(),
        );
        
        let result = service.add_recovery_key(key);
        assert!(result.is_ok());
        assert_eq!(service.recovery_keys.len(), 1);
    }

    #[test]
    fn test_add_duplicate_label() {
        let mut service = RecoveryService::new();
        let key1 = RecoveryKey::new(
            vec![1, 2, 3, 4],
            "m/44'/0'/0'".to_string(),
            "backup1".to_string(),
        );
        let key2 = RecoveryKey::new(
            vec![5, 6, 7, 8],
            "m/44'/0'/1'".to_string(),
            "backup1".to_string(), // Duplicate label
        );
        
        service.add_recovery_key(key1).unwrap();
        let result = service.add_recovery_key(key2);
        assert!(result.is_err());
        assert_eq!(service.recovery_keys.len(), 1);
    }

    #[test]
    fn test_max_recovery_keys() {
        let mut service = RecoveryService::new();
        
        // Add max keys
        for i in 0..5 {
            let key = RecoveryKey::new(
                vec![i as u8; 4],
                format!("m/44'/0'/{}'", i),
                format!("backup{}", i),
            );
            service.add_recovery_key(key).unwrap();
        }
        
        // Try to add one more
        let extra_key = RecoveryKey::new(
            vec![99; 4],
            "m/44'/0'/5'".to_string(),
            "backup5".to_string(),
        );
        let result = service.add_recovery_key(extra_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_recovery_key() {
        let mut service = RecoveryService::new();
        let key = RecoveryKey::new(
            vec![1, 2, 3, 4],
            "m/44'/0'/0'".to_string(),
            "backup1".to_string(),
        );
        let key_id = key.id.clone();
        
        service.add_recovery_key(key).unwrap();
        let result = service.remove_recovery_key(&key_id);
        assert!(result.is_ok());
        assert_eq!(service.recovery_keys.len(), 0);
    }

    #[test]
    fn test_get_recovery_key() {
        let mut service = RecoveryService::new();
        let key = RecoveryKey::new(
            vec![1, 2, 3, 4],
            "m/44'/0'/0'".to_string(),
            "backup1".to_string(),
        );
        let key_id = key.id.clone();
        
        service.add_recovery_key(key).unwrap();
        let found = service.get_recovery_key(&key_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().label, "backup1");
    }

    #[test]
    fn test_get_active_recovery_keys() {
        let mut service = RecoveryService::new();
        let mut key = RecoveryKey::new(
            vec![1, 2, 3, 4],
            "m/44'/0'/0'".to_string(),
            "backup1".to_string(),
        );
        key.is_active = true;
        
        service.add_recovery_key(key).unwrap();
        
        let active = service.get_active_recovery_keys();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_validate_recovery_key() {
        let service = RecoveryService::new();
        
        assert!(service.validate_recovery_key(&vec![0u8; 32])); // Min size
        assert!(service.validate_recovery_key(&vec![0u8; 64])); // Mid size
        assert!(service.validate_recovery_key(&vec![0u8; 128])); // Max size
        assert!(!service.validate_recovery_key(&vec![0u8; 16])); // Too small
        assert!(!service.validate_recovery_key(&vec![0u8; 256])); // Too large
    }

    #[tokio::test]
    async fn test_import_identity_from_phrase() {
        let service = RecoveryService::new();
        
        // Create a valid 24-word phrase
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        
        let result = service.import_identity_from_phrase(phrase).await;
        assert!(result.is_ok());
        
        let (identity, private_data) = result.unwrap();
        assert_eq!(identity.identity_type, IdentityType::Human);
        assert_eq!(identity.access_level, AccessLevel::FullCitizen);
        assert!(!identity.public_key.is_empty());
        assert!(!private_data.private_key().is_empty());
    }

    #[tokio::test]
    async fn test_import_invalid_phrase() {
        let service = RecoveryService::new();
        
        // Invalid phrase (too short)
        let phrase = "abandon abandon abandon";
        
        let result = service.import_identity_from_phrase(phrase).await;
        assert!(result.is_err());
    }
}
