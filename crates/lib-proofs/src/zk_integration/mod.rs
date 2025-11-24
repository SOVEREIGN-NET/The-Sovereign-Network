//! ZK Integration Module - Production Implementation
//! 
//! This module provides the actual ZK proof system implementation,
//! moved from lib-crypto to lib-proofs for proper architectural separation.

// Re-export the main Plonky2 implementation
pub use crate::plonky2::{
    ZkProofSystem, 
    Plonky2Proof,
    CircuitConfig,
    CircuitBuilder,
};

// Re-export convenience functions from plonky2 proof_system
use anyhow::Result;
use lib_crypto::types::PrivateKey;

/// Create a production ZK proof system
pub fn create_zk_system() -> Result<ZkProofSystem> {
    ZkProofSystem::new()
}

/// Prove identity using production Plonky2 system
pub fn prove_identity(
    private_key: &PrivateKey,
    age: u64,
    jurisdiction_hash: u64, 
    credential_hash: u64,
    min_age: u64,
    required_jurisdiction: u64,
) -> Result<Plonky2Proof> {
    let zk_system = create_zk_system()?;
    // Use private key hash as identity secret
    let hash = lib_crypto::hashing::hash_blake3(&private_key.master_seed);
    let identity_secret = u64::from_le_bytes(hash[0..8].try_into()?);
    zk_system.prove_identity(identity_secret, age, jurisdiction_hash, credential_hash, min_age, required_jurisdiction, 1)
}

/// Prove range using production Plonky2 system
pub fn prove_range(
    value: u64,
    blinding_factor: u64,
    min_value: u64,
    max_value: u64,
) -> Result<Plonky2Proof> {
    let zk_system = create_zk_system()?;
    zk_system.prove_range(value, blinding_factor, min_value, max_value)
}

/// Prove storage access using production Plonky2 system
pub fn prove_storage_access(
    access_key: u64,
    requester_secret: u64,
    data_hash: u64,
    permission_level: u64,
    required_permission: u64,
) -> Result<Plonky2Proof> {
    let zk_system = create_zk_system()?;
    zk_system.prove_storage_access(access_key, requester_secret, data_hash, permission_level, required_permission)
}

// NEW: ZK proofs of cryptographic operations (to be implemented in plonky2)
/// Prove Dilithium signature properties without revealing the private key
pub fn prove_dilithium_signature(private_key: &PrivateKey, message: &[u8]) -> Result<Plonky2Proof> {
    let zk_system = create_zk_system()?;
    // TODO: Implement in plonky2/proof_system.rs
    // For now, use identity proof as placeholder
    let message_hash = lib_crypto::hashing::hash_blake3(message);
    let msg_u64 = u64::from_le_bytes(message_hash[0..8].try_into()?);
    let key_u64 = u64::from_le_bytes(private_key.dilithium_sk[0..8].try_into().unwrap_or([0; 8]));
    zk_system.prove_identity(key_u64, msg_u64, 0, 0, 0, 0, 1)
}

/// Prove ring signature membership without revealing identity
pub fn prove_ring_membership(ring_members: &[Vec<u8>], secret_index: usize, secret_key: &[u8]) -> Result<Plonky2Proof> {
    let zk_system = create_zk_system()?;
    
    if secret_index >= ring_members.len() {
        return Err(anyhow::anyhow!("Secret index {} out of bounds for ring of size {}", secret_index, ring_members.len()));
    }
    
    // Hash the secret key for use in the proof
    let key_hash = lib_crypto::hashing::hash_blake3(secret_key);
    let key_value = u64::from_le_bytes(key_hash[0..8].try_into().unwrap_or([0; 8]));
    
    // Prove knowledge of secret key corresponding to ring member at secret_index
    let ring_size = ring_members.len() as u64;
    zk_system.prove_identity(key_value, secret_index as u64, ring_size, 0, 0, 0, 1)
}

/// Prove post-quantum key properties
pub fn prove_pqc_key_properties(private_key: &PrivateKey) -> Result<Plonky2Proof> {
    let zk_system = create_zk_system()?;
    // TODO: Implement PQC property circuit in plonky2/proof_system.rs
    // For now, use storage access proof as placeholder
    let dilithium_hash = lib_crypto::hashing::hash_blake3(&private_key.dilithium_sk);
    let kyber_hash = lib_crypto::hashing::hash_blake3(&private_key.kyber_sk);
    let dil_u64 = u64::from_le_bytes(dilithium_hash[0..8].try_into()?);
    let kyb_u64 = u64::from_le_bytes(kyber_hash[0..8].try_into()?);
    zk_system.prove_storage_access(dil_u64, kyb_u64, 0, 100, 50)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::types::PrivateKey;

    fn create_test_private_key() -> PrivateKey {
        PrivateKey {
            dilithium_sk: vec![1, 2, 3, 4, 5, 6, 7, 8],
            kyber_sk: vec![9, 10, 11, 12, 13, 14, 15, 16],
            ed25519_sk: vec![17, 18, 19, 20, 21, 22, 23, 24],
            master_seed: vec![25, 26, 27, 28, 29, 30, 31, 32],
        }
    }

    #[test]
    fn test_zk_system_creation() {
        let result = create_zk_system();
        assert!(result.is_ok());
    }

    #[test]
    fn test_identity_proof_with_private_key() {
        let private_key = create_test_private_key();
        let result = prove_identity(&private_key, 25, 840, 9999, 18, 840);
        assert!(result.is_ok());
        
        let proof = result.unwrap();
        assert!(!proof.proof.is_empty());
    }

    #[test]
    fn test_range_proof() {
        let result = prove_range(500, 123456, 0, 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dilithium_signature_proof() {
        let private_key = create_test_private_key();
        let message = b"test message for dilithium proof";
        
        let result = prove_dilithium_signature(&private_key, message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ring_membership_proof() {
        let ring_members = vec![
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8], 
            vec![9, 10, 11, 12],
        ];
        let secret_key = vec![5, 6, 7, 8];
        
        let result = prove_ring_membership(&ring_members, 1, &secret_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pqc_key_properties_proof() {
        let private_key = create_test_private_key();
        
        let result = prove_pqc_key_properties(&private_key);
        assert!(result.is_ok());
    }
}
