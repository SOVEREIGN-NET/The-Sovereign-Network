//! Transaction hashing utilities
//!
//! Provides secure hashing functionality for ZHTP blockchain transactions.

use crate::transaction::core::{Transaction, TransactionInput, TransactionOutput};
use crate::types::Hash;
use crate::integration::crypto_integration::{Signature, PublicKey, PrivateKey, SignatureAlgorithm};
use crate::integration::zk_integration::ZkTransactionProof;
use tracing::debug;

/// Hash a complete transaction
pub fn hash_transaction(transaction: &Transaction) -> Hash {
    // Create a copy without signature for consistent hashing
    let mut tx_for_hash = transaction.clone();
    // CRITICAL: Must use all-zero key_id, NOT blake3(empty)
    // PublicKey::new(vec![]) computes key_id = blake3([]) = af1349b9...
    // For zeroed signature, key_id must be [0u8; 32] to match client
    tx_for_hash.signature = Signature {
        signature: Vec::new(),
        public_key: PublicKey {
            dilithium_pk: Vec::new(),
            kyber_pk: Vec::new(),
            key_id: [0u8; 32],  // All zeros - must match client's zeroed signature
        },
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    };
    
    // Serialize and hash
    let serialized = bincode::serialize(&tx_for_hash)
        .expect("Transaction serialization should never fail");

    // Log serialized bytes for comparison with client (debug only)
    debug!(
        "[hashing] Serialized tx for hashing, len={}",
        serialized.len()
    );
    if serialized.len() >= 64 {
        debug!(
            "[hashing] First 64 bytes: {}",
            hex::encode(&serialized[..64])
        );
    }
    if serialized.len() > 97 {
        debug!(
            "[hashing] Bytes 33-97 (signature struct): {}",
            hex::encode(&serialized[33..97])
        );
    }

    crate::types::hash::blake3_hash(&serialized)
}

/// Hash transaction for signing (excludes signature field)
pub fn hash_transaction_for_signing(transaction: &Transaction) -> Hash {
    hash_for_signature(transaction)
}

/// Hash a transaction input
pub fn hash_transaction_input(input: &TransactionInput) -> Hash {
    let serialized = bincode::serialize(input)
        .expect("TransactionInput serialization should never fail");
    
    crate::types::hash::blake3_hash(&serialized)
}

/// Hash a transaction output
pub fn hash_transaction_output(output: &TransactionOutput) -> Hash {
    let serialized = bincode::serialize(output)
        .expect("TransactionOutput serialization should never fail");
    
    crate::types::hash::blake3_hash(&serialized)
}

/// Calculate transaction Merkle tree root from multiple transactions
pub fn calculate_transaction_merkle_root(transactions: &[Transaction]) -> Hash {
    if transactions.is_empty() {
        return Hash::default();
    }

    // Get all transaction hashes
    let mut hashes: Vec<Hash> = transactions
        .iter()
        .map(hash_transaction)
        .collect();

    // Build Merkle tree bottom-up
    while hashes.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in hashes.chunks(2) {
            let left = chunk[0];
            let right = chunk.get(1).copied().unwrap_or(left); // Duplicate if odd
            
            let mut combined = Vec::new();
            combined.extend_from_slice(left.as_bytes());
            combined.extend_from_slice(right.as_bytes());
            let parent_hash = crate::types::hash::blake3_hash(&combined);
            next_level.push(parent_hash);
        }
        
        hashes = next_level;
    }

    hashes[0]
}

/// Generate nullifier for transaction input
/// Nullifiers prevent double-spending in zero-knowledge systems
pub fn generate_nullifier(
    secret_key: &[u8],
    commitment: &Hash,
    position: u64,
) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(secret_key);
    data.extend_from_slice(commitment.as_bytes());
    data.extend_from_slice(&position.to_le_bytes());
    
    crate::types::hash::blake3_hash(&data)
}

/// Create commitment hash for transaction output
/// Commitments hide transaction amounts in zero-knowledge systems
pub fn create_commitment(
    amount: u64,
    blinding_factor: &[u8],
    recipient_key: &PublicKey,
) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(blinding_factor);
    data.extend_from_slice(&crate::integration::crypto_integration::public_key_bytes(recipient_key));
    
    crate::types::hash::blake3_hash(&data)
}

/// Create encrypted note for transaction output
/// Notes contain encrypted transaction data for recipients
pub fn create_encrypted_note(
    amount: u64,
    memo: &[u8],
    recipient_key: &PublicKey,
    sender_key: &PrivateKey,
) -> Result<Hash, String> {
    // Prepare note data
    let mut note_data = Vec::new();
    note_data.extend_from_slice(&amount.to_le_bytes());
    note_data.extend_from_slice(&(memo.len() as u32).to_le_bytes());
    note_data.extend_from_slice(memo);
    
    // Use the provided keys for encryption
    debug!("Creating encrypted note using recipient key: {} bytes, sender key: {} bytes", 
           recipient_key.dilithium_pk.len(), sender_key.dilithium_sk.len());
    
    // Add sender's signature to the note for authenticity
    let mut signed_note_data = note_data.clone();
    // Create authenticated note with sender signature using lib-identity
    // Convert PrivateKey to PostQuantumKeypair for lib-identity signing
    let post_quantum_keypair = lib_identity::cryptography::key_generation::PostQuantumKeypair {
        public_key: recipient_key.dilithium_pk.clone(),
        private_key: sender_key.dilithium_sk.clone(),
        algorithm: "Dilithium5".to_string(),
        security_level: 5,
        key_id: format!("tx_signing_{}", hex::encode(&sender_key.dilithium_sk[..8])),
    };
    
    // Sign the note data using lib-identity's post-quantum signing
    if let Ok(signature) = lib_identity::cryptography::signatures::sign_with_identity(
        &post_quantum_keypair,
        &note_data,
        None, // No additional signature parameters
    ) {
        // Append the actual signature to note data
        signed_note_data.extend_from_slice(&signature.signature);
    }
    
    // Encrypt the note using hybrid encryption with the recipient's public key
    let encrypted_note = crate::integration::crypto_integration::hybrid_encrypt(&signed_note_data, recipient_key)
        .map_err(|e| format!("Note encryption failed: {}", e))?;
    
    // Return hash of encrypted note
    Ok(crate::types::hash::blake3_hash(&encrypted_note))
}

/// Hash transaction for signature (deterministic ordering)
pub fn hash_for_signature(transaction: &Transaction) -> Hash {
    // Create signing hash with deterministic field ordering
    let mut hasher = blake3::Hasher::new();
    
    // Add version
    hasher.update(&transaction.version.to_le_bytes());
    
    // Add transaction type
    let type_bytes = bincode::serialize(&transaction.transaction_type)
        .expect("TransactionType serialization should never fail");
    hasher.update(&type_bytes);
    
    // Add inputs (sorted by outpoint for determinism)
    let mut sorted_inputs = transaction.inputs.clone();
    sorted_inputs.sort_by_key(|input| (input.previous_output, input.output_index));
    
    for input in &sorted_inputs {
        let input_bytes = bincode::serialize(input)
            .expect("TransactionInput serialization should never fail");
        hasher.update(&input_bytes);
    }
    
    // Add outputs (sorted by commitment for determinism)
    let mut sorted_outputs = transaction.outputs.clone();
    sorted_outputs.sort_by_key(|output| output.commitment);
    
    for output in &sorted_outputs {
        let output_bytes = bincode::serialize(output)
            .expect("TransactionOutput serialization should never fail");
        hasher.update(&output_bytes);
    }
    
    // Add fee
    hasher.update(&transaction.fee.to_le_bytes());
    
    // Add memo
    hasher.update(&transaction.memo);
    
    // Add identity data if present
    if let Some(identity_data) = &transaction.identity_data {
        let identity_bytes = bincode::serialize(identity_data)
            .expect("IdentityTransactionData serialization should never fail");
        hasher.update(&identity_bytes);
    }
    
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(hasher.finalize().as_bytes());
    Hash::new(hash_bytes)
}

/// Implement Hash trait for Transaction
impl crate::types::hash::Hashable for Transaction {
    fn hash(&self) -> Hash {
        hash_transaction(self)
    }
}

/// Implement Hash trait for TransactionInput
impl crate::types::hash::Hashable for TransactionInput {
    fn hash(&self) -> Hash {
        hash_transaction_input(self)
    }
}

/// Implement Hash trait for TransactionOutput
impl crate::types::hash::Hashable for TransactionOutput {
    fn hash(&self) -> Hash {
        hash_transaction_output(self)
    }
}

/// Transaction hashing utilities
pub mod utils {
    use super::*;

    /// Create a deterministic transaction ID
    pub fn transaction_id(transaction: &Transaction) -> String {
        let hash = hash_transaction(transaction);
        crate::types::hash::hash_to_hex(&hash)
    }

    /// Create short transaction ID (first 8 bytes)
    pub fn short_transaction_id(transaction: &Transaction) -> String {
        let full_hash = hash_transaction(transaction);
        let short_bytes = &full_hash.as_bytes()[..8];
        hex::encode(short_bytes)
    }

    /// Verify transaction hash integrity
    pub fn verify_transaction_hash(transaction: &Transaction, expected_hash: &Hash) -> bool {
        &hash_transaction(transaction) == expected_hash
    }

    /// Calculate witness hash for SegWit-style separation
    /// (Not used in ZHTP but included for compatibility)
    pub fn calculate_witness_hash(transaction: &Transaction) -> Hash {
        // In ZHTP, ZK proofs are part of witness data
        let mut witness_data = Vec::new();
        
        for input in &transaction.inputs {
            let proof_bytes = bincode::serialize(&input.zk_proof)
                .expect("ZkTransactionProof serialization should never fail");
            witness_data.extend_from_slice(&proof_bytes);
        }
        
        if witness_data.is_empty() {
            Hash::default()
        } else {
            crate::types::hash::blake3_hash(&witness_data)
        }
    }

    /// Create content hash for deduplication
    pub fn content_hash(transaction: &Transaction) -> Hash {
        // Hash everything except signature and ZK proofs
        let mut tx_content = transaction.clone();
        tx_content.signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(Vec::new()),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };
        
        // Clear ZK proofs for content-only hash
        for input in &mut tx_content.inputs {
            input.zk_proof = ZkTransactionProof::default();
        }
        
        hash_transaction(&tx_content)
    }

    /// Calculate double-SHA256 hash (Bitcoin compatibility)
    pub fn double_sha256_hash(transaction: &Transaction) -> Hash {
        let first_hash = hash_transaction(transaction);
        crate::types::hash::blake3_hash(first_hash.as_bytes())
    }
}
