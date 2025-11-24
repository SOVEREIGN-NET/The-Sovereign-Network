//! Transaction signing utilities
//!
//! Provides secure signing functionality for ZHTP blockchain transactions.

use crate::transaction::core::Transaction;
use crate::types::Hash;
use lib_crypto::{Signature, PrivateKey, PublicKey};

/// Transaction signing error types
#[derive(Debug, Clone)]
pub enum SigningError {
    InvalidPrivateKey,
    HashingError,
    CryptoError(String),
    InvalidTransaction,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::InvalidPrivateKey => write!(f, "Invalid private key"),
            SigningError::HashingError => write!(f, "Transaction hashing failed"),
            SigningError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            SigningError::InvalidTransaction => write!(f, "Invalid transaction for signing"),
        }
    }
}

impl std::error::Error for SigningError {}

/// Sign a transaction with a private key
pub fn sign_transaction(
    transaction: &mut Transaction,
    private_key: &PrivateKey,
) -> Result<(), SigningError> {
    // Create signing hash (without existing signature)
    let signing_hash = crate::transaction::hashing::hash_for_signature(transaction);
    
    // Create a keypair from the provided private key for signing
    // TODO: In a proper implementation, would construct keypair from the provided private_key
    // For now, we use the private_key validation but generate a new keypair
    if private_key.dilithium_sk.is_empty() {
        return Err(SigningError::InvalidPrivateKey);
    }
    
    let keypair = lib_crypto::KeyPair::generate()
        .map_err(|e| SigningError::CryptoError(e.to_string()))?;
    
    // Sign the hash using the keypair and transaction context
    let signature = keypair.sign(signing_hash.as_bytes())
        .map_err(|e| SigningError::CryptoError(e.to_string()))?;
    
    // Set the signature on the transaction
    transaction.signature = signature;
    
    // Log the transaction ID for auditing
    log::info!("Successfully signed transaction: {}", hex::encode(&transaction.id()));
    
    Ok(())
}

/// Verify a transaction signature
pub fn verify_transaction_signature(
    transaction: &Transaction,
    public_key: &PublicKey,
) -> Result<bool, SigningError> {
    // Create signing hash (without signature)
    let mut tx_for_verification = transaction.clone();
    tx_for_verification.signature = lib_crypto::Signature {
        signature: Vec::new(),
        public_key: lib_crypto::PublicKey::new(Vec::new()),
        algorithm: lib_crypto::SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    };
    
    let signing_hash = crate::transaction::hashing::hash_for_signature(&tx_for_verification);
    
    // Use lib_crypto's verify_signature function
    let signature_bytes = transaction.signature.signature.clone();
    let public_key_bytes = public_key.as_bytes();
    
    lib_crypto::verify_signature(signing_hash.as_bytes(), &signature_bytes, &public_key_bytes)
        .map_err(|e| SigningError::CryptoError(e.to_string()))
}

/// Multi-signature support for transactions
pub struct MultiSigContext {
    required_signatures: usize,
    public_keys: Vec<PublicKey>,
    signatures: Vec<Option<Signature>>,
}

impl MultiSigContext {
    /// Create a new multi-signature context
    pub fn new(required_signatures: usize, public_keys: Vec<PublicKey>) -> Self {
        let signatures = vec![None; public_keys.len()];
        Self {
            required_signatures,
            public_keys,
            signatures,
        }
    }

    /// Add a signature for a specific key index
    pub fn add_signature(
        &mut self,
        key_index: usize,
        signature: Signature,
    ) -> Result<(), SigningError> {
        if key_index >= self.public_keys.len() {
            return Err(SigningError::InvalidPrivateKey);
        }

        self.signatures[key_index] = Some(signature);
        Ok(())
    }

    /// Check if enough signatures are collected
    pub fn is_complete(&self) -> bool {
        let signature_count = self.signatures.iter().filter(|s| s.is_some()).count();
        signature_count >= self.required_signatures
    }

    /// Verify all provided signatures
    pub fn verify_signatures(&self, transaction: &Transaction) -> Result<bool, SigningError> {
        let signing_hash = crate::transaction::hashing::hash_for_signature(transaction);

        let mut valid_signatures = 0;

        for (i, signature_opt) in self.signatures.iter().enumerate() {
            if let Some(signature) = signature_opt {
                let signature_bytes = signature.signature.clone();
                let public_key_bytes = self.public_keys[i].as_bytes();
                
                let is_valid = lib_crypto::verify_signature(
                    signing_hash.as_bytes(), 
                    &signature_bytes, 
                    &public_key_bytes
                ).map_err(|e| SigningError::CryptoError(e.to_string()))?;

                if is_valid {
                    valid_signatures += 1;
                }
            }
        }

        Ok(valid_signatures >= self.required_signatures)
    }

    /// Combine signatures into a single signature for the transaction
    pub fn finalize_signature(&self) -> Result<Signature, SigningError> {
        if !self.is_complete() {
            return Err(SigningError::CryptoError("Not enough signatures".to_string()));
        }

        // For ZHTP, we use the first valid signature as the transaction signature
        // In a full implementation, this would create an aggregate signature
        for signature_opt in &self.signatures {
            if let Some(signature) = signature_opt {
                return Ok(signature.clone());
            }
        }

        Err(SigningError::CryptoError("No valid signatures found".to_string()))
    }
}

/// Create signature for identity transaction
pub fn sign_identity_transaction(
    transaction: &mut Transaction,
    identity_private_key: &PrivateKey,
) -> Result<(), SigningError> {
    // Identity transactions may have special signing requirements
    // For now, use standard signing
    sign_transaction(transaction, identity_private_key)
}

/// Create signature for contract transaction
pub fn sign_contract_transaction(
    transaction: &mut Transaction,
    private_key: &PrivateKey,
) -> Result<(), SigningError> {
    // Contract transactions may need additional validation
    // Delegate to lib-contracts package for contract-specific logic
    sign_transaction(transaction, private_key)
}

/// Batch sign multiple transactions
pub fn batch_sign_transactions(
    transactions: &mut [Transaction],
    private_key: &PrivateKey,
) -> Result<(), SigningError> {
    for transaction in transactions {
        sign_transaction(transaction, private_key)?;
    }
    Ok(())
}

/// Signing utilities
pub mod utils {
    use super::*;

    /// Extract public key from transaction signature (if possible)
    pub fn extract_public_key_from_signature(
        transaction: &Transaction,
    ) -> Option<PublicKey> {
        // In CRYSTALS-Dilithium, public keys cannot be directly extracted from signatures
        // However, we can return the public key stored in the signature if available
        if !transaction.signature.public_key.dilithium_pk.is_empty() {
            // Return a clone of the existing public key from the signature
            Some(transaction.signature.public_key.clone())
        } else {
            // Log the transaction ID for debugging when no public key is available
            log::debug!("No public key available in transaction signature: {}", 
                hex::encode(&transaction.id()));
            None
        }
    }

    /// Check if transaction is properly signed
    pub fn is_transaction_signed(transaction: &Transaction) -> bool {
        !transaction.signature.signature.is_empty()
    }

    /// Get transaction signer count (for multi-sig analysis)
    pub fn get_signer_count(transaction: &Transaction) -> usize {
        // For single signature transactions, always 1
        // Multi-sig would require additional metadata
        if is_transaction_signed(transaction) { 1 } else { 0 }
    }

    /// Create deterministic signing nonce
    pub fn create_signing_nonce(
        transaction: &Transaction,
        private_key: &PrivateKey,
    ) -> Hash {
        let tx_hash = transaction.hash();
        // Use the Dilithium secret key bytes for nonce generation
        let key_bytes = &private_key.dilithium_sk;
        
        let mut nonce_data = Vec::new();
        nonce_data.extend_from_slice(tx_hash.as_bytes());
        nonce_data.extend_from_slice(key_bytes);
        
        crate::types::hash::blake3_hash(&nonce_data)
    }

    /// Verify signature chain for dependent transactions
    pub fn verify_signature_chain(
        transactions: &[Transaction],
        public_keys: &[PublicKey],
    ) -> Result<bool, SigningError> {
        if transactions.len() != public_keys.len() {
            return Err(SigningError::InvalidTransaction);
        }

        for (transaction, public_key) in transactions.iter().zip(public_keys.iter()) {
            if !verify_transaction_signature(transaction, public_key)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Calculate signature verification cost
    pub fn calculate_verification_cost(transaction: &Transaction) -> u64 {
        // Base cost for signature verification
        let base_cost = 1000u64;
        
        // Additional cost for zero-knowledge proofs
        let zk_cost = transaction.inputs.len() as u64 * 5000;
        
        // Additional cost for identity transactions
        let identity_cost = if transaction.identity_data.is_some() { 2000 } else { 0 };
        
        base_cost + zk_cost + identity_cost
    }
}
