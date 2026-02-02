//! Token Transaction Builder
//!
//! Provides FFI-exportable functions for building signed token transactions.
//! iOS/Android clients call these to get hex-encoded transactions ready for the API.

use serde::{Deserialize, Serialize};
use crate::identity::Identity;
use crate::crypto;

// Use the canonical types from lib-blockchain and lib-crypto to ensure bincode compatibility
// CRITICAL: These MUST be imported, not redefined locally, for bincode serialization to match
use lib_blockchain::{Transaction, TransactionType};
use lib_blockchain::types::{ContractType, ContractCall, CallPermissions};
use lib_crypto::types::SignatureAlgorithm;
use lib_blockchain::integration::crypto_integration::{Signature, PublicKey};

// ============================================================================
// Helper functions
// ============================================================================

/// Helper function to create a PublicKey from dilithium_pk
pub fn create_public_key(dilithium_pk: Vec<u8>) -> PublicKey {
    let key_id = crypto::Blake3::hash(&dilithium_pk);
    let mut key_id_arr = [0u8; 32];
    key_id_arr.copy_from_slice(&key_id[..32]);
    PublicKey {
        dilithium_pk,
        kyber_pk: vec![],
        key_id: key_id_arr,
    }
}

// ============================================================================
// Token Operation Parameters
// ============================================================================

/// Parameters for creating a new token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenParams {
    pub name: String,
    pub symbol: String,
    pub initial_supply: u64,
    pub decimals: u8,
}

/// Parameters for minting tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintParams {
    pub token_id: [u8; 32],
    pub to: Vec<u8>,  // PublicKey bytes
    pub amount: u64,
}

/// Parameters for transferring tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferParams {
    pub token_id: [u8; 32],
    pub to: Vec<u8>,  // PublicKey bytes
    pub amount: u64,
}

/// Parameters for burning tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnParams {
    pub token_id: [u8; 32],
    pub amount: u64,
}

// ============================================================================
// Transaction Builder
// ============================================================================

/// Build a signed token transaction
///
/// CRITICAL: Uses lib-blockchain's signing_hash() for deterministic, version-safe signing.
/// This ensures compatibility between server, CLI, and mobile clients.
///
/// Signing process:
/// 1. Build tx with placeholder signature
/// 2. Call tx.signing_hash() - uses deterministic field-by-field hashing
/// 3. Sign the hash with Dilithium
/// 4. Put real signature back into transaction
/// 5. Serialize with bincode for transmission
fn build_token_transaction(
    identity: &Identity,
    method: &str,
    params: Vec<u8>,
    chain_id: u8,
) -> Result<String, String> {
    // Build ContractCall with Public permissions
    // Authorization is via tx.signature.public_key, not the permissions field
    let call = ContractCall {
        contract_type: ContractType::Token,
        method: method.to_string(),
        params,
        permissions: CallPermissions::Public,
    };

    // Create public key using the blockchain's canonical structure
    let public_key = create_public_key(identity.public_key.clone());

    // Build memo: "ZHTP" + bincode(call, placeholder_sig)
    // Note: The memo signature uses the actual public key (this is separate from tx signature)
    let memo_sig = Signature {
        signature: vec![],
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2, // Use Dilithium2 to match identity key type
        timestamp: 0,
    };

    let call_and_sig = (&call, &memo_sig);
    let call_data = bincode::serialize(&call_and_sig)
        .map_err(|e| format!("Failed to serialize call: {}", e))?;

    let mut memo = b"ZHTP".to_vec();
    memo.extend(call_data);

    // Step 1: Calculate dynamic fee based on estimated transaction size
    // Fee formula: ~0.119 ZHTP per byte, or 1 ZHTP per ~8.4 bytes
    // Server calculation: fee = ceil(transaction_size_bytes / 8.4)
    let estimated_tx_size = 200 // minimum fixed fields
        + memo.len() // memo variable size
        + 3732; // Dilithium2 witness: 2420 byte sig + 1312 byte pk (from lib-blockchain)

    // Calculate fee using integer arithmetic: ceil(size / 8.4) = ceil(size * 10 / 84)
    // This ensures: 10083 bytes -> 1200 ZHTP (matches server requirement)
    let min_fee = ((estimated_tx_size as u64 * 10 + 83) / 84) + 50; // Buffer for rounding safety

    // Step 2: Build transaction with calculated fee for hashing
    // ALL fields must be present - signing_hash() includes all of them
    let mut tx = Transaction {
        version: 1,
        chain_id,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![],
        fee: min_fee,
        signature: Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        },
        memo: memo.clone(),
        // ALL optional fields must be present (even if None)
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,        // Added - was missing
        governance_config_data: None,     // Added - was missing
    };

    eprintln!("[token_tx] Method: {}", method);
    eprintln!("[token_tx] Chain ID: {}", chain_id);
    eprintln!("[token_tx] Memo length: {} bytes", memo.len());
    eprintln!("[token_tx] Public key size: {}", identity.public_key.len());
    eprintln!("[token_tx] Estimated tx size: {} bytes", estimated_tx_size);
    eprintln!("[token_tx] Calculated minimum fee: {} ZHTP", min_fee);

    // Step 3: Use signing_hash() - deterministic field-by-field hashing
    // This is the SAFE method that won't break when Transaction struct changes
    let tx_hash = tx.signing_hash();

    eprintln!("[token_tx] Signing hash: {}", hex::encode(tx_hash.as_bytes()));

    // Step 4: Sign the hash with Dilithium
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    eprintln!("[token_tx] Signature size: {} bytes", signature_bytes.len());

    // Step 5: Put real signature and public key back into transaction
    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    // Step 6: Serialize final transaction with signature for transmission
    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize final tx: {}", e))?;

    eprintln!("[token_tx] Final tx size: {} bytes (estimated was {})", final_tx_bytes.len(), estimated_tx_size);
    eprintln!("[token_tx] Fee verification: {} ZHTP for {} bytes = {:.3} ZHTP/byte",
        min_fee, final_tx_bytes.len(),
        min_fee as f64 / final_tx_bytes.len() as f64);

    // Hex encode for API
    Ok(hex::encode(final_tx_bytes))
}

// ============================================================================
// Public API
// ============================================================================

/// Build a signed token transfer transaction
pub fn build_transfer_tx(
    identity: &Identity,
    token_id: &[u8; 32],
    to_pubkey: &[u8],
    amount: u64,
    chain_id: u8,
) -> Result<String, String> {
    let params = TransferParams {
        token_id: *token_id,
        to: to_pubkey.to_vec(),
        amount,
    };
    let params_bytes = bincode::serialize(&params)
        .map_err(|e| format!("Failed to serialize params: {}", e))?;

    build_token_transaction(identity, "transfer", params_bytes, chain_id)
}

/// Build a signed token mint transaction
pub fn build_mint_tx(
    identity: &Identity,
    token_id: &[u8; 32],
    to_pubkey: &[u8],
    amount: u64,
    chain_id: u8,
) -> Result<String, String> {
    let params = MintParams {
        token_id: *token_id,
        to: to_pubkey.to_vec(),
        amount,
    };
    let params_bytes = bincode::serialize(&params)
        .map_err(|e| format!("Failed to serialize params: {}", e))?;

    build_token_transaction(identity, "mint", params_bytes, chain_id)
}

/// Build a signed token creation transaction
pub fn build_create_token_tx(
    identity: &Identity,
    name: &str,
    symbol: &str,
    initial_supply: u64,
    decimals: u8,
    chain_id: u8,
) -> Result<String, String> {
    let params = CreateTokenParams {
        name: name.to_string(),
        symbol: symbol.to_string(),
        initial_supply,
        decimals,
    };
    let params_bytes = bincode::serialize(&params)
        .map_err(|e| format!("Failed to serialize params: {}", e))?;

    build_token_transaction(identity, "create_custom_token", params_bytes, chain_id)
}

/// Build a signed token burn transaction
pub fn build_burn_tx(
    identity: &Identity,
    token_id: &[u8; 32],
    amount: u64,
    chain_id: u8,
) -> Result<String, String> {
    let params = BurnParams {
        token_id: *token_id,
        amount,
    };
    let params_bytes = bincode::serialize(&params)
        .map_err(|e| format!("Failed to serialize params: {}", e))?;

    build_token_transaction(identity, "burn", params_bytes, chain_id)
}
