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
/// CRITICAL: The signing process must match lib-blockchain's verification exactly:
/// 1. Build tx with ZEROED signature (empty public_key, timestamp 0)
/// 2. Serialize with bincode
/// 3. Hash with blake3
/// 4. Sign the HASH (not the raw serialized bytes)
/// 5. Put real signature and public key back
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
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    };

    let call_and_sig = (&call, &memo_sig);
    let call_data = bincode::serialize(&call_and_sig)
        .map_err(|e| format!("Failed to serialize call: {}", e))?;

    let mut memo = b"ZHTP".to_vec();
    memo.extend(call_data);

    // Step 1: Build transaction with ZEROED signature for hashing
    // This MUST match lib-blockchain/src/transaction/hashing.rs:hash_transaction()
    let mut tx = Transaction {
        version: 1,
        chain_id,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![],
        fee: 1000,
        signature: Signature {
            signature: vec![],
            // CRITICAL: Must use all-zero key_id, NOT blake3(empty)
            // PublicKey::new(vec![]) computes key_id = blake3([]) = af1349b9...
            // For zeroed signature, key_id must be [0u8; 32] to match server
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],  // All zeros - must match server's hash_transaction()
            },
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,  // ZERO - must match server
        },
        memo: memo.clone(),
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
    };

    eprintln!("[token_tx] Method: {}", method);
    eprintln!("[token_tx] Memo length: {} bytes", memo.len());
    eprintln!("[token_tx] Public key size: {}", identity.public_key.len());

    // Debug: Log the zeroed signature structure
    eprintln!("[token_tx] Zeroed sig.signature.len={}", tx.signature.signature.len());
    eprintln!("[token_tx] Zeroed sig.public_key.dilithium_pk.len={}", tx.signature.public_key.dilithium_pk.len());
    eprintln!("[token_tx] Zeroed sig.public_key.kyber_pk.len={}", tx.signature.public_key.kyber_pk.len());
    eprintln!("[token_tx] Zeroed sig.public_key.key_id={}", hex::encode(&tx.signature.public_key.key_id));
    eprintln!("[token_tx] Zeroed sig.timestamp={}", tx.signature.timestamp);
    eprintln!("[token_tx] Memo hex (first 100): {}", hex::encode(&memo[..std::cmp::min(100, memo.len())]));

    // Step 2: Serialize for hashing
    let tx_bytes_for_hashing = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize tx: {}", e))?;

    eprintln!("[token_tx] Serialized tx size: {} bytes", tx_bytes_for_hashing.len());
    eprintln!("[token_tx] Serialized tx hex (first 100): {}", hex::encode(&tx_bytes_for_hashing[..std::cmp::min(100, tx_bytes_for_hashing.len())]));
    // Log signature struct position (after fee at offset ~33) for comparison with server
    if tx_bytes_for_hashing.len() > 97 {
        eprintln!("[token_tx] Bytes 33-97 (signature struct): {}", hex::encode(&tx_bytes_for_hashing[33..97]));
    }

    // Step 3: Hash with blake3 (matching lib-blockchain's hash_transaction)
    let tx_hash = blake3::hash(&tx_bytes_for_hashing);

    eprintln!("[token_tx] Tx hash: {}", hex::encode(tx_hash.as_bytes()));

    // Step 4: Sign the HASH (not the raw bytes)
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    eprintln!("[token_tx] Signature size: {} bytes", signature_bytes.len());

    // Step 5: Put real signature and public key back into transaction
    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    // Step 6: Serialize final transaction with signature
    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize final tx: {}", e))?;

    // Hex encode
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
