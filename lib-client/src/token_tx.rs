//! Contract Transaction Builder
//!
//! Provides FFI-exportable functions for building signed contract transactions.
//! iOS/Android clients call these to get hex-encoded transactions ready for the API.
//!
//! Supports all contract types: Token, DomainRegistry, Identity, etc.

use serde::{Deserialize, Serialize};
use crate::identity::Identity;
use crate::crypto;
use hex;

// Use the canonical types from lib-blockchain and lib-crypto to ensure bincode compatibility
// CRITICAL: These MUST be imported, not redefined locally, for bincode serialization to match
use lib_blockchain::{Transaction, TransactionType};
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::transaction::{TokenCreationPayloadV1, TokenMintData, TokenTransferData};
use lib_blockchain::types::{ContractType, ContractCall, CallPermissions};
use lib_crypto::types::SignatureAlgorithm;
use lib_blockchain::integration::crypto_integration::{Signature, PublicKey};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const DEFAULT_BASE_FEE: u64 = 100;
const DEFAULT_BYTES_PER_SOV: u64 = 100;
const DEFAULT_WITNESS_CAP: u32 = 500;

static TX_FEE_BASE_FEE: AtomicU64 = AtomicU64::new(DEFAULT_BASE_FEE);
static TX_FEE_BYTES_PER_SOV: AtomicU64 = AtomicU64::new(DEFAULT_BYTES_PER_SOV);
static TX_FEE_WITNESS_CAP: AtomicU32 = AtomicU32::new(DEFAULT_WITNESS_CAP);

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

/// Override fee parameters at runtime (set via governance-fed config).
pub fn set_fee_config(base_fee: u64, bytes_per_sov: u64, witness_cap: u32) {
    if base_fee > 0 {
        TX_FEE_BASE_FEE.store(base_fee, Ordering::SeqCst);
    }
    if bytes_per_sov > 0 {
        TX_FEE_BYTES_PER_SOV.store(bytes_per_sov, Ordering::SeqCst);
    }
    if witness_cap > 0 {
        TX_FEE_WITNESS_CAP.store(witness_cap, Ordering::SeqCst);
    }
}

/// Parse fee config JSON from /api/v1/blockchain/fee-config and apply locally.
pub fn set_fee_config_from_json(json: &str) -> Result<(), String> {
    #[derive(Deserialize)]
    struct FeeConfigPayload {
        base_fee: u64,
        bytes_per_sov: u64,
        witness_cap: u32,
        #[allow(dead_code)]
        updated_at_height: Option<u64>,
        #[allow(dead_code)]
        chain_height: Option<u64>,
    }

    let payload: FeeConfigPayload =
        serde_json::from_str(json).map_err(|e| format!("Invalid fee config JSON: {}", e))?;
    set_fee_config(payload.base_fee, payload.bytes_per_sov, payload.witness_cap);
    Ok(())
}

pub struct FeeConfigMeta {
    pub updated_at_height: u64,
    pub chain_height: u64,
}

/// Parse fee config JSON and return metadata.
pub fn set_fee_config_from_json_with_meta(json: &str) -> Result<FeeConfigMeta, String> {
    #[derive(Deserialize)]
    struct FeeConfigPayload {
        base_fee: u64,
        bytes_per_sov: u64,
        witness_cap: u32,
        updated_at_height: Option<u64>,
        chain_height: Option<u64>,
    }

    let payload: FeeConfigPayload =
        serde_json::from_str(json).map_err(|e| format!("Invalid fee config JSON: {}", e))?;
    set_fee_config(payload.base_fee, payload.bytes_per_sov, payload.witness_cap);
    Ok(FeeConfigMeta {
        updated_at_height: payload.updated_at_height.unwrap_or(0),
        chain_height: payload.chain_height.unwrap_or(0),
    })
}

// ============================================================================
// Token Operation Parameters (kept for backward compatibility)
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
    pub to: Vec<u8>,  // PublicKey bytes or key_id (32 bytes)
    pub amount: u64,
}

/// Parameters for burning tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnParams {
    pub token_id: [u8; 32],
    pub amount: u64,
}

// ============================================================================
// Domain Operation Parameters
// ============================================================================

/// Parameters for registering a domain (matches server's SimpleDomainRegistrationRequest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRegisterParams {
    pub domain: String,
    pub owner: String,
    #[serde(default)]
    pub content_mappings: std::collections::HashMap<String, ContentMapping>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    pub signature: String,
    pub timestamp: u64,
    #[serde(default)]
    pub fee: Option<u64>,
    #[serde(default)]
    pub fee_payment_tx: Option<String>,
}

/// Content mapping for domain registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMapping {
    pub content: String,
    pub content_type: String,
}

/// Parameters for updating a domain (matches server's DomainUpdateRequest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainUpdateParams {
    pub domain: String,
    pub new_manifest_cid: String,
    pub expected_previous_manifest_cid: String,
    pub signature: String,
    pub timestamp: u64,
}

/// Parameters for transferring a domain (matches server's ApiDomainTransferRequest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTransferParams {
    pub domain: String,
    pub from_owner: String,
    pub to_owner: String,
    pub transfer_proof: String,
}

// ============================================================================
// Generic Transaction Builder
// ============================================================================

/// Build a signed contract transaction for ANY contract type
///
/// CRITICAL: Uses lib-blockchain's signing_hash() for deterministic, version-safe signing.
/// This ensures compatibility between server, CLI, and mobile clients.
///
/// # Arguments
/// * `identity` - The signer's identity (contains Dilithium keypair)
/// * `contract_type` - Type of contract (Token, DomainRegistry, Identity, etc.)
/// * `method` - Contract method name (e.g., "transfer", "register", "mint")
/// * `params` - Serialized parameters (bincode bytes)
/// * `chain_id` - Network chain ID
///
/// # Returns
/// Hex-encoded signed transaction ready for API submission
///
/// # Example
/// ```ignore
/// // For token transfer:
/// let params = bincode::serialize(&TransferParams { ... })?;
/// let tx_hex = build_contract_transaction(&identity, ContractType::Token, "transfer", params, 1)?;
///
/// // For domain registration:
/// let params = bincode::serialize(&DomainRegisterParams { ... })?;
/// let tx_hex = build_contract_transaction(&identity, ContractType::DomainRegistry, "register", params, 1)?;
/// ```
pub fn build_contract_transaction(
    identity: &Identity,
    contract_type: ContractType,
    method: &str,
    params: Vec<u8>,
    chain_id: u8,
) -> Result<String, String> {
    eprintln!("[contract_tx] Contract: {:?}", &contract_type);
    eprintln!("[contract_tx] Method: {}", method);

    // Build ContractCall with Public permissions
    // Authorization is via tx.signature.public_key, not the permissions field
    let call = ContractCall {
        contract_type,
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
        algorithm: SignatureAlgorithm::Dilithium5, // Use Dilithium2 to match identity key type
        timestamp: 0,
    };

    let call_and_sig = (&call, &memo_sig);
    let call_data = bincode::serialize(&call_and_sig)
        .map_err(|e| format!("Failed to serialize call: {}", e))?;

    let mut memo = b"ZHTP".to_vec();
    memo.extend(call_data);

    // Step 1: Calculate dynamic fee based on estimated transaction size
    // Fee formula: ~0.119 SOV per byte, or 1 SOV per ~8.4 bytes
    // Server calculation: fee = ceil(transaction_size_bytes / 8.4)
    let estimated_tx_size = 200 // minimum fixed fields
        + memo.len() // memo variable size
        + 7187; // Dilithium5 witness: 4595 byte sig + 2592 byte pk

    // Calculate fee using integer arithmetic: ceil(size / 8.4) = ceil(size * 10 / 84)
    // This ensures: 10083 bytes -> 1200 SOV (matches server requirement)
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
            algorithm: SignatureAlgorithm::Dilithium5,
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
        token_transfer_data: None,
            token_mint_data: None,
                    governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
    };

    eprintln!("[contract_tx] Chain ID: {}", chain_id);
    eprintln!("[contract_tx] Memo length: {} bytes", memo.len());
    eprintln!("[contract_tx] Public key size: {}", identity.public_key.len());
    eprintln!("[contract_tx] Estimated tx size: {} bytes", estimated_tx_size);
    eprintln!("[contract_tx] Calculated minimum fee: {} SOV", min_fee);

    // Step 3: Use signing_hash() - deterministic field-by-field hashing
    // This is the SAFE method that won't break when Transaction struct changes
    let tx_hash = tx.signing_hash();

    eprintln!("[contract_tx] Signing hash: {}", hex::encode(tx_hash.as_bytes()));

    // Step 4: Sign the hash with Dilithium
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    eprintln!("[contract_tx] Signature size: {} bytes", signature_bytes.len());

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

    // Step 6: Serialize final transaction with signature for transmission
    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize final tx: {}", e))?;

    eprintln!("[contract_tx] Final tx size: {} bytes (estimated was {})", final_tx_bytes.len(), estimated_tx_size);
    eprintln!("[contract_tx] Fee verification: {} SOV for {} bytes = {:.3} SOV/byte",
        min_fee, final_tx_bytes.len(),
        min_fee as f64 / final_tx_bytes.len() as f64);

    // Hex encode for API
    Ok(hex::encode(final_tx_bytes))
}

// ============================================================================
// Convenience: Token-specific API (backward compatible)
// ============================================================================

/// Build a signed token transfer transaction with nonce for replay protection.
pub fn build_transfer_tx(
    identity: &Identity,
    token_id: &[u8; 32],
    to_pubkey: &[u8],
    amount: u64,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    if *token_id == generate_lib_token_id() || *token_id == [0u8; 32] {
        return Err("SOV transfers require wallet_id; use build_sov_wallet_transfer_tx".to_string());
    }
    let sender_pk = create_public_key(identity.public_key.clone());

    let to_key_id = if to_pubkey.len() == 32 {
        // 32 bytes: already a key_id (blake3 hash)
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(to_pubkey);
        key_id
    } else if to_pubkey.len() >= 1000 {
        // Full Dilithium public key: Dilithium2 (1312 bytes) or Dilithium5 (2592 bytes)
        // Derive wallet_id as blake3(dilithium_pk)
        create_public_key(to_pubkey.to_vec()).key_id
    } else {
        return Err(format!(
            "Invalid recipient public key length: {} (expected 32-byte key_id or full Dilithium2/5 key)",
            to_pubkey.len()
        ));
    };

    let transfer_data = TokenTransferData {
        token_id: *token_id,
        from: sender_pk.key_id,
        to: to_key_id,
        amount: amount as u128,
        nonce,
    };

    let mut tx = Transaction::new_token_transfer_with_chain_id(
        chain_id,
        transfer_data,
        Signature {
            signature: vec![],
            public_key: sender_pk.clone(),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        },
        Vec::new(),
    );

    let fee = calculate_transfer_fee(identity, &mut tx)?;
    tx.fee = fee;

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: sender_pk,
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize final tx: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

/// Build a signed SOV wallet-based transfer transaction with nonce for replay protection.
pub fn build_sov_wallet_transfer_tx(
    identity: &Identity,
    from_wallet_id: &[u8; 32],
    to_wallet_id: &[u8; 32],
    amount: u64,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    let sender_pk = create_public_key(identity.public_key.clone());

    let transfer_data = TokenTransferData {
        token_id: generate_lib_token_id(),
        from: *from_wallet_id,
        to: *to_wallet_id,
        amount: amount as u128,
        nonce,
    };

    let mut tx = Transaction::new_token_transfer_with_chain_id(
        chain_id,
        transfer_data,
        Signature {
            signature: vec![],
            public_key: sender_pk.clone(),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        },
        Vec::new(),
    );

    let fee = calculate_transfer_fee(identity, &mut tx)?;
    tx.fee = fee;

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: sender_pk,
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize final tx: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

fn calculate_transfer_fee(identity: &Identity, tx: &mut Transaction) -> Result<u64, String> {
    // Sign once to estimate size with real signature length.
    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign for fee estimation: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: create_public_key(identity.public_key.clone()),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize tx for fee estimation: {}", e))?;

    let base_fee = TX_FEE_BASE_FEE.load(Ordering::SeqCst);
    let bytes_per_sov = TX_FEE_BYTES_PER_SOV.load(Ordering::SeqCst);
    let witness_cap = TX_FEE_WITNESS_CAP.load(Ordering::SeqCst);

    let min_fee = calculate_min_fee_from_size(tx_bytes.len(), base_fee, bytes_per_sov, witness_cap);
    Ok(min_fee)
}

fn calculate_min_fee_from_size(
    tx_size: usize,
    base_fee: u64,
    bytes_per_sov: u64,
    witness_cap: u32,
) -> u64 {
    const PQ_WITNESS_SIZE: usize = 7219;

    let payload_bytes = tx_size.saturating_sub(PQ_WITNESS_SIZE);
    let witness_bytes = tx_size.saturating_sub(payload_bytes);
    let effective_size = payload_bytes + witness_bytes.min(witness_cap as usize);

    let size_fee = (effective_size as u64 / bytes_per_sov).max(1);
    base_fee + size_fee
}

/// Calculate the minimum fee for a hex-encoded bincode transaction.
/// If the signature/public key is missing, a Dilithium5 witness is assumed.
pub fn calculate_min_fee_for_tx_hex(tx_hex: &str) -> Result<u64, String> {
    let raw = hex::decode(tx_hex).map_err(|e| format!("Invalid hex: {}", e))?;
    let mut tx: Transaction = bincode::deserialize(&raw)
        .map_err(|e| format!("Failed to deserialize tx: {}", e))?;

    let sig_len = tx.signature.signature.len();
    let pk_len = tx.signature.public_key.dilithium_pk.len();
    if sig_len == 0 || pk_len == 0 {
        let (expected_sig, expected_pk) = match tx.signature.algorithm {
            SignatureAlgorithm::Dilithium2 => (2420usize, 1312usize),
            _ => (4595usize, 2592usize), // Dilithium5 (identity default)
        };
        tx.signature.signature = vec![0u8; expected_sig];
        tx.signature.public_key.dilithium_pk = vec![0u8; expected_pk];
    }

    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize tx: {}", e))?;

    let base_fee = TX_FEE_BASE_FEE.load(Ordering::SeqCst);
    let bytes_per_sov = TX_FEE_BYTES_PER_SOV.load(Ordering::SeqCst);
    let witness_cap = TX_FEE_WITNESS_CAP.load(Ordering::SeqCst);

    Ok(calculate_min_fee_from_size(
        tx_bytes.len(),
        base_fee,
        bytes_per_sov,
        witness_cap,
    ))
}

/// Build a signed token mint transaction
pub fn build_mint_tx(
    identity: &Identity,
    token_id: &[u8; 32],
    to_pubkey: &[u8],
    amount: u64,
    chain_id: u8,
) -> Result<String, String> {
    let to_key_id = if to_pubkey.len() == 32 {
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(to_pubkey);
        key_id
    } else if to_pubkey.len() >= 2000 {
        create_public_key(to_pubkey.to_vec()).key_id
    } else {
        return Err(format!(
            "Invalid mint recipient key length: {} (expected 32-byte key_id or full Dilithium key)",
            to_pubkey.len()
        ));
    };

    let signer_pk = create_public_key(identity.public_key.clone());
    let mint_data = TokenMintData {
        token_id: *token_id,
        to: to_key_id,
        amount: amount as u128,
    };

    let mut tx = Transaction::new_token_mint_with_chain_id(
        chain_id,
        mint_data,
        Signature {
            signature: vec![],
            public_key: signer_pk.clone(),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        },
        Vec::new(),
    );

    tx.fee = 0;
    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize final tx: {}", e))?;
    Ok(hex::encode(final_tx_bytes))
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
    let payload = TokenCreationPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        initial_supply,
        decimals,
    };
    let memo = payload
        .encode_memo()
        .map_err(|e| format!("Invalid token creation payload: {}", e))?;
    let signer_pk = create_public_key(identity.public_key.clone());
    let mut tx = Transaction::new_token_creation_with_chain_id(
        chain_id,
        Signature {
            signature: vec![],
            public_key: signer_pk.clone(),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        },
        memo,
    );

    tx.fee = 0;
    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: signer_pk,
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize tx for fee estimation: {}", e))?;
    tx.fee = calculate_min_fee_from_size(
        tx_bytes.len(),
        TX_FEE_BASE_FEE.load(Ordering::SeqCst),
        TX_FEE_BYTES_PER_SOV.load(Ordering::SeqCst),
        TX_FEE_WITNESS_CAP.load(Ordering::SeqCst),
    );

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;
    tx.signature = Signature {
        signature: signature_bytes,
        public_key: create_public_key(identity.public_key.clone()),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize final tx: {}", e))?;
    Ok(hex::encode(final_tx_bytes))
}

/// Build a signed token burn transaction
pub fn build_burn_tx(
    _identity: &Identity,
    token_id: &[u8; 32],
    amount: u64,
    _chain_id: u8,
) -> Result<String, String> {
    let _ = (token_id, amount);
    Err("Token burn via ContractExecution is disabled; use canonical typed token mutation transactions".to_string())
}

// ============================================================================
// Convenience: Domain-specific API
// ============================================================================

use crate::crypto::Dilithium5;

/// Domain registration fee in SOV tokens
const DOMAIN_REGISTRATION_FEE: u64 = 10;

/// Build a signed domain registration request (JSON format matching server's SimpleDomainRegistrationRequest)
///
/// # Arguments
/// * `identity` - The identity registering the domain (becomes owner)
/// * `domain` - Domain name (e.g., "example.sov")
/// * `content_mappings` - Optional content mappings (path -> content)
///
/// # Returns
/// Returns an error unless a canonical `fee_payment_tx` is provided.
///
/// Use `build_domain_register_request_with_fee_payment` for valid requests.
#[deprecated(
    since = "0.3.0",
    note = "Domain registration requires fee_payment_tx; use build_domain_register_request_with_fee_payment"
)]
pub fn build_domain_register_request(
    identity: &Identity,
    domain: &str,
    content_mappings: Option<std::collections::HashMap<String, ContentMapping>>,
) -> Result<String, String> {
    let _ = (identity, domain, content_mappings);
    Err(
        "build_domain_register_request is deprecated: fee_payment_tx is required. \
         Use build_domain_register_request_with_fee_payment(...) with a signed canonical fee transaction."
            .to_string(),
    )
}

/// Build a signed domain registration request and attach a signed canonical fee tx.
///
/// `fee_payment_tx` must be a hex-encoded signed TokenTransfer transaction that pays
/// the domain registration fee from owner's Primary wallet to the DAO treasury wallet.
pub fn build_domain_register_request_with_fee_payment(
    identity: &Identity,
    domain: &str,
    content_mappings: Option<std::collections::HashMap<String, ContentMapping>>,
    fee_payment_tx: Option<String>,
) -> Result<String, String> {
    if fee_payment_tx.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
        return Err(
            "fee_payment_tx is required for domain registration. \
             Provide a hex-encoded signed canonical TokenTransfer paying the DAO treasury."
                .to_string(),
        );
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Failed to get timestamp: {}", e))?
        .as_secs();

    // Sign: domain|timestamp|fee_amount
    let message = format!("{}|{}|{}", domain, timestamp, DOMAIN_REGISTRATION_FEE);
    let signature = Dilithium5::sign(message.as_bytes(), &identity.private_key)
        .map_err(|e| format!("Failed to sign: {}", e))?;

    let request = DomainRegisterParams {
        domain: domain.to_string(),
        owner: identity.did.clone(),
        content_mappings: content_mappings.unwrap_or_default(),
        metadata: None,
        signature: hex::encode(&signature),
        timestamp,
        fee: Some(DOMAIN_REGISTRATION_FEE),
        fee_payment_tx,
    };

    serde_json::to_string(&request)
        .map_err(|e| format!("Failed to serialize request: {}", e))
}

/// Build a signed domain update request (JSON format matching server's DomainUpdateRequest)
///
/// # Arguments
/// * `identity` - The domain owner's identity
/// * `domain` - Domain name to update
/// * `new_manifest_cid` - CID of the new manifest
/// * `expected_previous_manifest_cid` - Expected current manifest CID (for compare-and-swap)
///
/// # Returns
/// JSON string ready to POST to /api/v1/web4/domains/update
pub fn build_domain_update_request(
    identity: &Identity,
    domain: &str,
    new_manifest_cid: &str,
    expected_previous_manifest_cid: &str,
) -> Result<String, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Failed to get timestamp: {}", e))?
        .as_secs();

    // Sign: domain|expected_previous_manifest_cid|new_manifest_cid|timestamp
    let message = format!("{}|{}|{}|{}", domain, expected_previous_manifest_cid, new_manifest_cid, timestamp);
    let signature = Dilithium5::sign(message.as_bytes(), &identity.private_key)
        .map_err(|e| format!("Failed to sign: {}", e))?;

    let request = DomainUpdateParams {
        domain: domain.to_string(),
        new_manifest_cid: new_manifest_cid.to_string(),
        expected_previous_manifest_cid: expected_previous_manifest_cid.to_string(),
        signature: hex::encode(&signature),
        timestamp,
    };

    serde_json::to_string(&request)
        .map_err(|e| format!("Failed to serialize request: {}", e))
}

/// Build a signed domain transfer request (JSON format matching server's ApiDomainTransferRequest)
///
/// # Arguments
/// * `identity` - The current domain owner's identity
/// * `domain` - Domain name to transfer
/// * `to_owner` - New owner's DID (did:zhtp:hex format)
///
/// # Returns
/// JSON string ready to POST to /api/v1/web4/domains/transfer
pub fn build_domain_transfer_request(
    identity: &Identity,
    domain: &str,
    to_owner: &str,
) -> Result<String, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Failed to get timestamp: {}", e))?
        .as_secs();

    // Sign: domain|from_owner|to_owner|timestamp
    let message = format!("{}|{}|{}|{}", domain, identity.did, to_owner, timestamp);
    let signature = Dilithium5::sign(message.as_bytes(), &identity.private_key)
        .map_err(|e| format!("Failed to sign: {}", e))?;

    let request = DomainTransferParams {
        domain: domain.to_string(),
        from_owner: identity.did.clone(),
        to_owner: to_owner.to_string(),
        transfer_proof: hex::encode(&signature),
    };

    serde_json::to_string(&request)
        .map_err(|e| format!("Failed to serialize request: {}", e))
}

// Legacy function names for backward compatibility - these now call the new JSON-based functions
#[deprecated(since = "0.2.0", note = "Use build_domain_register_request instead")]
pub fn build_domain_register_tx(
    identity: &Identity,
    domain: &str,
    _content_cid: Option<&str>,
    _chain_id: u8,
) -> Result<String, String> {
    let _ = (identity, domain);
    Err(
        "build_domain_register_tx is deprecated: fee_payment_tx is required. \
         Use build_domain_register_request_with_fee_payment(...) instead."
            .to_string(),
    )
}

#[deprecated(since = "0.2.0", note = "Use build_domain_update_request instead")]
pub fn build_domain_update_tx(
    identity: &Identity,
    domain: &str,
    content_cid: &str,
    _chain_id: u8,
) -> Result<String, String> {
    // For legacy calls, use content_cid as both new and expected (not ideal but maintains compat)
    build_domain_update_request(identity, domain, content_cid, "")
}

#[deprecated(since = "0.2.0", note = "Use build_domain_transfer_request instead")]
pub fn build_domain_transfer_tx(
    identity: &Identity,
    domain: &str,
    to_pubkey: &[u8],
    _chain_id: u8,
) -> Result<String, String> {
    // Convert pubkey bytes to DID format for legacy callers
    let to_did = format!("did:zhtp:{}", hex::encode(to_pubkey));
    build_domain_transfer_request(identity, domain, &to_did)
}
