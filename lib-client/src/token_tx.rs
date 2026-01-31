//! Token Transaction Builder
//!
//! Provides FFI-exportable functions for building signed token transactions.
//! iOS/Android clients call these to get hex-encoded transactions ready for the API.

use serde::{Deserialize, Serialize};
use crate::identity::Identity;
use crate::crypto;

// ============================================================================
// Transaction Types (minimal subset matching lib-blockchain bincode format)
// ============================================================================

/// Transaction type enum - must match lib-blockchain exactly for bincode compat
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionType {
    Transfer = 0,
    IdentityRegistration = 1,
    IdentityUpdate = 2,
    IdentityRevocation = 3,
    ContractDeployment = 4,
    ContractExecution = 5,
    SessionCreation = 6,
    SessionTermination = 7,
    ContentUpload = 8,
    UbiDistribution = 9,
    WalletRegistration = 10,
    ValidatorRegistration = 11,
    UBIClaim = 12,
    ProfitDeclaration = 13,
}

/// Signature algorithm enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519,
    Secp256k1,
    Dilithium5,
}

/// Public key wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub dilithium_pk: Vec<u8>,
    pub kyber_pk: Vec<u8>,
    pub key_id: [u8; 32],
}

impl PublicKey {
    pub fn new(dilithium_pk: Vec<u8>) -> Self {
        let key_id = crypto::Blake3::hash(&dilithium_pk);
        let mut key_id_arr = [0u8; 32];
        key_id_arr.copy_from_slice(&key_id[..32]);
        Self {
            dilithium_pk,
            kyber_pk: vec![],
            key_id: key_id_arr,
        }
    }
}

/// Signature structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub signature: Vec<u8>,
    pub public_key: PublicKey,
    pub algorithm: SignatureAlgorithm,
    pub timestamp: u64,
}

/// ZK proof placeholder (minimal for token txs which don't need ZK proofs)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZkProof {
    pub proof_system: String,
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub verification_key: Vec<u8>,
    pub plonky2_proof: Option<Vec<u8>>,
    pub proof: Vec<u8>,
}

/// ZK transaction proof
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZkTransactionProof {
    pub amount_proof: ZkProof,
    pub balance_proof: ZkProof,
    pub nullifier_proof: ZkProof,
}

/// Transaction input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: [u8; 32],
    pub output_index: u32,
    pub nullifier: [u8; 32],
    pub zk_proof: ZkTransactionProof,
}

/// Transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub commitment: [u8; 32],
    pub encrypted_amount: Vec<u8>,
    pub owner_commitment: [u8; 32],
    pub range_proof: ZkProof,
}

/// Contract type enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContractType {
    Token,
    WhisperMessaging,
    ContactRegistry,
    GroupChat,
    FileSharing,
    Custom,
}

/// Call permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallPermissions {
    Public,
    Restricted {
        caller: PublicKey,
        permissions: Vec<String>,
    },
    AdminOnly {
        admin: PublicKey,
    },
}

/// Contract call structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCall {
    pub contract_type: ContractType,
    pub method: String,
    pub params: Vec<u8>,
    pub permissions: CallPermissions,
}

/// Full transaction structure (matching lib-blockchain)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub chain_id: u8,
    pub transaction_type: TransactionType,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub fee: u64,
    pub signature: Signature,
    pub memo: Vec<u8>,
    pub identity_data: Option<()>,
    pub wallet_data: Option<()>,
    pub validator_data: Option<()>,
    pub dao_proposal_data: Option<()>,
    pub dao_vote_data: Option<()>,
    pub dao_execution_data: Option<()>,
    pub ubi_claim_data: Option<()>,
    pub profit_declaration_data: Option<()>,
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

    // Create signature struct (will be populated after signing)
    let public_key = PublicKey::new(identity.public_key.clone());

    // Build memo: "ZHTP" + bincode(call, placeholder_sig)
    let placeholder_sig = Signature {
        signature: vec![],
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp: 0,
    };

    let call_and_sig = (&call, &placeholder_sig);
    let call_data = bincode::serialize(&call_and_sig)
        .map_err(|e| format!("Failed to serialize call: {}", e))?;

    let mut memo = b"ZHTP".to_vec();
    memo.extend(call_data);

    // Build transaction without signature first
    let mut tx = Transaction {
        version: 1,
        chain_id,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![],
        fee: 1000,
        signature: Signature {
            signature: vec![],
            public_key: public_key.clone(),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        },
        memo,
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
    };

    // Serialize tx for signing (with empty signature)
    let tx_bytes_for_signing = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize tx: {}", e))?;

    // Sign the transaction
    let signature_bytes = crate::identity::sign_message(identity, &tx_bytes_for_signing)
        .map_err(|e| format!("Failed to sign: {}", e))?;

    // Update signature in transaction
    tx.signature.signature = signature_bytes;

    // Serialize final transaction
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_type_serialization() {
        // Ensure enum values match expected
        assert_eq!(TransactionType::ContractExecution as u8, 5);
    }
}
