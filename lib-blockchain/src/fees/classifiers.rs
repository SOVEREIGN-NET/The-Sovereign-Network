//! Byte Classifiers for Phase-2 Transaction Types
//!
//! Classifies transaction bytes into categories for fee calculation:
//! - **envelope_bytes**: Fixed header fields and type tags (constant per tx type)
//! - **payload_bytes**: Intent fields (inputs, outputs, amounts, token transfer data)
//! - **witness_bytes**: Signature bytes + public key bytes + ZK proof bytes

use crate::transaction::Transaction;
use crate::types::TransactionType;
use super::types::{FeeInput, TxKind, SigScheme};

/// Size constants for byte classification
mod sizes {
    /// Fixed envelope size for all transactions
    /// version (4) + chain_id (1) + tx_type (1) + fee (8) = 14 bytes
    pub const BASE_ENVELOPE: u32 = 14;

    /// TransactionInput layout:
    /// previous_output (32) + output_index (4) + nullifier (32) = 68 bytes base
    /// ZK proof is witness, not payload
    pub const INPUT_PAYLOAD: u32 = 68;

    /// TransactionOutput layout:
    /// commitment (32) + note (32) + recipient pubkey (variable, ~32-64)
    pub const OUTPUT_PAYLOAD_MIN: u32 = 96;

    /// TokenTransferData layout:
    /// token_id (32) + from (32) + to (32) + amount (16) + nonce (8) = 120 bytes
    pub const TOKEN_TRANSFER_PAYLOAD: u32 = 120;

    /// Estimated ZK proof size (per input)
    pub const ZK_PROOF_SIZE: u32 = 256;

    /// Estimated signature sizes by scheme
    pub const ED25519_SIG_SIZE: u32 = 64;
    pub const DILITHIUM5_SIG_SIZE: u32 = 4627;
    pub const HYBRID_SIG_SIZE: u32 = ED25519_SIG_SIZE + DILITHIUM5_SIG_SIZE;

    /// Public key sizes
    pub const ED25519_PUBKEY_SIZE: u32 = 32;
    pub const DILITHIUM5_PUBKEY_SIZE: u32 = 2592;

    /// Balance entry size estimate (for state write bytes)
    pub const BALANCE_ENTRY_SIZE: u32 = 64; // token_id + address + balance + nonce

    /// UTXO entry size estimate
    pub const UTXO_ENTRY_SIZE: u32 = 128; // outpoint + commitment + note + recipient
}

/// Classify a Transfer (native UTXO) transaction.
///
/// # Byte Classification
///
/// - **envelope**: Fixed headers (version, chain_id, tx_type, fee)
/// - **payload**: Inputs (outpoint refs) + Outputs (commitments, notes, recipients) + memo
/// - **witness**: Signature + public key + ZK proofs (per input)
///
/// # State Operations
///
/// - **reads**: Number of inputs (each input UTXO is read)
/// - **writes**: Number of inputs (deleted) + number of outputs (created)
/// - **write_bytes**: UTXO_ENTRY_SIZE * (inputs + outputs)
pub fn classify_transfer(tx: &Transaction) -> FeeInput {
    let envelope_bytes = sizes::BASE_ENVELOPE;

    // Payload: inputs (refs only) + outputs + memo
    let input_payload = tx.inputs.len() as u32 * sizes::INPUT_PAYLOAD;
    let output_payload = tx.outputs.len() as u32 * sizes::OUTPUT_PAYLOAD_MIN;
    let memo_payload = tx.memo.len() as u32;
    let payload_bytes = input_payload + output_payload + memo_payload;

    // Witness: signature + pubkey + ZK proofs
    let sig_bytes = estimate_signature_size(&tx.signature);
    let pubkey_bytes = estimate_pubkey_size(&tx.signature);
    let zk_proof_bytes = tx.inputs.len() as u32 * sizes::ZK_PROOF_SIZE;
    let witness_bytes = sig_bytes + pubkey_bytes + zk_proof_bytes;

    // State operations
    let state_reads = tx.inputs.len() as u16;
    let state_writes = (tx.inputs.len() + tx.outputs.len()) as u16;
    let state_write_bytes = state_writes as u32 * sizes::UTXO_ENTRY_SIZE;

    FeeInput::new(
        TxKind::NativeTransfer,
        detect_sig_scheme(&tx.signature),
        1, // One signature per transaction
        envelope_bytes,
        payload_bytes,
        witness_bytes,
        state_reads,
        state_writes,
        state_write_bytes,
    )
}

/// Classify a TokenTransfer (balance model) transaction.
///
/// # Byte Classification
///
/// - **envelope**: Fixed headers
/// - **payload**: TokenTransferData (token_id, from, to, amount, nonce) + memo
/// - **witness**: Signature + public key (no ZK proofs for balance model)
///
/// # State Operations
///
/// - **reads**: 2 (sender balance + receiver balance)
/// - **writes**: 2 (update sender + update receiver)
/// - **write_bytes**: 2 * BALANCE_ENTRY_SIZE
pub fn classify_token_transfer(tx: &Transaction) -> FeeInput {
    let envelope_bytes = sizes::BASE_ENVELOPE;

    // Payload: TokenTransferData + memo
    let token_payload = sizes::TOKEN_TRANSFER_PAYLOAD;
    let memo_payload = tx.memo.len() as u32;
    let payload_bytes = token_payload + memo_payload;

    // Witness: signature + pubkey only (no ZK proofs for balance model)
    let sig_bytes = estimate_signature_size(&tx.signature);
    let pubkey_bytes = estimate_pubkey_size(&tx.signature);
    let witness_bytes = sig_bytes + pubkey_bytes;

    // State operations: read/write sender and receiver balances
    let state_reads = 2;
    let state_writes = 2;
    let state_write_bytes = 2 * sizes::BALANCE_ENTRY_SIZE;

    FeeInput::new(
        TxKind::TokenTransfer,
        detect_sig_scheme(&tx.signature),
        1, // One signature
        envelope_bytes,
        payload_bytes,
        witness_bytes,
        state_reads,
        state_writes,
        state_write_bytes,
    )
}

/// Classify a Coinbase transaction.
///
/// # Byte Classification
///
/// - **envelope**: Fixed headers
/// - **payload**: Outputs only (no inputs for coinbase)
/// - **witness**: Minimal (coinbase doesn't require authorization)
///
/// # State Operations
///
/// - **reads**: 0 (no UTXOs consumed)
/// - **writes**: Number of outputs
/// - **write_bytes**: UTXO_ENTRY_SIZE * outputs
///
/// # Fee Behavior
///
/// Coinbase transactions have fee = 0 by protocol rule.
pub fn classify_coinbase(tx: &Transaction) -> FeeInput {
    let envelope_bytes = sizes::BASE_ENVELOPE;

    // Payload: outputs only + memo
    let output_payload = tx.outputs.len() as u32 * sizes::OUTPUT_PAYLOAD_MIN;
    let memo_payload = tx.memo.len() as u32;
    let payload_bytes = output_payload + memo_payload;

    // Coinbase has minimal witness (may have empty or validator signature)
    let witness_bytes = 0; // Coinbase doesn't require spend authorization

    // State operations: create output UTXOs
    let state_reads = 0;
    let state_writes = tx.outputs.len() as u16;
    let state_write_bytes = state_writes as u32 * sizes::UTXO_ENTRY_SIZE;

    FeeInput::new(
        TxKind::NativeTransfer, // Coinbase uses same base cost as transfer
        SigScheme::Dilithium5,     // Default scheme (not used for fee calc)
        0,                      // No signatures
        envelope_bytes,
        payload_bytes,
        witness_bytes,
        state_reads,
        state_writes,
        state_write_bytes,
    )
}

/// Classify any Phase-2 transaction type.
///
/// Returns None for unsupported transaction types.
pub fn classify_transaction(tx: &Transaction) -> Option<FeeInput> {
    match tx.transaction_type {
        TransactionType::Transfer => Some(classify_transfer(tx)),
        TransactionType::TokenTransfer => Some(classify_token_transfer(tx)),
        TransactionType::Coinbase => Some(classify_coinbase(tx)),
        _ => None, // Unsupported in Phase 2
    }
}

/// Detect signature scheme from the Signature struct.
fn detect_sig_scheme(sig: &crate::integration::crypto_integration::Signature) -> SigScheme {
    use crate::integration::crypto_integration::SignatureAlgorithm;

    match sig.algorithm {
        // Dilithium variants are post-quantum
        SignatureAlgorithm::Dilithium2 | SignatureAlgorithm::Dilithium5 => {
            SigScheme::Dilithium5 // Treat all Dilithium variants as Dilithium5 for fee purposes
        }
        SignatureAlgorithm::RingSignature => {
            SigScheme::Dilithium5 // Ring signatures use post-quantum crypto
        }
    }
}

/// Estimate signature size in bytes.
fn estimate_signature_size(sig: &crate::integration::crypto_integration::Signature) -> u32 {
    // Use actual signature bytes if available
    if !sig.signature.is_empty() {
        return sig.signature.len() as u32;
    }

    // Otherwise estimate based on algorithm (all are post-quantum)
    use crate::integration::crypto_integration::SignatureAlgorithm;
    match sig.algorithm {
        SignatureAlgorithm::Dilithium2 | SignatureAlgorithm::Dilithium5 => {
            sizes::DILITHIUM5_SIG_SIZE
        }
        SignatureAlgorithm::RingSignature => {
            sizes::DILITHIUM5_SIG_SIZE // Similar size to Dilithium
        }
    }
}

/// Estimate public key size in bytes.
fn estimate_pubkey_size(sig: &crate::integration::crypto_integration::Signature) -> u32 {
    // Use actual public key bytes if available
    let key_bytes = sig.public_key.as_bytes();
    if !key_bytes.is_empty() {
        return key_bytes.len() as u32;
    }

    // Otherwise estimate based on algorithm (all are post-quantum)
    use crate::integration::crypto_integration::SignatureAlgorithm;
    match sig.algorithm {
        SignatureAlgorithm::Dilithium2 | SignatureAlgorithm::Dilithium5 => {
            sizes::DILITHIUM5_PUBKEY_SIZE
        }
        SignatureAlgorithm::RingSignature => {
            sizes::DILITHIUM5_PUBKEY_SIZE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput};
    use crate::types::Hash;
    use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
    use crate::integration::zk_integration::ZkTransactionProof;

    fn create_test_transfer() -> Transaction {
        Transaction::new(
            vec![
                TransactionInput::new(
                    Hash::new([1u8; 32]),
                    0,
                    Hash::new([2u8; 32]),
                    ZkTransactionProof::default(),
                ),
            ],
            vec![
                TransactionOutput::new(
                    Hash::new([3u8; 32]),
                    Hash::new([4u8; 32]),
                    PublicKey::new(vec![5u8; 32]),
                ),
                TransactionOutput::new(
                    Hash::new([6u8; 32]),
                    Hash::new([7u8; 32]),
                    PublicKey::new(vec![8u8; 32]),
                ),
            ],
            1000, // fee
            Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey::new(vec![0u8; 32]),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            },
            b"test memo".to_vec(),
        )
    }

    fn create_test_token_transfer() -> Transaction {
        let mut tx = Transaction::new(
            vec![], // No UTXO inputs for token transfer
            vec![], // No UTXO outputs for token transfer
            0,      // Fee must be 0 for token transfers
            Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey::new(vec![0u8; 32]),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            },
            vec![],
        );
        tx.transaction_type = TransactionType::TokenTransfer;
        tx.token_transfer_data = Some(crate::transaction::TokenTransferData {
            token_id: [0u8; 32],
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 1000,
            nonce: 0,
        });
        tx
    }

    fn create_test_coinbase() -> Transaction {
        let mut tx = Transaction::new(
            vec![], // No inputs for coinbase
            vec![
                TransactionOutput::new(
                    Hash::new([1u8; 32]),
                    Hash::new([2u8; 32]),
                    PublicKey::new(vec![0u8; 32]),
                ),
            ],
            0, // Coinbase has no fee
            Signature {
                signature: vec![],
                public_key: PublicKey::new(vec![]),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            },
            vec![],
        );
        tx.transaction_type = TransactionType::Coinbase;
        tx
    }

    #[test]
    fn test_classify_transfer() {
        let tx = create_test_transfer();
        let fee_input = classify_transfer(&tx);

        // Check tx_kind
        assert_eq!(fee_input.tx_kind, TxKind::NativeTransfer);

        // Check sig_scheme
        assert_eq!(fee_input.sig_scheme, SigScheme::Dilithium5);

        // Check sig_count
        assert_eq!(fee_input.sig_count, 1);

        // Check envelope is constant
        assert_eq!(fee_input.envelope_bytes, 14);

        // Check state reads = inputs
        assert_eq!(fee_input.state_reads, 1);

        // Check state writes = inputs + outputs
        assert_eq!(fee_input.state_writes, 3); // 1 input + 2 outputs
    }

    #[test]
    fn test_classify_token_transfer() {
        let tx = create_test_token_transfer();
        let fee_input = classify_token_transfer(&tx);

        // Check tx_kind
        assert_eq!(fee_input.tx_kind, TxKind::TokenTransfer);

        // Check state operations for balance model
        assert_eq!(fee_input.state_reads, 2);  // sender + receiver
        assert_eq!(fee_input.state_writes, 2); // sender + receiver

        // Check no ZK proof bytes (balance model)
        // witness = sig (64) + pubkey (32) = 96
        assert_eq!(fee_input.witness_bytes, 96);
    }

    #[test]
    fn test_classify_coinbase() {
        let tx = create_test_coinbase();
        let fee_input = classify_coinbase(&tx);

        // Coinbase has no inputs
        assert_eq!(fee_input.state_reads, 0);

        // Coinbase has 1 output (the reward)
        assert_eq!(fee_input.state_writes, 1);

        // Coinbase has no witness (no spend authorization)
        assert_eq!(fee_input.witness_bytes, 0);

        // Coinbase has no signature
        assert_eq!(fee_input.sig_count, 0);
    }

    #[test]
    fn test_classify_transaction_routing() {
        let transfer = create_test_transfer();
        let token = create_test_token_transfer();
        let coinbase = create_test_coinbase();

        assert!(classify_transaction(&transfer).is_some());
        assert!(classify_transaction(&token).is_some());
        assert!(classify_transaction(&coinbase).is_some());

        // Create unsupported type
        let mut unsupported = create_test_transfer();
        unsupported.transaction_type = TransactionType::IdentityRegistration;
        assert!(classify_transaction(&unsupported).is_none());
    }

    #[test]
    fn test_dilithium_signature_detection() {
        let mut tx = create_test_transfer();
        tx.signature.algorithm = SignatureAlgorithm::Dilithium5;

        let fee_input = classify_transfer(&tx);
        assert_eq!(fee_input.sig_scheme, SigScheme::Dilithium5);
    }
}
