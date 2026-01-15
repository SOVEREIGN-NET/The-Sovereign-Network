//! DHT indexing for blockchain data (headers and transaction summaries).
//!
//! This bridges blockchain events into the lib-storage DHT. It is intentionally
//! lightweight and resilient to missing network data: when information such as
//! explicit sender addresses is unavailable, it will record a minimal placeholder
//! so downstream developers can continue integrating. Any placeholder is clearly
//! labeled as dummy data.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::integration::crypto_integration::public_key_bytes;
use crate::transaction::Transaction;
use lib_storage::dht::storage::DhtStorage;

/// Compact block header representation for DHT indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedBlockHeader {
    pub height: u64,
    pub hash_hex: String,
    pub prev_hash_hex: String,
    pub timestamp: u64,
}

/// Minimal transaction summary for address-based indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedTransactionSummary {
    pub tx_id_hex: String,
    pub sender_hint: String,
    pub recipient_hex: String,
    pub amount_hint: u64,
    pub block_height: u64,
}

/// Validate that a key belongs to the blockchain namespace (not domain storage)
/// This prevents cross-namespace pollution if MeshRouter and UnifiedStorageSystem
/// accidentally share the same persistence file.
fn validate_blockchain_key(key: &str) -> Result<()> {
    if key.starts_with("web4/") || key.starts_with("identity/") || key.starts_with("manifest:") {
        return Err(anyhow::anyhow!(
            "NAMESPACE VIOLATION: Blockchain tried to store reserved key '{}'. \
            Reserved key prefixes are:\n  \
            - 'web4/' and 'manifest:' → Web4 domain/content storage (UnifiedStorageSystem)\n  \
            - 'identity/' → Identity management storage\n  \
            Blockchain keys should use prefixes like 'block_header:', 'tx_idx:' etc.\n\
            This error indicates DHT persistence file(s) are misconfigured. \
            Ensure separate persistence files for blockchain vs. Web4/identity operations.",
            key
        ));
    }
    Ok(())
}

/// Index a single block header and its transactions into the DHT.
///
/// Keys are stable strings, so they work across both in-memory and networked
/// storage:
/// - `block_header:{height}` -> Serialized [`IndexedBlockHeader`]
/// - `tx_idx:recipient:{recipient_hex}:{tx_id_hex}` -> Serialized [`IndexedTransactionSummary`]
/// - `tx_idx:sender:{sender_hint}:{tx_id_hex}`     -> Serialized [`IndexedTransactionSummary`]
pub async fn index_block(storage: &mut DhtStorage, block: &Block) -> Result<()> {
    index_block_header(storage, block).await?;
    for tx in &block.transactions {
        index_transaction(storage, tx, block.height()).await?;
    }
    Ok(())
}

/// Store a block header keyed by height.
pub async fn index_block_header(storage: &mut DhtStorage, block: &Block) -> Result<()> {
    let header = IndexedBlockHeader {
        height: block.height(),
        hash_hex: block.hash().to_hex(),
        prev_hash_hex: block.previous_hash().to_hex(),
        timestamp: block.timestamp(),
    };
    let key = format!("block_header:{}", header.height);
    validate_blockchain_key(&key)?;  // NAMESPACE GUARD
    let bytes = bincode::serialize(&header)?;
    storage.store(key, bytes, None).await
}

/// Store a transaction summary keyed by recipient and sender hint.
pub async fn index_transaction(
    storage: &mut DhtStorage,
    tx: &Transaction,
    block_height: u64,
) -> Result<()> {
    // Recipient index: create one entry per output recipient
    for output in &tx.outputs {
        let recipient_hex = hex::encode(public_key_bytes(&output.recipient));
        let summary = IndexedTransactionSummary {
            tx_id_hex: tx.hash().to_hex(),
            // We do not have an explicit sender address in the current transaction model.
            // Use the first input's previous_output as a stable sender hint; if no inputs,
            // mark it as system-generated.
            sender_hint: derive_sender_hint(tx),
            recipient_hex: recipient_hex.clone(),
            amount_hint: 0, // Dummy amount; actual values are hidden by commitments.
            block_height,
        };

        let key_recipient = format!("tx_idx:recipient:{}:{}", recipient_hex, summary.tx_id_hex);
        validate_blockchain_key(&key_recipient)?;  // NAMESPACE GUARD
        let bytes = bincode::serialize(&summary)?;
        storage.store(key_recipient, bytes, None).await?;
    }

    // Sender index: single entry per transaction using sender_hint
    let summary = IndexedTransactionSummary {
        tx_id_hex: tx.hash().to_hex(),
        sender_hint: derive_sender_hint(tx),
        recipient_hex: "broadcast".to_string(),
        amount_hint: 0, // Dummy amount; actual values are hidden by commitments.
        block_height,
    };
    let key_sender = format!("tx_idx:sender:{}:{}", summary.sender_hint, summary.tx_id_hex);
    validate_blockchain_key(&key_sender)?;  // NAMESPACE GUARD
    let bytes = bincode::serialize(&summary)?;
    storage.store(key_sender, bytes, None).await
}

fn derive_sender_hint(tx: &Transaction) -> String {
    if let Some(first_input) = tx.inputs.first() {
        // Use previous_output hash as a stable hint for sender tracing.
        return format!("prevout:{}", first_input.previous_output.to_hex());
    }
    "system-tx".to_string()
}
