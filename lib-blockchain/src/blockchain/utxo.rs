//! Sled-first UTXO read facades (#2662).
//!
//! In-memory `utxo_set` keys are legacy `blake3(tx_hash ‖ index_le)` hashes
//! (see [`Blockchain::legacy_utxo_hash`]). Sled keys are canonical
//! [`OutPoint`] `{ tx, index }` with [`Utxo`] values. Handlers must use these
//! facades instead of reading `utxo_set` directly.

use super::*;
use crate::storage::{Address, BlockchainStore, OutPoint, StorageResult, Utxo};

/// Normalized spendable output for handler scans (marketplace, wallet payments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendableOutputView {
    /// Legacy in-mem map key — use as `TransactionInput.previous_output`.
    pub legacy_hash: Hash,
    /// Output index within the creating transaction (0 when unknown on in-mem path).
    pub output_index: u32,
    /// Owner id for wallet matching (`PublicKey::key_id` / sled `Address`).
    pub owner_key_id: [u8; 32],
}

impl Blockchain {
    /// Legacy in-memory UTXO map key: `blake3(tx_hash ‖ index_le)`.
    ///
    /// Sled uses [`OutPoint`] instead; this hash is **not reversible**. Genesis
    /// bootstrap may insert entries under ad-hoc hashes — those appear only on
    /// the in-mem fallback scan path.
    pub fn legacy_utxo_hash(tx_hash: &Hash, output_index: usize) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(tx_hash.as_bytes());
        data.extend_from_slice(&(output_index as u64).to_le_bytes());
        crate::types::hash::blake3_hash(&data)
    }

    /// Sled-first UTXO count for metrics / bootstrap probes.
    pub fn utxo_count(&self) -> usize {
        if let Some(store) = self.get_store() {
            match store.iter_utxos() {
                Ok(iter) => {
                    let mut n = 0usize;
                    for row in iter {
                        match row {
                            Ok(_) => n += 1,
                            Err(e) => {
                                tracing::warn!(error = %e, "utxo_count: sled scan error; using in-memory shadow");
                                return self.utxo_set.len();
                            }
                        }
                    }
                    return n;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "utxo_count: sled iter failed; using in-memory shadow");
                }
            }
        }
        self.utxo_set.len()
    }

    pub fn utxo_set_is_empty(&self) -> bool {
        self.utxo_count() == 0
    }

    /// Sled-first single-UTXO lookup by canonical outpoint.
    pub fn utxo_at_outpoint(&self, outpoint: &OutPoint) -> StorageResult<Option<Utxo>> {
        if let Some(store) = self.get_store() {
            return store.get_utxo(outpoint);
        }
        let tx_hash = Hash::from_slice(outpoint.tx.as_bytes());
        let legacy = Self::legacy_utxo_hash(&tx_hash, outpoint.index as usize);
        Ok(self.utxo_set.get(&legacy).map(|output| Utxo {
            amount: 0,
            owner: Address::new(output.recipient.key_id),
            token: crate::storage::TokenId::NATIVE,
            created_at_height: 0,
            script: None,
            merkle_leaf: if output.merkle_leaf == Hash::default() {
                None
            } else {
                Some(output.merkle_leaf.as_array())
            },
        }))
    }

    /// Collect spendable outputs for handler scans. Sled-first when a store is
    /// attached; falls back to the in-memory `utxo_set` shadow in store-less
    /// mode or on sled scan failure.
    pub fn collect_spendable_outputs(&self) -> Vec<SpendableOutputView> {
        if let Some(store) = self.get_store() {
            match store.iter_utxos() {
                Ok(iter) => {
                    let mut out = Vec::new();
                    for row in iter {
                        let Ok((op, utxo)) = row else {
                            tracing::warn!("collect_spendable_outputs: sled row error; using in-memory shadow");
                            return self.collect_spendable_outputs_in_mem();
                        };
                        let tx_hash = Hash::from_slice(op.tx.as_bytes());
                        out.push(SpendableOutputView {
                            legacy_hash: Self::legacy_utxo_hash(
                                &tx_hash,
                                op.index as usize,
                            ),
                            output_index: op.index,
                            owner_key_id: utxo.owner.0,
                        });
                    }
                    return out;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "collect_spendable_outputs: sled iter failed; using in-memory shadow");
                }
            }
        }
        self.collect_spendable_outputs_in_mem()
    }

    /// Outputs owned by `owner_key_id` (`PublicKey::key_id` / wallet id bytes).
    pub fn spendable_outputs_for_owner(
        &self,
        owner_key_id: &[u8; 32],
    ) -> Vec<SpendableOutputView> {
        self.collect_spendable_outputs()
            .into_iter()
            .filter(|v| v.owner_key_id == *owner_key_id)
            .collect()
    }

    fn collect_spendable_outputs_in_mem(&self) -> Vec<SpendableOutputView> {
        self.utxo_set
            .iter()
            .map(|(legacy_hash, output)| SpendableOutputView {
                legacy_hash: *legacy_hash,
                output_index: 0,
                owner_key_id: output.recipient.key_id,
            })
            .collect()
    }
}