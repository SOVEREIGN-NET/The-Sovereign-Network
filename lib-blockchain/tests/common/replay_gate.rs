//! Helpers for GENESIS-2 g4 replay acceptance gates (#2730).
//!
//! Captures balance checkpoints and produces actionable mismatch messages
//! (`token_id`, `address`, `have`, `need`) when wipe-and-replay diverges.

use std::path::Path;
use std::sync::Arc;

use lib_blockchain::contracts::bonding_curve::canonical::GENESIS_TREASURY_ALLOCATION;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::genesis::GenesisConfig;
use lib_blockchain::storage::{Address, BlockchainStore, TokenId};
use lib_blockchain::Blockchain;
use serde::{Deserialize, Serialize};

/// Balance checkpoint used to verify replay parity at a given height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCheckpointSnapshot {
    pub checkpoint_height: u64,
    pub sov_wallets: Vec<SovWalletBalance>,
    pub cbe_treasury_balance: u128,
    pub treasury_sov_balance: u128,
    /// Allowed absolute drift per balance (testnet coinbase / rounding tolerance).
    #[serde(default)]
    pub tolerance_atoms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovWalletBalance {
    pub wallet_id: String,
    pub balance: u128,
}

impl ReplayCheckpointSnapshot {
    pub fn from_store_at_height(
        store: &dyn BlockchainStore,
        checkpoint_height: u64,
        sov_wallet_ids: &[[u8; 32]],
    ) -> Self {
        let sov_token = TokenId::new(generate_lib_token_id());
        let cbe_token = TokenId::new(Blockchain::derive_cbe_token_id_pub());
        let treasury_addr = Address::new([0u8; 32]); // default fee_sink / CBE treasury

        let sov_wallets = sov_wallet_ids
            .iter()
            .map(|wallet_id| {
                let balance = store
                    .get_token_balance(&sov_token, &Address::new(*wallet_id))
                    .unwrap_or(0);
                SovWalletBalance {
                    wallet_id: hex::encode(wallet_id),
                    balance,
                }
            })
            .collect();

        Self {
            checkpoint_height,
            sov_wallets,
            cbe_treasury_balance: store
                .get_token_balance(&cbe_token, &treasury_addr)
                .unwrap_or(0),
            treasury_sov_balance: store
                .get_token_balance(&sov_token, &treasury_addr)
                .unwrap_or(0),
            tolerance_atoms: 0,
        }
    }

    pub fn load_json(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn assert_matches_store(
        &self,
        store: &dyn BlockchainStore,
        label: &str,
    ) -> Result<(), String> {
        let live = Self::from_store_at_height(
            store,
            self.checkpoint_height,
            &self
                .sov_wallets
                .iter()
                .map(|w| {
                    let mut arr = [0u8; 32];
                    let bytes = hex::decode(&w.wallet_id).map_err(|e| e.to_string())?;
                    if bytes.len() != 32 {
                        return Err(format!(
                            "invalid wallet_id length in snapshot: {}",
                            w.wallet_id
                        ));
                    }
                    arr.copy_from_slice(&bytes);
                    Ok(arr)
                })
                .collect::<Result<Vec<_>, String>>()?,
        );

        compare_snapshots(label, self, &live)
    }
}

pub fn first_n_genesis_sov_wallets(n: usize) -> Vec<[u8; 32]> {
    let cfg = GenesisConfig::from_embedded().expect("embedded genesis");
    let entries = cfg.sov_allocation_entries().expect("sov entries");
    assert!(
        entries.len() >= n,
        "embedded genesis must contain at least {n} sov_balances entries (have {})",
        entries.len()
    );
    entries.into_iter().take(n).map(|(id, _)| id).collect()
}

pub fn compare_snapshots(
    label: &str,
    expected: &ReplayCheckpointSnapshot,
    actual: &ReplayCheckpointSnapshot,
) -> Result<(), String> {
    let tol = expected.tolerance_atoms;

    if expected.checkpoint_height != actual.checkpoint_height {
        return Err(format!(
            "{label}: checkpoint height mismatch (expected {}, got {})",
            expected.checkpoint_height, actual.checkpoint_height
        ));
    }

    if expected.sov_wallets.len() != actual.sov_wallets.len() {
        return Err(format!(
            "{label}: SOV wallet sample count mismatch (expected {}, got {})",
            expected.sov_wallets.len(),
            actual.sov_wallets.len()
        ));
    }

    for (exp, act) in expected.sov_wallets.iter().zip(actual.sov_wallets.iter()) {
        if exp.wallet_id != act.wallet_id {
            return Err(format!(
                "{label}: SOV wallet ordering mismatch (expected {}, got {})",
                exp.wallet_id, act.wallet_id
            ));
        }
        if !within_tolerance(exp.balance, act.balance, tol) {
            let sov_token = hex::encode(generate_lib_token_id());
            return Err(format!(
                "{label}: SOV balance mismatch at height {} — token_id={sov_token} \
                 address={} have={} need={} (tolerance={tol})",
                expected.checkpoint_height, exp.wallet_id, act.balance, exp.balance
            ));
        }
    }

    if !within_tolerance(
        expected.cbe_treasury_balance,
        actual.cbe_treasury_balance,
        tol,
    ) {
        let cbe_token = hex::encode(Blockchain::derive_cbe_token_id_pub());
        return Err(format!(
            "{label}: CBE DAO treasury mismatch at height {} — token_id={cbe_token} \
             address={} have={} need={} (tolerance={tol}); \
             expected genesis allocation={GENESIS_TREASURY_ALLOCATION}",
            expected.checkpoint_height,
            hex::encode([0u8; 32]),
            actual.cbe_treasury_balance,
            expected.cbe_treasury_balance
        ));
    }

    if !within_tolerance(expected.treasury_sov_balance, actual.treasury_sov_balance, tol) {
        let sov_token = hex::encode(generate_lib_token_id());
        return Err(format!(
            "{label}: treasury SOV mismatch at height {} — token_id={sov_token} \
             address={} have={} need={} (tolerance={tol})",
            expected.checkpoint_height,
            hex::encode([0u8; 32]),
            actual.treasury_sov_balance,
            expected.treasury_sov_balance
        ));
    }

    Ok(())
}

fn within_tolerance(expected: u128, actual: u128, tolerance: u128) -> bool {
    if expected >= actual {
        expected - actual <= tolerance
    } else {
        actual - expected <= tolerance
    }
}

/// Load a bincode-serialised `Vec<Block>` fixture exported from a live node sled.
pub fn load_blocks_fixture(path: &Path) -> anyhow::Result<Vec<lib_blockchain::block::Block>> {
    let data = std::fs::read(path)?;
    bincode::deserialize(&data).map_err(|e| anyhow::anyhow!("block fixture decode failed: {e}"))
}

pub fn open_fresh_store(
    dir: &tempfile::TempDir,
) -> Arc<dyn BlockchainStore> {
    Arc::new(
        lib_blockchain::storage::SledStore::open(dir.path())
            .expect("open test sled store"),
    )
}