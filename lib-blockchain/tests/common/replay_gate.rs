//! Helpers for GENESIS-2 replay acceptance gates (#2730).
//!
//! **Test-only module.** `compare_snapshots` returns `Result<(), String>` deliberately —
//! these helpers are for integration tests, not production runtime self-checks.

use std::path::Path;
use std::sync::Arc;

use lib_blockchain::contracts::bonding_curve::canonical::GENESIS_TREASURY_ALLOCATION;
use lib_blockchain::contracts::utils::{generate_custom_token_id, generate_lib_token_id};
use lib_blockchain::genesis::GenesisConfig;
use lib_blockchain::protocol::ProtocolParams;
use lib_blockchain::storage::{Address, BlockchainStore, TokenId};
use lib_blockchain::sync::ReplayBlocksFixture;

/// Pre-GENESIS-3 testnet incident height (g4 wedged @ h=74_010). Meaningless after reset.
pub const G4_CHECKPOINT_HEIGHT_FLOOR: u64 = 74_010;
use lib_blockchain::Blockchain;
use serde::{Deserialize, Serialize};

/// Treasury / fee-sink address — same source as executor block-0 CBE seed.
pub fn cbe_treasury_address() -> Address {
    *ProtocolParams::default().fee_sink_address()
}

/// Balance checkpoint used to verify replay parity at a given height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCheckpointSnapshot {
    pub checkpoint_height: u64,
    pub sov_wallets: Vec<SovWalletBalance>,
    pub cbe_treasury_balance: u128,
    pub treasury_sov_balance: u128,
    /// DAO tokens (BUBL class) — balances after `TokenCreation` + transfers.
    #[serde(default)]
    pub dao_tokens: Vec<DaoTokenBalance>,
    /// Allowed absolute drift per balance (testnet coinbase / rounding tolerance).
    #[serde(default)]
    pub tolerance_atoms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovWalletBalance {
    pub wallet_id: String,
    pub balance: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoTokenBalance {
    pub token_id: String,
    pub symbol: String,
    pub holder_wallet_id: String,
    pub balance: u128,
}

impl ReplayCheckpointSnapshot {
    pub fn from_store_at_height(
        store: &dyn BlockchainStore,
        checkpoint_height: u64,
        sov_wallet_ids: &[[u8; 32]],
        dao_tokens: &[DaoTokenExpectation],
    ) -> Self {
        let sov_token = TokenId::new(generate_lib_token_id());
        let cbe_token = TokenId::new(Blockchain::derive_cbe_token_id_pub());
        let treasury_addr = cbe_treasury_address();

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

        let dao_token_balances = dao_tokens
            .iter()
            .map(|expect| {
                let token_id = TokenId::new(expect.token_id);
                let balance = store
                    .get_token_balance(&token_id, &Address::new(expect.holder_wallet_id))
                    .unwrap_or(0);
                DaoTokenBalance {
                    token_id: hex::encode(expect.token_id),
                    symbol: expect.symbol.to_string(),
                    holder_wallet_id: hex::encode(expect.holder_wallet_id),
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
            dao_tokens: dao_token_balances,
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
        let dao_expectations: Vec<DaoTokenExpectation> = self
            .dao_tokens
            .iter()
            .map(|d| {
                let mut token_id = [0u8; 32];
                let mut holder = [0u8; 32];
                let tid = hex::decode(&d.token_id).map_err(|e| e.to_string())?;
                let hid = hex::decode(&d.holder_wallet_id).map_err(|e| e.to_string())?;
                if tid.len() != 32 || hid.len() != 32 {
                    return Err("invalid hex length in dao_tokens snapshot".to_string());
                }
                token_id.copy_from_slice(&tid);
                holder.copy_from_slice(&hid);
                Ok(DaoTokenExpectation {
                    token_id,
                    symbol: d.symbol.clone(),
                    holder_wallet_id: holder,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        let sov_ids: Vec<[u8; 32]> = self
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
            .collect::<Result<Vec<_>, String>>()?;

        let live = Self::from_store_at_height(
            store,
            self.checkpoint_height,
            &sov_ids,
            &dao_expectations,
        );

        compare_snapshots(label, self, &live)
    }
}

pub struct DaoTokenExpectation {
    pub token_id: [u8; 32],
    pub symbol: String,
    pub holder_wallet_id: [u8; 32],
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

pub fn bubl_like_token_id() -> [u8; 32] {
    generate_custom_token_id("Bubble", "BUBL")
}

pub fn compare_snapshots(
    label: &str,
    expected: &ReplayCheckpointSnapshot,
    actual: &ReplayCheckpointSnapshot,
) -> Result<(), String> {
    let tol = expected.tolerance_atoms;
    let treasury_hex = hex::encode(cbe_treasury_address().as_bytes());

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

    if expected.dao_tokens.len() != actual.dao_tokens.len() {
        return Err(format!(
            "{label}: DAO token sample count mismatch (expected {}, got {})",
            expected.dao_tokens.len(),
            actual.dao_tokens.len()
        ));
    }

    for (exp, act) in expected.dao_tokens.iter().zip(actual.dao_tokens.iter()) {
        if exp.token_id != act.token_id || exp.holder_wallet_id != act.holder_wallet_id {
            return Err(format!(
                "{label}: DAO token sample key mismatch (expected {}@{}, got {}@{})",
                exp.token_id, exp.holder_wallet_id, act.token_id, act.holder_wallet_id
            ));
        }
        if !within_tolerance(exp.balance, act.balance, tol) {
            return Err(format!(
                "{label}: DAO token balance mismatch at height {} — token_id={} symbol={} \
                 address={} have={} need={} (tolerance={tol})",
                expected.checkpoint_height,
                exp.token_id,
                exp.symbol,
                exp.holder_wallet_id,
                act.balance,
                exp.balance
            ));
        }
    }

    // TODO(GENESIS-6, #2734): when block-0 CBE seed is removed, expect treasury from
    // founding TokenCreation replay instead of GENESIS_TREASURY_ALLOCATION.
    if !within_tolerance(
        expected.cbe_treasury_balance,
        actual.cbe_treasury_balance,
        tol,
    ) {
        let cbe_token = hex::encode(Blockchain::derive_cbe_token_id_pub());
        return Err(format!(
            "{label}: CBE DAO treasury mismatch at height {} — token_id={cbe_token} \
             address={treasury_hex} have={} need={} (tolerance={tol}); \
             legacy genesis allocation={GENESIS_TREASURY_ALLOCATION}",
            expected.checkpoint_height,
            actual.cbe_treasury_balance,
            expected.cbe_treasury_balance
        ));
    }

    if !within_tolerance(expected.treasury_sov_balance, actual.treasury_sov_balance, tol) {
        let sov_token = hex::encode(generate_lib_token_id());
        return Err(format!(
            "{label}: treasury SOV mismatch at height {} — token_id={sov_token} \
             address={treasury_hex} have={} need={} (tolerance={tol})",
            expected.checkpoint_height,
            actual.treasury_sov_balance,
            expected.treasury_sov_balance
        ));
    }

    Ok(())
}

pub fn within_tolerance(expected: u128, actual: u128, tolerance: u128) -> bool {
    if expected >= actual {
        expected - actual <= tolerance
    } else {
        actual - expected <= tolerance
    }
}

/// Load a versioned replay fixture (`blocks.v1.bin`) or legacy raw `Vec<Block>` bincode.
pub fn load_blocks_fixture(path: &Path) -> anyhow::Result<Vec<lib_blockchain::block::Block>> {
    if let Ok(fixture) = ReplayBlocksFixture::load(path) {
        return Ok(fixture.blocks);
    }
    let data = std::fs::read(path)?;
    anyhow::ensure!(
        data.len() <= lib_blockchain::sync::MAX_REPLAY_FIXTURE_BYTES,
        "fixture file too large ({} bytes)",
        data.len()
    );
    // Legacy: unversioned Vec<Block> — may break across bincode layout changes.
    bincode::deserialize(&data)
        .map_err(|e| anyhow::anyhow!("block fixture decode failed (try re-exporting v1): {e}"))
}

pub fn open_fresh_store(dir: &tempfile::TempDir) -> Arc<dyn BlockchainStore> {
    Arc::new(
        lib_blockchain::storage::SledStore::open(dir.path()).expect("open test sled store"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_tolerance_exact_and_drift() {
        assert!(within_tolerance(100, 100, 0));
        assert!(within_tolerance(100, 98, 2));
        assert!(within_tolerance(98, 100, 2));
        assert!(!within_tolerance(100, 97, 2));
        assert!(!within_tolerance(97, 100, 2));
    }

    #[test]
    fn compare_snapshots_respects_tolerance_atoms() {
        let expected = ReplayCheckpointSnapshot {
            checkpoint_height: 1,
            sov_wallets: vec![SovWalletBalance {
                wallet_id: hex::encode([1u8; 32]),
                balance: 1_000,
            }],
            cbe_treasury_balance: 500,
            treasury_sov_balance: 0,
            dao_tokens: vec![],
            tolerance_atoms: 5,
        };
        let mut actual = expected.clone();
        actual.sov_wallets[0].balance = 996;
        compare_snapshots("tol-ok", &expected, &actual).expect("within tolerance");

        actual.sov_wallets[0].balance = 994;
        compare_snapshots("tol-fail", &expected, &actual)
            .expect_err("outside tolerance must fail");
    }

    #[test]
    fn g4_floor_documents_incident_height() {
        assert_eq!(G4_CHECKPOINT_HEIGHT_FLOOR, 74_010);
    }
}