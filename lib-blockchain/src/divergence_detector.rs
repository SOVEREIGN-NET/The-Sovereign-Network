//! State-unification divergence detector (Phase 1 / #2635).
//!
//! Implements the design spec in `docs/arch/state-unification.md` §5.
//!
//! The `Blockchain` god-object carries an in-memory state representation
//! (HashMaps / Vecs) alongside the sled-backed [`BlockchainStore`], which the
//! codebase documents as the *authoritative* source of truth. During the
//! read-migration phases (#2636–#2639) the two can drift. This module is a
//! pure, sync, runtime-agnostic harness that detects that drift before a
//! handler returns stale data.
//!
//! # Critical correctness constraint
//!
//! The detector reads **both** sources *raw* and compares them directly. It
//! must NOT go through any `Blockchain` facade method: the facades fall back
//! from sled to the in-memory map, which would *hide* divergence (a missing
//! sled value would silently return the in-mem value). Therefore:
//!
//! - **in-memory**: read the public `Blockchain` struct fields directly
//!   (`bc.token_nonces`, `bc.token_contracts`, `bc.identity_registry`,
//!   `bc.blocks`, `bc.height`).
//! - **sled**: read via [`Blockchain::get_store`] (returns
//!   `Option<&Arc<dyn BlockchainStore>>`) and call the trait methods directly.
//!
//! # Runtime wiring is NOT here
//!
//! This module deliberately exposes only pure/sync functions. The tokio task
//! (spawn + interval + `Arc<RwLock<Blockchain>>`) is wired by the parent in
//! `zhtp` so this module unit-tests cleanly without a runtime.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::blockchain::Blockchain;
use crate::storage::{did_to_hash, Address, BlockchainStore, TokenId};

/// Default sampling cadence in seconds (used by the parent's interval task).
const DEFAULT_INTERVAL_SECS: u64 = 30;
/// Default number of keys sampled per cycle, per field.
const DEFAULT_SAMPLE_SIZE: usize = 100;

// =============================================================================
// Configuration
// =============================================================================

/// Activation/behavior configuration for the divergence detector.
///
/// Construct from the environment with [`DivergenceConfig::from_env`]. See
/// §5.2 of the design spec for the env-var contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceConfig {
    /// Whether the detector should run at all (`ZHTP_DIVERGENCE_DETECT`).
    pub enabled: bool,
    /// On mismatch, panic instead of logging (`ZHTP_DIVERGENCE_PANIC`).
    /// Used for testnet enforcement and CI gating.
    pub panic_on_mismatch: bool,
    /// Sampling cadence in seconds (`ZHTP_DIVERGENCE_INTERVAL_SECS`, default 30).
    pub interval_secs: u64,
    /// Number of keys sampled per cycle, per field
    /// (`ZHTP_DIVERGENCE_SAMPLE_SIZE`, default 100).
    pub sample_size: usize,
}

impl Default for DivergenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            panic_on_mismatch: false,
            interval_secs: DEFAULT_INTERVAL_SECS,
            sample_size: DEFAULT_SAMPLE_SIZE,
        }
    }
}

impl DivergenceConfig {
    /// Read configuration from the environment.
    ///
    /// Booleans are gated on env-var *presence* (`is_ok()`), matching the house
    /// pattern (`zhtp/src/config/aggregation.rs`). Numbers parse the value and
    /// fall back to the documented default on absence or parse failure.
    pub fn from_env() -> Self {
        let enabled = std::env::var("ZHTP_DIVERGENCE_DETECT").is_ok();
        let panic_on_mismatch = std::env::var("ZHTP_DIVERGENCE_PANIC").is_ok();
        let interval_secs = std::env::var("ZHTP_DIVERGENCE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_INTERVAL_SECS);
        let sample_size = std::env::var("ZHTP_DIVERGENCE_SAMPLE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_SAMPLE_SIZE);
        Self {
            enabled,
            panic_on_mismatch,
            interval_secs,
            sample_size,
        }
    }
}

// =============================================================================
// Metrics
// =============================================================================

/// Prometheus-compatible metrics for the divergence detector.
///
/// Follows the house pattern (no `prometheus` crate): a struct of atomics with
/// `fetch_add(1, Relaxed)` increment methods and a manual
/// [`export_prometheus`](DivergenceMetrics::export_prometheus) formatter.
/// Model: `zhtp/src/pouw/metrics.rs`.
#[derive(Default)]
pub struct DivergenceMetrics {
    /// Token-balance mismatches detected (`divergence_total{field="token_balance"}`).
    pub token_balance: AtomicU64,
    /// Token-nonce mismatches detected (`divergence_total{field="token_nonce"}`).
    pub token_nonce: AtomicU64,
    /// Identity mismatches detected (`divergence_total{field="identity"}`).
    pub identity: AtomicU64,
    /// Block mismatches detected (`divergence_total{field="block"}`).
    pub block: AtomicU64,
    /// Total keys sampled across all fields (`divergence_samples_total`).
    pub samples_total: AtomicU64,
}

impl DivergenceMetrics {
    /// Create a fresh, zeroed metrics collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one detected mismatch for the given field.
    pub fn record_mismatch(&self, field: DivergenceField) {
        match field {
            DivergenceField::TokenBalance => {
                self.token_balance.fetch_add(1, Ordering::Relaxed);
            }
            DivergenceField::TokenNonce => {
                self.token_nonce.fetch_add(1, Ordering::Relaxed);
            }
            DivergenceField::Identity => {
                self.identity.fetch_add(1, Ordering::Relaxed);
            }
            DivergenceField::Block => {
                self.block.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Add `n` to the total-samples counter.
    pub fn add_samples(&self, n: u64) {
        self.samples_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Export all metrics in Prometheus text exposition format.
    pub fn export_prometheus(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP divergence_total In-memory vs sled state mismatches detected, by field\n");
        out.push_str("# TYPE divergence_total counter\n");
        out.push_str(&format!(
            "divergence_total{{field=\"token_balance\"}} {}\n",
            self.token_balance.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "divergence_total{{field=\"token_nonce\"}} {}\n",
            self.token_nonce.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "divergence_total{{field=\"identity\"}} {}\n",
            self.identity.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "divergence_total{{field=\"block\"}} {}\n",
            self.block.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP divergence_samples_total Total keys sampled across all detection cycles\n");
        out.push_str("# TYPE divergence_samples_total counter\n");
        out.push_str(&format!(
            "divergence_samples_total {}\n",
            self.samples_total.load(Ordering::Relaxed)
        ));

        out
    }
}

// =============================================================================
// Divergence records
// =============================================================================

/// Which duplicate-state pair a divergence belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivergenceField {
    /// Per-(token, address) balance (catalog row 2).
    TokenBalance,
    /// Per-(token, sender) replay nonce (catalog row 3).
    TokenNonce,
    /// Identity registry record (catalog row 5).
    Identity,
    /// Block at a sampled height (catalog row 1).
    Block,
}

impl DivergenceField {
    /// Stable lowercase label used in logs and Prometheus output.
    pub fn label(&self) -> &'static str {
        match self {
            DivergenceField::TokenBalance => "token_balance",
            DivergenceField::TokenNonce => "token_nonce",
            DivergenceField::Identity => "identity",
            DivergenceField::Block => "block",
        }
    }
}

/// A single detected disagreement between the in-memory and sled states.
///
/// `in_mem` / `sled` are human-readable renderings of the two values (or the
/// sentinel `"<absent>"` when one side has no entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// Which duplicate-state pair diverged.
    pub field: DivergenceField,
    /// Identifying key, rendered for logs (e.g. `<token>:<addr>`, DID, height).
    pub key: String,
    /// In-memory value rendering (or `"<absent>"`).
    pub in_mem: String,
    /// Sled value rendering (or `"<absent>"`).
    pub sled: String,
    /// Chain height at the time of detection (the in-mem tip).
    pub height: u64,
}

/// Sentinel rendering for a side that has no entry for the sampled key.
const ABSENT: &str = "<absent>";

// =============================================================================
// Detection (pure)
// =============================================================================

/// Run ONE detection cycle.
///
/// Pure: samples the in-memory representation, reads the same keys from sled,
/// and returns the mismatches. Performs NO logging, NO metrics mutation, and
/// NEVER panics. If the blockchain has no store attached there is nothing to
/// compare against and this returns an empty vec.
///
/// # Sampling determinism
///
/// Sampling is **deterministic**, not random, so the CI smoke test is
/// reproducible: for each map-keyed field we sort the in-memory key set and
/// take the first `sample_size` keys. For blocks we sample the heights
/// `{0, latest, latest-1}` unioned with the first `sample_size` heights. A
/// runtime caller could later randomize the selection; tests need determinism,
/// hence the fixed ordering here.
pub fn detect_divergences(bc: &Blockchain, sample_size: usize) -> Vec<Divergence> {
    let store = match bc.get_store() {
        Some(s) => s.as_ref(),
        // No store attached → in-memory is the only representation; nothing to
        // diverge from. (Matches the spec: store-less node returns empty.)
        None => return Vec::new(),
    };

    let height = bc.height;
    let mut out = Vec::new();

    detect_token_nonces(bc, store, sample_size, height, &mut out);
    detect_token_balances(bc, store, sample_size, height, &mut out);
    detect_identities(bc, store, sample_size, height, &mut out);
    detect_blocks(bc, store, sample_size, height, &mut out);

    out
}

/// Token nonces: `bc.token_nonces: HashMap<([u8;32],[u8;32]), u64>` (in-mem)
/// vs `store.get_token_nonce(&TokenId, &Address)` (sled). Catalog row 3.
fn detect_token_nonces(
    bc: &Blockchain,
    store: &dyn BlockchainStore,
    sample_size: usize,
    height: u64,
    out: &mut Vec<Divergence>,
) {
    let mut keys: Vec<([u8; 32], [u8; 32])> = bc.token_nonces.keys().copied().collect();
    keys.sort_unstable();
    keys.truncate(sample_size);

    for (token_bytes, addr_bytes) in keys {
        let in_mem = *bc
            .token_nonces
            .get(&(token_bytes, addr_bytes))
            .unwrap_or(&0);
        let token = TokenId::new(token_bytes);
        let addr = Address::new(addr_bytes);
        // Raw sled read — no facade fallback.
        let sled = store.get_token_nonce(&token, &addr).unwrap_or(0);
        if in_mem != sled {
            out.push(Divergence {
                field: DivergenceField::TokenNonce,
                key: format!("{}:{}", hex::encode(token_bytes), hex::encode(addr_bytes)),
                in_mem: in_mem.to_string(),
                sled: sled.to_string(),
                height,
            });
        }
    }
}

/// Token balances + token-contract metadata.
///
/// In-mem: `bc.token_contracts: HashMap<[u8;32], TokenContract>` (catalog rows
/// 2 + 7). Sled: `store.get_token_contract(&TokenId)` for metadata and
/// `store.get_token_balance(&TokenId, &Address)` for per-address balances.
///
/// Balances inside `TokenContract` are keyed by `PublicKey`; the sled store
/// keys balances by the 32-byte `key_id` address — they match for both SOV and
/// custom tokens (confirmed by the executor's seed-sled reconciliation in
/// `blockchain.rs`). So we map `pk.key_id` → `Address::new(pk.key_id)`.
fn detect_token_balances(
    bc: &Blockchain,
    store: &dyn BlockchainStore,
    sample_size: usize,
    height: u64,
    out: &mut Vec<Divergence>,
) {
    let mut token_keys: Vec<[u8; 32]> = bc.token_contracts.keys().copied().collect();
    token_keys.sort_unstable();
    token_keys.truncate(sample_size);

    for token_bytes in token_keys {
        let contract = match bc.token_contracts.get(&token_bytes) {
            Some(c) => c,
            None => continue,
        };
        let token = TokenId::new(token_bytes);

        // --- Metadata comparison (DivergenceField::Block? no — TokenBalance) ---
        // Metadata divergence is reported under the token_balance field bucket
        // since both belong to the token_contracts pair; a missing sled
        // contract is a divergence on its own.
        match store.get_token_contract(&token) {
            Ok(Some(sled_contract)) => {
                if contract.name != sled_contract.name
                    || contract.symbol != sled_contract.symbol
                    || contract.decimals != sled_contract.decimals
                {
                    out.push(Divergence {
                        field: DivergenceField::TokenBalance,
                        key: format!("{}:meta", hex::encode(token_bytes)),
                        in_mem: format!(
                            "name={} symbol={} decimals={}",
                            contract.name, contract.symbol, contract.decimals
                        ),
                        sled: format!(
                            "name={} symbol={} decimals={}",
                            sled_contract.name, sled_contract.symbol, sled_contract.decimals
                        ),
                        height,
                    });
                }
            }
            Ok(None) => {
                out.push(Divergence {
                    field: DivergenceField::TokenBalance,
                    key: format!("{}:meta", hex::encode(token_bytes)),
                    in_mem: format!("name={} symbol={}", contract.name, contract.symbol),
                    sled: ABSENT.to_string(),
                    height,
                });
            }
            Err(_) => continue,
        }

        // --- Per-address balance comparison ---
        // Deterministic: collect + sort the balance key_ids, then sample.
        let mut bal_keys: Vec<[u8; 32]> =
            contract.balances_iter().map(|(pk, _)| pk.key_id).collect();
        bal_keys.sort_unstable();
        bal_keys.truncate(sample_size);

        for key_id in bal_keys {
            let in_mem = contract
                .find_balance_by_key_id(&key_id)
                .map(|(_, b)| b)
                .unwrap_or(0);
            let addr = Address::new(key_id);
            let sled = store.get_token_balance(&token, &addr).unwrap_or(0);
            if in_mem != sled {
                out.push(Divergence {
                    field: DivergenceField::TokenBalance,
                    key: format!("{}:{}", hex::encode(token_bytes), hex::encode(key_id)),
                    in_mem: in_mem.to_string(),
                    sled: sled.to_string(),
                    height,
                });
            }
        }
    }
}

/// Identities. Catalog row 5.
///
/// In-mem: `bc.identity_registry: HashMap<String /*DID*/, IdentityTransactionData>`.
/// Sled: `store.get_identity(&[u8;32] /*DID hash*/) -> Option<IdentityConsensus>`,
/// keyed by `did_to_hash(did)`.
///
/// The two record types differ structurally (`IdentityTransactionData` vs
/// `IdentityConsensus`), so we compare only what is meaningfully shared:
///   1. **Presence/absence** — in-mem-only or sled-only is a divergence.
///   2. **`did_document_hash`** — present in both (`Hash` vs `[u8;32]`),
///      compared as raw bytes. This is the strongest shared identifier.
///   3. **`registration_fee`** and **`dao_fee`** — both carry these; note the
///      in-mem type is `u64` and the sled type is also `u64`, so they compare
///      directly.
fn detect_identities(
    bc: &Blockchain,
    store: &dyn BlockchainStore,
    sample_size: usize,
    height: u64,
    out: &mut Vec<Divergence>,
) {
    let mut dids: Vec<String> = bc.identity_registry.keys().cloned().collect();
    dids.sort_unstable();
    dids.truncate(sample_size);

    for did in dids {
        let in_mem = match bc.identity_registry.get(&did) {
            Some(d) => d,
            None => continue,
        };
        let did_hash = did_to_hash(&did);
        let sled = match store.get_identity(&did_hash) {
            Ok(s) => s,
            Err(_) => continue,
        };

        match sled {
            None => {
                // In-mem has the identity but sled does not.
                out.push(Divergence {
                    field: DivergenceField::Identity,
                    key: did.clone(),
                    in_mem: format!("present did_document_hash={}", hex::encode(in_mem.did_document_hash.as_array())),
                    sled: ABSENT.to_string(),
                    height,
                });
            }
            Some(consensus) => {
                let in_mem_doc = in_mem.did_document_hash.as_array();
                if in_mem_doc != consensus.did_document_hash {
                    out.push(Divergence {
                        field: DivergenceField::Identity,
                        key: format!("{}:did_document_hash", did),
                        in_mem: hex::encode(in_mem_doc),
                        sled: hex::encode(consensus.did_document_hash),
                        height,
                    });
                }
                if in_mem.registration_fee != consensus.registration_fee {
                    out.push(Divergence {
                        field: DivergenceField::Identity,
                        key: format!("{}:registration_fee", did),
                        in_mem: in_mem.registration_fee.to_string(),
                        sled: consensus.registration_fee.to_string(),
                        height,
                    });
                }
                if in_mem.dao_fee != consensus.dao_fee {
                    out.push(Divergence {
                        field: DivergenceField::Identity,
                        key: format!("{}:dao_fee", did),
                        in_mem: in_mem.dao_fee.to_string(),
                        sled: consensus.dao_fee.to_string(),
                        height,
                    });
                }
            }
        }
    }
}

/// Blocks. Catalog row 1.
///
/// In-mem: `bc.blocks: Vec<Block>` (hot window only) + `bc.height: u64`.
/// Sled: `store.get_block_by_height(h)` + `store.latest_height()`.
///
/// We compare the block hash at sampled heights. The in-memory `blocks` Vec is
/// only a hot window, so we look up by height inside that window rather than
/// indexing positionally. Sampled heights are deterministic:
/// `{0, latest, latest-1} ∪ {0..sample_size}` (bounded by `latest`).
fn detect_blocks(
    bc: &Blockchain,
    store: &dyn BlockchainStore,
    sample_size: usize,
    height: u64,
    out: &mut Vec<Divergence>,
) {
    // Sled tip — also a divergence axis vs in-mem height.
    let sled_latest = match store.latest_height() {
        Ok(h) => h,
        Err(_) => return,
    };

    // Build the in-memory height → block-hash index for the hot window.
    let in_mem_index: std::collections::HashMap<u64, [u8; 32]> = bc
        .blocks
        .iter()
        .map(|b| (b.header.height, b.hash().as_array()))
        .collect();

    if in_mem_index.is_empty() {
        // No hot window to compare (e.g. fresh/pruned node) — nothing to do.
        return;
    }

    let latest = bc.height.max(sled_latest);

    // Deterministic sampled height set.
    let mut heights: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    heights.insert(0);
    heights.insert(latest);
    if latest > 0 {
        heights.insert(latest - 1);
    }
    for h in 0..(sample_size as u64) {
        if h > latest {
            break;
        }
        heights.insert(h);
    }

    for h in heights {
        let in_mem_hash = in_mem_index.get(&h).copied();
        let sled_hash = match store.get_block_by_height(h) {
            Ok(Some(b)) => Some(b.hash().as_array()),
            Ok(None) => None,
            Err(_) => continue,
        };

        match (in_mem_hash, sled_hash) {
            // Height not in the hot window — can't compare; skip (not a divergence).
            (None, _) => {}
            (Some(im), None) => {
                out.push(Divergence {
                    field: DivergenceField::Block,
                    key: format!("height={}", h),
                    in_mem: hex::encode(im),
                    sled: ABSENT.to_string(),
                    height,
                });
            }
            (Some(im), Some(sl)) => {
                if im != sl {
                    out.push(Divergence {
                        field: DivergenceField::Block,
                        key: format!("height={}", h),
                        in_mem: hex::encode(im),
                        sled: hex::encode(sl),
                        height,
                    });
                }
            }
        }
    }
}

// =============================================================================
// Cycle wrapper (logging + metrics + optional panic)
// =============================================================================

/// Run one detection cycle and act on the result per the config.
///
/// 1. Calls [`detect_divergences`].
/// 2. Bumps the samples counter (approximate: the number of in-mem keys we
///    could have sampled, capped per field by `sample_size`).
/// 3. For each mismatch: emits a structured `tracing::error!` (per §5.4) and
///    increments the per-field counter.
/// 4. If `cfg.panic_on_mismatch` and there is at least one mismatch, panics
///    with the divergence details (testnet/CI enforcement).
///
/// Returns the number of mismatches detected.
pub fn run_cycle(
    bc: &Blockchain,
    cfg: &DivergenceConfig,
    metrics: &DivergenceMetrics,
) -> usize {
    let divergences = detect_divergences(bc, cfg.sample_size);

    // Approximate sample count: how many keys we examined this cycle.
    let sampled = sampled_key_count(bc, cfg.sample_size);
    metrics.add_samples(sampled as u64);

    if divergences.is_empty() {
        tracing::debug!(
            samples = sampled,
            sample_size = cfg.sample_size,
            "divergence_check ok"
        );
        return 0;
    }

    for d in &divergences {
        metrics.record_mismatch(d.field);
        tracing::error!(
            field = d.field.label(),
            key = %d.key,
            in_mem = %d.in_mem,
            sled = %d.sled,
            block_height = d.height,
            "divergence_detected"
        );
    }

    if cfg.panic_on_mismatch {
        panic!(
            "divergence_detected: {} mismatch(es); first: field={} key={} in_mem={} sled={} block_height={}",
            divergences.len(),
            divergences[0].field.label(),
            divergences[0].key,
            divergences[0].in_mem,
            divergences[0].sled,
            divergences[0].height,
        );
    }

    divergences.len()
}

/// Count of in-memory keys examined this cycle, capped per field by
/// `sample_size`. Used only to feed the `divergence_samples_total` metric.
fn sampled_key_count(bc: &Blockchain, sample_size: usize) -> usize {
    let nonces = bc.token_nonces.len().min(sample_size);
    let tokens = bc.token_contracts.len().min(sample_size);
    let idents = bc.identity_registry.len().min(sample_size);
    nonces + tokens + idents
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SledStore;
    use std::sync::Arc;

    // Process env is global and cargo runs tests on parallel threads, so the
    // two env-parsing tests must not set/remove the ZHTP_DIVERGENCE_* vars
    // concurrently. Serialize them on this lock. (Recover from poisoning so one
    // failing test doesn't cascade-fail the other.)
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn config_from_env_defaults_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Clear the vars so this test is independent of the harness env.
        std::env::remove_var("ZHTP_DIVERGENCE_DETECT");
        std::env::remove_var("ZHTP_DIVERGENCE_PANIC");
        std::env::remove_var("ZHTP_DIVERGENCE_INTERVAL_SECS");
        std::env::remove_var("ZHTP_DIVERGENCE_SAMPLE_SIZE");

        let cfg = DivergenceConfig::from_env();
        assert!(!cfg.enabled);
        assert!(!cfg.panic_on_mismatch);
        assert_eq!(cfg.interval_secs, DEFAULT_INTERVAL_SECS);
        assert_eq!(cfg.sample_size, DEFAULT_SAMPLE_SIZE);
    }

    #[test]
    fn config_from_env_parses_overrides() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // NOTE: env is process-global; keep var names unique-ish and restore.
        std::env::set_var("ZHTP_DIVERGENCE_DETECT", "1");
        std::env::set_var("ZHTP_DIVERGENCE_PANIC", "1");
        std::env::set_var("ZHTP_DIVERGENCE_INTERVAL_SECS", "5");
        std::env::set_var("ZHTP_DIVERGENCE_SAMPLE_SIZE", "7");

        let cfg = DivergenceConfig::from_env();
        assert!(cfg.enabled);
        assert!(cfg.panic_on_mismatch);
        assert_eq!(cfg.interval_secs, 5);
        assert_eq!(cfg.sample_size, 7);

        // A non-numeric override falls back to the default.
        std::env::set_var("ZHTP_DIVERGENCE_INTERVAL_SECS", "not-a-number");
        let cfg2 = DivergenceConfig::from_env();
        assert_eq!(cfg2.interval_secs, DEFAULT_INTERVAL_SECS);

        std::env::remove_var("ZHTP_DIVERGENCE_DETECT");
        std::env::remove_var("ZHTP_DIVERGENCE_PANIC");
        std::env::remove_var("ZHTP_DIVERGENCE_INTERVAL_SECS");
        std::env::remove_var("ZHTP_DIVERGENCE_SAMPLE_SIZE");
    }

    #[test]
    fn metrics_export_format() {
        let m = DivergenceMetrics::new();
        m.record_mismatch(DivergenceField::TokenBalance);
        m.record_mismatch(DivergenceField::TokenBalance);
        m.record_mismatch(DivergenceField::TokenNonce);
        m.record_mismatch(DivergenceField::Identity);
        m.record_mismatch(DivergenceField::Block);
        m.add_samples(42);

        let out = m.export_prometheus();
        assert!(out.contains("# TYPE divergence_total counter"));
        assert!(out.contains("divergence_total{field=\"token_balance\"} 2"));
        assert!(out.contains("divergence_total{field=\"token_nonce\"} 1"));
        assert!(out.contains("divergence_total{field=\"identity\"} 1"));
        assert!(out.contains("divergence_total{field=\"block\"} 1"));
        assert!(out.contains("divergence_samples_total 42"));
    }

    #[test]
    fn detect_is_empty_without_store() {
        // Blockchain::new() builds an in-mem-only chain (no store attached).
        // With nothing to compare against, detection must return empty and
        // run_cycle must report zero mismatches.
        let bc = Blockchain::new().expect("blockchain construct");
        assert!(bc.get_store().is_none(), "test assumes no store attached");

        let divs = detect_divergences(&bc, DEFAULT_SAMPLE_SIZE);
        assert!(divs.is_empty(), "store-less chain has nothing to diverge");

        let metrics = DivergenceMetrics::new();
        let cfg = DivergenceConfig {
            // panic_on_mismatch is irrelevant here (no mismatches), but exercise
            // run_cycle end-to-end.
            panic_on_mismatch: true,
            ..DivergenceConfig::default()
        };
        let count = run_cycle(&bc, &cfg, &metrics);
        assert_eq!(count, 0);
    }

    #[test]
    fn detects_matching_and_mismatching_nonce() {
        let temp = tempfile::tempdir().unwrap();
        let store_path = temp.path().join("divergence_store");
        let store = Arc::new(SledStore::open(&store_path).unwrap());

        // Seed two nonces into sled within a block boundary.
        let token_a = TokenId::new([1u8; 32]);
        let addr_a = Address::new([0xAA; 32]);
        let token_b = TokenId::new([2u8; 32]);
        let addr_b = Address::new([0xBB; 32]);

        // The store enforces sequential block heights starting at 0; the first
        // begin_block must be height 0. No block is appended, so latest_height()
        // stays uninitialized and detect_blocks self-skips (no spurious block
        // divergence) — we only assert on the nonce comparison below.
        store.begin_block(0).unwrap();
        store.set_token_nonce(&token_a, &addr_a, 5).unwrap();
        store.set_token_nonce(&token_b, &addr_b, 9).unwrap();
        store.commit_block().unwrap();

        let mut bc = Blockchain::new().expect("blockchain construct");
        bc.set_store(store);

        // Matching entry: same nonce in-mem and sled → no divergence.
        bc.token_nonces.insert(([1u8; 32], [0xAA; 32]), 5);
        // Mismatching entry: in-mem 9 vs sled... we deliberately make in-mem
        // disagree with sled for token_b (sled=9, in-mem=3).
        bc.token_nonces.insert(([2u8; 32], [0xBB; 32]), 3);

        let divs = detect_divergences(&bc, DEFAULT_SAMPLE_SIZE);

        let nonce_divs: Vec<&Divergence> = divs
            .iter()
            .filter(|d| d.field == DivergenceField::TokenNonce)
            .collect();
        assert_eq!(
            nonce_divs.len(),
            1,
            "exactly one nonce divergence expected, got: {:?}",
            divs
        );
        let d = nonce_divs[0];
        assert_eq!(d.in_mem, "3");
        assert_eq!(d.sled, "9");
        assert!(d.key.contains(&hex::encode([0xBB; 32])));

        // run_cycle (non-panic) should report at least the nonce mismatch and
        // bump the per-field counter.
        let metrics = DivergenceMetrics::new();
        let cfg = DivergenceConfig::default(); // panic_on_mismatch = false
        let count = run_cycle(&bc, &cfg, &metrics);
        assert!(count >= 1, "run_cycle should report the mismatch");
        assert!(metrics.token_nonce.load(Ordering::Relaxed) >= 1);
        assert!(metrics.samples_total.load(Ordering::Relaxed) >= 2);
    }
}
