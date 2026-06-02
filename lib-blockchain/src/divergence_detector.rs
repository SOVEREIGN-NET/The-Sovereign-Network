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
    /// Token-contract metadata mismatches (`divergence_total{field="token_contract"}`).
    pub token_contract: AtomicU64,
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
            DivergenceField::TokenContract => {
                self.token_contract.fetch_add(1, Ordering::Relaxed);
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
            "divergence_total{{field=\"token_contract\"}} {}\n",
            self.token_contract.load(Ordering::Relaxed)
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
    /// Token-contract metadata: name / symbol / decimals / missing contract
    /// (catalog row 7). Split from `TokenBalance` (CR #2658) so a contract that
    /// is in-memory but not yet in sled — normal during bootstrap before
    /// `put_token_contract` fires — does not raise spurious `token_balance`
    /// alerts when balances are perfectly in sync.
    TokenContract,
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
            DivergenceField::TokenContract => "token_contract",
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
// Detection: snapshot (under lock) + compare (lock released)
// =============================================================================

/// An owned, point-in-time sample of the in-memory state plus a cloned handle
/// to the sled store, captured while the caller holds the blockchain read lock.
///
/// **Why this split exists (CR #2658).** The detector used to read the
/// in-memory maps and do all sled I/O while holding `blockchain.read()`. A
/// cycle does up to `sample_size` sled reads per field; under a held read lock
/// that blocks every consensus `blockchain.write()` for the whole scan — at
/// 100 keys × 4 fields × a few ms each that is seconds, during sled compaction,
/// enough to miss a BFT round. So we now capture this cheap owned snapshot under
/// the lock, the caller **releases the lock**, and [`compare_to_sled`] does all
/// the slow sled I/O lock-free. The snapshot may be up to one block stale by the
/// time we compare — fine for a background diagnostic.
pub struct DivergenceSnapshot {
    store: std::sync::Arc<dyn BlockchainStore>,
    height: u64,
    /// Sampled in-memory nonces.
    nonces: Vec<(([u8; 32], [u8; 32]), u64)>,
    /// Sampled in-memory token contracts (metadata + sampled per-address balances).
    contracts: Vec<ContractSample>,
    /// FULL in-memory token-id set, for the sled-side absence scan (CR #2658 #4).
    all_token_ids: std::collections::HashSet<[u8; 32]>,
    /// Sampled in-memory identities.
    identities: Vec<IdentitySample>,
    /// FULL in-memory identity DID-hash set, for the sled-side absence scan
    /// (#2639). Lets the reverse scan flag sled-only identities — the dominant
    /// case on a store-backed node after restart, where the in-memory registry
    /// is empty but sled is authoritative.
    all_did_hashes: std::collections::HashSet<[u8; 32]>,
    /// In-memory hot-window block hashes (stored header hash), by height.
    window_block_hashes: Vec<(u64, [u8; 32])>,
    /// Per-field sample cap.
    sample_size: usize,
    /// Approximate count of in-mem keys examined (for the samples metric).
    sampled_count: usize,
}

impl DivergenceSnapshot {
    /// Number of in-memory keys this snapshot examined (feeds the samples
    /// metric via [`report`]).
    pub fn sampled_count(&self) -> usize {
        self.sampled_count
    }
}

struct ContractSample {
    token: [u8; 32],
    name: String,
    symbol: String,
    decimals: u8,
    /// Sampled (key_id, balance) pairs — bounded by `sample_size`, NOT the whole map.
    balances: Vec<([u8; 32], u128)>,
}

struct IdentitySample {
    did: String,
    did_document_hash: [u8; 32],
    registration_fee: u64,
    dao_fee: u64,
}

/// Capture the in-memory sample under the caller's read lock. Cheap: bounded
/// clones, **no sled I/O**. Returns `None` if no store is attached (store-less
/// node has nothing to diverge from).
///
/// Sampling is **deterministic** (sorted keys, take `sample_size`) so the CI
/// smoke test is reproducible.
pub fn snapshot_in_memory(bc: &Blockchain, sample_size: usize) -> Option<DivergenceSnapshot> {
    let store = bc.get_store()?.clone();

    // --- nonces ---
    let mut nonce_keys: Vec<([u8; 32], [u8; 32])> = bc.token_nonces.keys().copied().collect();
    nonce_keys.sort_unstable();
    nonce_keys.truncate(sample_size);
    let nonces = nonce_keys
        .into_iter()
        .map(|k| (k, *bc.token_nonces.get(&k).unwrap_or(&0)))
        .collect();

    // --- contracts (metadata + sampled balances) + full id set for the sled scan ---
    let all_token_ids: std::collections::HashSet<[u8; 32]> =
        bc.token_contracts.keys().copied().collect();
    let mut token_keys: Vec<[u8; 32]> = bc.token_contracts.keys().copied().collect();
    token_keys.sort_unstable();
    token_keys.truncate(sample_size);
    let contracts = token_keys
        .into_iter()
        .filter_map(|t| {
            let c = bc.token_contracts.get(&t)?;
            let mut balances: Vec<([u8; 32], u128)> =
                c.balances_iter().map(|(pk, b)| (pk.key_id, *b)).collect();
            balances.sort_unstable_by_key(|(k, _)| *k);
            balances.truncate(sample_size);
            Some(ContractSample {
                token: t,
                name: c.name.clone(),
                symbol: c.symbol.clone(),
                decimals: c.decimals,
                balances,
            })
        })
        .collect();

    // --- identities ---
    // FULL DID-hash set (not truncated) so the sled-side reverse scan can flag
    // sled-only identities.
    let all_did_hashes: std::collections::HashSet<[u8; 32]> =
        bc.identity_registry.keys().map(|did| did_to_hash(did)).collect();
    let mut dids: Vec<String> = bc.identity_registry.keys().cloned().collect();
    dids.sort_unstable();
    dids.truncate(sample_size);
    let identities = dids
        .into_iter()
        .filter_map(|did| {
            let d = bc.identity_registry.get(&did)?;
            Some(IdentitySample {
                did,
                did_document_hash: d.did_document_hash.as_array(),
                registration_fee: d.registration_fee,
                dao_fee: d.dao_fee,
            })
        })
        .collect();

    // --- hot-window block hashes (stored header hash, matching get_block_hash_by_height) ---
    let window_block_hashes: Vec<(u64, [u8; 32])> = bc
        .blocks
        .iter()
        .map(|b| (b.header.height, b.header.block_hash.as_array()))
        .collect();

    let sampled_count = bc.token_nonces.len().min(sample_size)
        + bc.token_contracts.len().min(sample_size)
        + bc.identity_registry.len().min(sample_size);

    Some(DivergenceSnapshot {
        store,
        height: bc.height,
        nonces,
        contracts,
        all_token_ids,
        identities,
        all_did_hashes,
        window_block_hashes,
        sample_size,
        sampled_count,
    })
}

/// Compare an in-memory [`DivergenceSnapshot`] against sled. Does ALL the sled
/// I/O and is meant to be called **after the blockchain lock is released** — it
/// never touches `Blockchain`, only the cloned store handle.
pub fn compare_to_sled(snap: &DivergenceSnapshot) -> Vec<Divergence> {
    let store = snap.store.as_ref();
    let height = snap.height;
    let mut out = Vec::new();

    compare_token_nonces(snap, store, height, &mut out);
    compare_token_balances(snap, store, height, &mut out);
    compare_identities(snap, store, height, &mut out);
    compare_blocks(snap, store, height, &mut out);

    out
}

/// Test/convenience entry: snapshot + compare together (holds `bc` for the whole
/// call — fine for tests). The runtime uses [`snapshot_in_memory`] then
/// [`compare_to_sled`] with the lock released between, so it never blocks a
/// consensus writer on sled I/O.
pub fn detect_divergences(bc: &Blockchain, sample_size: usize) -> Vec<Divergence> {
    snapshot_in_memory(bc, sample_size)
        .as_ref()
        .map(compare_to_sled)
        .unwrap_or_default()
}

/// Token nonces: sampled in-mem `(token, addr) -> nonce` (snapshot) vs
/// `store.get_token_nonce(&TokenId, &Address)` (sled). Catalog row 3.
fn compare_token_nonces(
    snap: &DivergenceSnapshot,
    store: &dyn BlockchainStore,
    height: u64,
    out: &mut Vec<Divergence>,
) {
    for &((token_bytes, addr_bytes), in_mem) in &snap.nonces {
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
/// In-mem (from the snapshot): sampled `ContractSample`s with metadata + sampled
/// `(key_id, balance)` pairs. Sled: `store.get_token_contract` for metadata,
/// `store.get_token_balance` for per-address balances. Balances are keyed by the
/// 32-byte `key_id` address on both sides (the executor's reconciliation keeps
/// `pk.key_id` ↔ `Address::new(pk.key_id)` aligned).
///
/// Also runs a **sled-side scan** (CR #2658 #4): the in-mem→sled checks above
/// only catch divergence for keys present in memory; this scans sled contracts
/// for any token **absent from the in-memory set** — the drift direction that
/// matters most once sled is authoritative and in-mem is the stale side.
fn compare_token_balances(
    snap: &DivergenceSnapshot,
    store: &dyn BlockchainStore,
    height: u64,
    out: &mut Vec<Divergence>,
) {
    for c in &snap.contracts {
        let token = TokenId::new(c.token);

        // --- Metadata comparison (tagged TokenContract, not TokenBalance). ---
        match store.get_token_contract(&token) {
            Ok(Some(sled_contract)) => {
                if c.name != sled_contract.name
                    || c.symbol != sled_contract.symbol
                    || c.decimals != sled_contract.decimals
                {
                    out.push(Divergence {
                        field: DivergenceField::TokenContract,
                        key: format!("{}:meta", hex::encode(c.token)),
                        in_mem: format!(
                            "name={} symbol={} decimals={}",
                            c.name, c.symbol, c.decimals
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
                    field: DivergenceField::TokenContract,
                    key: format!("{}:meta", hex::encode(c.token)),
                    in_mem: format!("name={} symbol={}", c.name, c.symbol),
                    sled: ABSENT.to_string(),
                    height,
                });
            }
            Err(_) => continue,
        }

        // --- Per-address balance comparison (sampled, in-mem → sled) ---
        for &(key_id, in_mem) in &c.balances {
            let addr = Address::new(key_id);
            let sled = store.get_token_balance(&token, &addr).unwrap_or(0);
            if in_mem != sled {
                out.push(Divergence {
                    field: DivergenceField::TokenBalance,
                    key: format!("{}:{}", hex::encode(c.token), hex::encode(key_id)),
                    in_mem: in_mem.to_string(),
                    sled: sled.to_string(),
                    height,
                });
            }
        }
    }

    // --- Sled-side scan: sled contracts absent from the in-memory set (#4). ---
    // Bounded to `sample_size` in deterministic sled key order. Identities now
    // also have a reverse scan (see `compare_identities`, via `iter_identities`,
    // #2639). The reverse scan for nonces / balances still needs sled iterators
    // the trait does not yet expose — tracked as follow-up; until then those two
    // fields are covered only in the in-mem → sled direction.
    if let Ok(iter) = store.iter_token_contracts() {
        for (_token_id, sled_contract) in iter.take(snap.sample_size) {
            if !snap.all_token_ids.contains(&sled_contract.token_id) {
                out.push(Divergence {
                    field: DivergenceField::TokenContract,
                    key: format!("{}:meta", hex::encode(sled_contract.token_id)),
                    in_mem: ABSENT.to_string(),
                    sled: format!("name={} symbol={}", sled_contract.name, sled_contract.symbol),
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
fn compare_identities(
    snap: &DivergenceSnapshot,
    store: &dyn BlockchainStore,
    height: u64,
    out: &mut Vec<Divergence>,
) {
    for id in &snap.identities {
        let did_hash = did_to_hash(&id.did);
        let sled = match store.get_identity(&did_hash) {
            Ok(s) => s,
            Err(_) => continue,
        };

        match sled {
            None => {
                // In-mem has the identity but sled does not.
                out.push(Divergence {
                    field: DivergenceField::Identity,
                    key: id.did.clone(),
                    in_mem: format!(
                        "present did_document_hash={}",
                        hex::encode(id.did_document_hash)
                    ),
                    sled: ABSENT.to_string(),
                    height,
                });
            }
            Some(consensus) => {
                if id.did_document_hash != consensus.did_document_hash {
                    out.push(Divergence {
                        field: DivergenceField::Identity,
                        key: format!("{}:did_document_hash", id.did),
                        in_mem: hex::encode(id.did_document_hash),
                        sled: hex::encode(consensus.did_document_hash),
                        height,
                    });
                }
                if id.registration_fee != consensus.registration_fee {
                    out.push(Divergence {
                        field: DivergenceField::Identity,
                        key: format!("{}:registration_fee", id.did),
                        in_mem: id.registration_fee.to_string(),
                        sled: consensus.registration_fee.to_string(),
                        height,
                    });
                }
                if id.dao_fee != consensus.dao_fee {
                    out.push(Divergence {
                        field: DivergenceField::Identity,
                        key: format!("{}:dao_fee", id.did),
                        in_mem: id.dao_fee.to_string(),
                        sled: consensus.dao_fee.to_string(),
                        height,
                    });
                }
            }
        }
    }

    // --- Sled-side scan: identities in sled but absent from the in-memory set
    // (#2639). This is the dominant divergence direction on a store-backed node
    // after restart, where the in-memory registry is empty (no sled->in-mem
    // rebuild) but sled holds the authoritative set. Bounded to `sample_size`
    // in sled iteration order; compared by did_hash since the sled record does
    // not carry the DID string. Enabled by `iter_identities` (#2639).
    if let Ok(iter) = store.iter_identities() {
        for sled_identity in iter.take(snap.sample_size) {
            if !snap.all_did_hashes.contains(&sled_identity.did_hash) {
                out.push(Divergence {
                    field: DivergenceField::Identity,
                    key: format!("{}:sled-only", hex::encode(sled_identity.did_hash)),
                    in_mem: ABSENT.to_string(),
                    sled: format!(
                        "present did_document_hash={}",
                        hex::encode(sled_identity.did_document_hash)
                    ),
                    height,
                });
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
fn compare_blocks(
    snap: &DivergenceSnapshot,
    store: &dyn BlockchainStore,
    height: u64,
    out: &mut Vec<Divergence>,
) {
    // Sled tip — also a divergence axis vs in-mem height.
    let sled_latest = match store.latest_height() {
        Ok(h) => h,
        Err(_) => return,
    };

    // In-memory height → stored-header-hash index for the hot window (captured
    // in the snapshot, matching what store.get_block_hash_by_height returns).
    let in_mem_index: std::collections::HashMap<u64, [u8; 32]> =
        snap.window_block_hashes.iter().copied().collect();

    if in_mem_index.is_empty() {
        // No hot window to compare (e.g. fresh/pruned node) — nothing to do.
        return;
    }

    let latest = snap.height.max(sled_latest);
    let sample_size = snap.sample_size;

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
        // CR #2658: compare via the stored block hash, not a full block
        // deserialization + rehash per sampled height.
        let sled_hash = match store.get_block_hash_by_height(h) {
            Ok(Some(bh)) => Some(bh.0),
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

/// Act on a completed comparison: meter samples, log each mismatch, optionally
/// panic. Separated from detection so the runtime can call it **after releasing
/// the blockchain lock** (it touches neither `Blockchain` nor sled). Returns the
/// number of mismatches.
pub fn report(
    divergences: &[Divergence],
    sampled: usize,
    cfg: &DivergenceConfig,
    metrics: &DivergenceMetrics,
) -> usize {
    metrics.add_samples(sampled as u64);

    if divergences.is_empty() {
        tracing::debug!(
            samples = sampled,
            sample_size = cfg.sample_size,
            "divergence_check ok"
        );
        return 0;
    }

    for d in divergences {
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

/// Run one detection cycle and act on the result per the config.
///
/// Test/convenience wrapper that holds `bc` across the whole cycle. The runtime
/// instead splits this — `snapshot_in_memory` under the lock, then `compare_to_sled`
/// + `report` with the lock released — so it never blocks a consensus writer on
/// sled I/O (CR #2658). Returns the number of mismatches detected.
pub fn run_cycle(bc: &Blockchain, cfg: &DivergenceConfig, metrics: &DivergenceMetrics) -> usize {
    let snap = snapshot_in_memory(bc, cfg.sample_size);
    let divergences = snap.as_ref().map(compare_to_sled).unwrap_or_default();
    let sampled = snap.as_ref().map(|s| s.sampled_count).unwrap_or(0);
    report(&divergences, sampled, cfg, metrics)
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

    /// CR #2658 #4: the sled-side scan catches a contract present in sled but
    /// absent from the in-memory map — the drift direction that matters once
    /// sled is authoritative and in-mem is the stale side.
    #[test]
    fn detects_sled_only_token_contract() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(SledStore::open(&temp.path().join("sled_only_store")).unwrap());

        // A custom (non-genesis) token: Blockchain::new() seeds SOV into the
        // in-memory token_contracts, so we use a unique id that exists ONLY in
        // sled to exercise the sled-side absence scan.
        let custom = crate::contracts::TokenContract::new(
            [0xEE; 32],
            "Test".to_string(),
            "TST".to_string(),
            8,
            1_000_000,
            false,
            0,
            crate::integration::crypto_integration::PublicKey::new([0u8; 2592]),
        );
        store.begin_block(0).unwrap();
        store.put_token_contract(&custom).unwrap();
        store.commit_block().unwrap();

        let mut bc = Blockchain::new().expect("blockchain construct");
        bc.set_store(store);
        // bc.token_contracts has only the genesis SOV token; sled additionally
        // holds the [0xEE..] custom contract.

        let divs = detect_divergences(&bc, DEFAULT_SAMPLE_SIZE);
        assert!(
            divs.iter().any(|d| d.field == DivergenceField::TokenContract
                && d.in_mem == ABSENT
                && d.key.starts_with(&hex::encode([0xEE; 32]))),
            "sled-only [0xEE..] contract must be flagged by the sled-side scan; got: {:?}",
            divs
        );
    }

    #[test]
    fn detects_sled_only_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(SledStore::open(&temp.path().join("sled_only_id_store")).unwrap());

        // An identity that exists ONLY in sled (the post-restart case: the
        // in-memory registry is empty of it). The sled-side reverse scan must
        // flag it — without `iter_identities` (#2639) this direction was blind.
        let did = "did:zhtp:sled-only-id";
        let did_hash = crate::storage::did_to_hash(did);
        store.begin_block(0).unwrap();
        store
            .put_identity(
                &did_hash,
                &crate::storage::IdentityConsensus {
                    did_hash,
                    did_document_hash: [0x5A; 32],
                    ..Default::default()
                },
            )
            .unwrap();
        store.commit_block().unwrap();

        let mut bc = Blockchain::new().expect("blockchain construct");
        bc.set_store(store);
        assert!(
            !bc.identity_registry.contains_key(did),
            "test premise: identity is sled-only"
        );

        let divs = detect_divergences(&bc, DEFAULT_SAMPLE_SIZE);
        assert!(
            divs.iter().any(|d| d.field == DivergenceField::Identity
                && d.in_mem == ABSENT
                && d.key.starts_with(&hex::encode(did_hash))),
            "sled-only identity must be flagged by the sled-side reverse scan; got: {:?}",
            divs
        );
    }

    /// CR #2658 #3: snapshot is captured under the (caller's) lock and compared
    /// lock-free; the split must produce the same result as the combined entry.
    #[test]
    fn snapshot_then_compare_equals_detect() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(SledStore::open(&temp.path().join("split_store")).unwrap());
        let token = TokenId::new([4u8; 32]);
        let addr = Address::new([0xCD; 32]);
        store.begin_block(0).unwrap();
        store.set_token_nonce(&token, &addr, 7).unwrap();
        store.commit_block().unwrap();

        let mut bc = Blockchain::new().expect("blockchain construct");
        bc.set_store(store);
        bc.token_nonces.insert(([4u8; 32], [0xCD; 32]), 2); // mismatch: in-mem 2 vs sled 7

        let combined = detect_divergences(&bc, DEFAULT_SAMPLE_SIZE);
        let snap = snapshot_in_memory(&bc, DEFAULT_SAMPLE_SIZE).expect("store attached");
        let split = compare_to_sled(&snap);

        assert_eq!(
            combined, split,
            "snapshot+compare must equal the combined detect_divergences"
        );
        assert!(split.iter().any(|d| d.field == DivergenceField::TokenNonce));
    }
}
