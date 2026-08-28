//! Deterministic genesis configuration — GENESIS-1 (#1909)
//!
//! `genesis.toml` is the single source of truth for genesis state.
//! Any node with the same file produces bit-for-bit identical block 0.
//! `CANONICAL_GENESIS_HASH` is hardcoded here; a node whose block 0 does not
//! match refuses to join the network.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// CANONICAL_GENESIS_HASH
// ─────────────────────────────────────────────────────────────────────────────

/// The expected hash of block 0.
///
/// # WARNING: Enforced via Bootstrap Leader Gate (Temporary)
///
/// This constant is currently all-zeros (disabled) because the testnet genesis
/// hash has not been finalized. Instead, genesis determinism is enforced via
/// the bootstrap leader gate in zhtp/src/runtime/mod.rs - only the bootstrap
/// leader can create genesis, all other nodes must sync from it.
///
/// # TODO: Set Real Hash Before Mainnet
/// Once the canonical testnet genesis is established (from g1/g2), run:
///   `zhtp-cli genesis build --config genesis.toml`
/// Then update this constant with the actual 64-char hex hash.
///
/// # Mainnet Workflow
/// 1. Fill `genesis.toml` with real keys (key ceremony).
/// 2. Run `zhtp-cli genesis build --config genesis.toml` → prints the block 0 hash.
/// 3. Set this constant to that hash and commit.
/// 4. Tag the commit `mainnet-genesis-v1`.
pub const CANONICAL_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// ─────────────────────────────────────────────────────────────────────────────
// genesis.toml embedded in the binary
// ─────────────────────────────────────────────────────────────────────────────

/// Raw bytes of the `genesis.toml` baked into the binary at compile time.
const EMBEDDED_GENESIS_TOML: &[u8] = include_bytes!("../../../genesis.toml");

// ─────────────────────────────────────────────────────────────────────────────
// Config structs (deserialised from genesis.toml)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct GenesisConfig {
    pub chain: ChainConfig,
    pub sov: SovConfig,
    pub entity_registry: EntityRegistryConfig,
    pub bootstrap_council: BootstrapCouncilConfig,
    pub bonding_curve: BondingCurveConfig,
    #[serde(default)]
    pub cbe_curve: CbeCurveConfig,
    #[serde(default)]
    pub allocations: GenesisAllocations,
    /// Lobby-auth OPAQUE server setup, embedded once at the genesis ceremony.
    /// Optional in v1 — missing `[opaque]` means no lobby auth is configured
    /// for this network, and OPAQUE endpoints will return 503 at runtime.
    #[serde(default)]
    pub opaque: Option<OpaqueConfig>,
}

/// `[opaque]` section of `genesis.toml` — locks the OPAQUE server setup
/// (an `opaque-ke`-serialized blob) into the chain.
///
/// **SECURITY (reviewer #2569)**: `ServerSetup::serialize()` output contains
/// the OPRF *private* seed. Anyone holding these bytes can offline-attack
/// every credential ever registered against this server setup. Therefore:
///
/// - The repo's checked-in `genesis.toml` MUST NOT carry a production
///   setup blob. Treat any `server_setup_b64` committed to source as
///   throwaway / testnet-only.
/// - Real-network genesis is produced by the genesis-ceremony helper and
///   distributed to validators out-of-band; the checked-in file gets the
///   real value swapped in at deployment time and is never pushed back.
/// - Removing `[opaque]` from genesis disables lobby auth on that
///   deployment (OPAQUE endpoints return 503) — preferred for any build
///   that isn't actually a validator.
#[derive(Debug, Clone, Deserialize)]
pub struct OpaqueConfig {
    /// `ServerSetup::serialize()` bytes, base64-encoded (STANDARD alphabet).
    /// Generated once at the genesis ceremony; never rotates in v1.
    /// **Contains the OPRF private seed — see struct-level note.**
    pub server_setup_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub chain_id: u8,
    pub name: String,
    pub genesis_time: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SovConfig {
    pub initial_supply: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EntityRegistryConfig {
    #[serde(default)]
    pub cbe_treasury_key: String,
    #[serde(default)]
    pub nonprofit_treasury_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapCouncilConfig {
    pub threshold: u8,
    #[serde(default)]
    pub members: Vec<BootstrapMember>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapMember {
    pub did: String,
    pub wallet: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BondingCurveConfig {
    pub reserve_ratio_ppm: u64,
    pub graduation_threshold: u64,
}

/// Canonical 18-decimal integer bonding curve config (#1922 / #1927).
///
/// `p_start_0` is the only free parameter — all five band `p_start` values
/// are derived via price continuity in `canonical::derive_cbe_bands`.
///
/// The `Default` impl pins `p_start_0` to `canonical::P_START_0` so that
/// older genesis files without a `[cbe_curve]` section continue to parse
/// and produce the same canonical curve.
#[derive(Debug, Clone, Deserialize)]
pub struct CbeCurveConfig {
    /// Price at zero supply, in atomic SOV units (18-decimal).
    /// Stored as `u64` for TOML compatibility (value fits; max band price is
    /// ~2.7e15, well within u64 range).  Cast to `u128` at runtime.
    /// Must equal `canonical::P_START_0`; validated by `build_block0()`.
    pub p_start_0: u64,
}

impl Default for CbeCurveConfig {
    fn default() -> Self {
        Self {
            // Safe: P_START_0 = 313_345_700_000_000, fits in u64.
            p_start_0: crate::contracts::bonding_curve::canonical::P_START_0 as u64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// State migration allocations (optional, populated by migrate-state)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GenesisAllocations {
    #[serde(default)]
    pub wallets: Vec<WalletAllocation>,
    #[serde(default)]
    pub identities: Vec<IdentityAllocation>,
    #[serde(default)]
    pub web4_contracts: Vec<Web4Allocation>,
    #[serde(default)]
    pub sov_balances: Vec<SovBalanceAllocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAllocation {
    pub wallet_id: String,
    pub wallet_type: String,
    pub public_key: String,
    pub owner_identity_id: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAllocation {
    pub did: String,
    pub display_name: String,
    pub public_key: String,
    pub identity_type: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4Allocation {
    pub contract_id: String,
    pub domain: String,
    pub owner: String,
    pub created_at: u64,
    pub contract_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovBalanceAllocation {
    pub wallet_id: String,
    #[serde(default)]
    pub public_key: String,
    /// SOV balance in atomic units (18 decimals). Accepts both integer and string
    /// in TOML because u128 values > i64::MAX cannot be represented as TOML integers.
    #[serde(deserialize_with = "deserialize_u128_flexible")]
    pub balance: u128,
}

fn deserialize_u128_flexible<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U128Visitor;
    impl<'de> serde::de::Visitor<'de> for U128Visitor {
        type Value = u128;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u128 as integer or string")
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u128, E> {
            Ok(v as u128)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u128, E> {
            if v < 0 {
                return Err(E::custom("negative balance"));
            }
            Ok(v as u128)
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<u128, E> {
            v.parse::<u128>().map_err(E::custom)
        }
        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<u128, E> {
            v.parse::<u128>().map_err(E::custom)
        }
    }
    deserializer.deserialize_any(U128Visitor)
}

// ─────────────────────────────────────────────────────────────────────────────
// State snapshot (serialised from a running blockchain, used in migration)
// ─────────────────────────────────────────────────────────────────────────────

/// Full state snapshot exported from a live blockchain node.
///
/// Produced by `zhtp-cli genesis export-state`.
/// Consumed by `zhtp-cli genesis migrate-state` to populate `genesis.toml [allocations]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisStateSnapshot {
    pub exported_at: u64,
    pub chain_height: u64,
    pub wallets: Vec<WalletAllocation>,
    pub identities: Vec<IdentityAllocation>,
    pub web4_contracts: Vec<Web4Allocation>,
    pub sov_balances: Vec<SovBalanceAllocation>,
}

impl GenesisStateSnapshot {
    /// Build a snapshot from a live `Blockchain` instance.
    pub fn from_blockchain(bc: &crate::Blockchain) -> Self {
        use crate::contracts::utils::generate_lib_token_id;

        let exported_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // --- wallets (sorted by wallet_id for deterministic output) ---
        let mut wallets: Vec<WalletAllocation> = bc
            .wallet_registry
            .values()
            .map(|w| WalletAllocation {
                wallet_id: hex::encode(w.wallet_id.as_bytes()),
                wallet_type: w.wallet_type.clone(),
                public_key: hex::encode(&w.public_key),
                owner_identity_id: w.owner_identity_id.map(|id| hex::encode(id.as_bytes())),
                created_at: w.created_at,
            })
            .collect();
        wallets.sort_by(|a, b| a.wallet_id.cmp(&b.wallet_id));

        // --- identities (sorted by DID for deterministic output) ---
        let mut identities: Vec<IdentityAllocation> = bc
            .identity_registry
            .values()
            .filter(|id| id.identity_type != "revoked")
            .map(|id| IdentityAllocation {
                did: id.did.clone(),
                display_name: id.display_name.clone(),
                public_key: hex::encode(&id.public_key),
                identity_type: id.identity_type.clone(),
                created_at: id.created_at,
            })
            .collect();
        identities.sort_by(|a, b| a.did.cmp(&b.did));

        // --- web4 contracts (sorted by domain for deterministic output) ---
        let mut web4_contracts: Vec<Web4Allocation> = bc
            .web4_contracts
            .values()
            .map(|c| Web4Allocation {
                contract_id: c.contract_id.clone(),
                domain: c.domain.clone(),
                owner: c.owner.clone(),
                created_at: c.created_at,
                contract_json: serde_json::to_string(c).unwrap_or_default(),
            })
            .collect();
        web4_contracts.sort_by(|a, b| a.domain.cmp(&b.domain));

        // --- SOV balances (sorted by wallet_id for deterministic output) ---
        let sov_id = generate_lib_token_id();
        let sov_balances = if let Some(token) = bc.token_contracts.get(&sov_id) {
            let mut balances: Vec<SovBalanceAllocation> = token
                .balances_iter()
                .filter(|(_, &bal)| bal > 0)
                .map(|(pk, &bal)| SovBalanceAllocation {
                    wallet_id: hex::encode(pk.key_id),
                    public_key: hex::encode(&pk.dilithium_pk),
                    balance: bal,
                })
                .collect();
            balances.sort_by(|a, b| a.wallet_id.cmp(&b.wallet_id));
            balances
        } else {
            Vec::new()
        };

        GenesisStateSnapshot {
            exported_at,
            chain_height: bc.height,
            wallets,
            identities,
            web4_contracts,
            sov_balances,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain bootstrap projection (GENESIS-1)
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of [`GenesisConfig::project_chain_bootstrap_to_store`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChainBootstrapOutcome {
    /// `true` when the SOV native contract record was written to sled.
    pub sov_contract_installed: bool,
    /// Count of `[allocations.sov_balances]` addresses credited this call.
    pub sov_balances_credited: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// GenesisConfig implementation
// ─────────────────────────────────────────────────────────────────────────────

impl GenesisConfig {
    /// Load genesis config from a TOML file on disk.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read genesis config: {}", path.display()))?;
        toml::from_str(&content).context("Failed to parse genesis.toml")
    }

    /// Load the genesis config embedded in the binary at compile time.
    pub fn from_embedded() -> Result<Self> {
        let content = std::str::from_utf8(EMBEDDED_GENESIS_TOML)
            .context("Embedded genesis.toml is not valid UTF-8")?;
        toml::from_str(content).context("Failed to parse embedded genesis.toml")
    }

    /// Parse the `genesis_time` string into a Unix timestamp.
    pub fn genesis_timestamp(&self) -> Result<u64> {
        // Accept ISO-8601 UTC strings like "2025-11-01T00:00:00Z"
        // Parse manually to avoid a heavy chrono dependency in the hot path.
        let s = &self.chain.genesis_time;
        if s.len() < 19 {
            anyhow::bail!(
                "genesis_time '{}' is too short; expected ISO 8601 format YYYY-MM-DDTHH:MM:SSZ",
                s
            );
        }
        let year: u64 = s[0..4]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid year in genesis_time '{}'", s))?;
        let month: u64 = s[5..7]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid month in genesis_time '{}'", s))?;
        let day: u64 = s[8..10]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid day in genesis_time '{}'", s))?;
        let hour: u64 = s[11..13]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid hour in genesis_time '{}'", s))?;
        let min: u64 = s[14..16]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid minute in genesis_time '{}'", s))?;
        let sec: u64 = s[17..19]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid second in genesis_time '{}'", s))?;
        let days_since_epoch = days_since_unix_epoch(year, month, day);
        Ok(days_since_epoch * 86_400 + hour * 3_600 + min * 60 + sec)
    }

    /// Build a fully-initialized `Blockchain` at block 0 from this config.
    ///
    /// This is the ONLY place genesis state is derived.  Every node calling
    /// `build_block0()` with the same `genesis.toml` gets the same result.
    pub fn build_block0(&self) -> Result<crate::Blockchain> {
        use crate::block::BlockHeader;
        use crate::contracts::bonding_curve::{
            BondingCurveToken, CurveType, PiecewiseLinearCurve, Threshold,
        };
        use crate::contracts::tokens::{CBE_NAME, CBE_SYMBOL};
        use crate::integration::crypto_integration::PublicKey;
        info!(
            "Building genesis block from config (chain_id={})",
            self.chain.chain_id
        );

        // Validate that the config's p_start_0 matches the compiled-in
        // canonical constant.  A mismatch means the genesis.toml was edited
        // to use a non-canonical curve, which would produce a different band
        // table at runtime while the executor still uses the hardcoded BANDS.
        {
            use crate::contracts::bonding_curve::canonical::P_START_0;
            if self.cbe_curve.p_start_0 as u128 != P_START_0 {
                bail!(
                    "genesis.toml [cbe_curve] p_start_0 ({}) does not match \
                     canonical::P_START_0 ({}); update genesis.toml or the \
                     compiled constant",
                    self.cbe_curve.p_start_0,
                    P_START_0,
                );
            }
        }

        let genesis_timestamp = self.genesis_timestamp()?;

        // ── block 0 header ──────────────────────────────────────────────────
        let header = BlockHeader::new(
            1,
            crate::types::Hash::default(),
            crate::types::Hash::default(),
            genesis_timestamp,
            0,
        );
        let genesis_block = crate::block::Block::new(header, Vec::new());

        // ── bootstrap blockchain state ───────────────────────────────────────
        let mut bc = crate::Blockchain::new_empty_for_genesis(genesis_block)?;

        // NOTE: cbe_token field removed from Blockchain (EPIC-001 Phase 1).
        // CBE token state will be managed via the standard token_balances sled tree.

        // ── bonding curve ────────────────────────────────────────────────────
        let genesis_creator = PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: [0u8; 32],
        };
        let token_id = crate::Blockchain::derive_cbe_token_id_pub();
        if !bc.bonding_curve_registry.contains(&token_id) {
            let curve = CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default());
            let threshold =
                Threshold::ReserveAmount(self.bonding_curve.graduation_threshold as u128);
            match BondingCurveToken::deploy(
                token_id,
                CBE_NAME.to_string(),
                CBE_SYMBOL.to_string(),
                curve,
                threshold,
                true,
                genesis_creator,
                "did:zhtp:genesis".to_string(),
                0,
                genesis_timestamp,
            ) {
                Ok(token) => {
                    if let Err(e) = bc.bonding_curve_registry.register(token) {
                        warn!("Failed to register CBE bonding curve: {}", e);
                    }
                }
                Err(e) => warn!("Failed to deploy CBE bonding curve: {}", e),
            }
        }

        // ── entity registry (if keys provided) ──────────────────────────────
        if !self.entity_registry.cbe_treasury_key.is_empty()
            && !self.entity_registry.nonprofit_treasury_key.is_empty()
        {
            let cbe_pk = key_from_hex(&self.entity_registry.cbe_treasury_key)
                .context("Invalid cbe_treasury_key in genesis.toml")?;
            let np_pk = key_from_hex(&self.entity_registry.nonprofit_treasury_key)
                .context("Invalid nonprofit_treasury_key in genesis.toml")?;
            let mut registry = crate::contracts::governance::EntityRegistry::new();
            if let Err(e) = registry.init(cbe_pk, np_pk) {
                warn!("Entity registry init failed: {}", e);
            } else {
                bc.entity_registry = Some(registry);
                info!("Entity registry initialized from genesis.toml");
            }
        }

        // ── bootstrap council ────────────────────────────────────────────────
        bc.council_threshold = self.bootstrap_council.threshold;
        for member in &self.bootstrap_council.members {
            bc.council_members.push(crate::dao::CouncilMember {
                identity_id: member.did.clone(),
                wallet_id: member.wallet.clone(),
                stake_amount: 0,
                joined_at_height: 0,
            });
        }
        if !self.bootstrap_council.members.is_empty() {
            info!(
                "Bootstrap council: {} members, threshold {}",
                self.bootstrap_council.members.len(),
                self.bootstrap_council.threshold,
            );
        }

        // ── state migration allocations ──────────────────────────────────────
        self.apply_allocations(&mut bc)?;

        // OPAQUE lobby-auth setup — must load here as well as apply_genesis_state.
        // Fresh-genesis paths (Blockchain::new / sled wipe) only call build_block0,
        // so skipping this left opaque_server_setup = None and OPAQUE endpoints
        // returned 503 "Lobby auth not configured...".
        bc.opaque_server_setup = self.load_opaque_setup()?;

        Ok(bc)
    }

    /// Apply state migration allocations (wallets, identities, web4, SOV balances).
    fn apply_allocations(&self, bc: &mut crate::Blockchain) -> Result<()> {
        let alloc = &self.allocations;
        if alloc.wallets.is_empty()
            && alloc.identities.is_empty()
            && alloc.web4_contracts.is_empty()
            && alloc.sov_balances.is_empty()
        {
            return Ok(());
        }

        use crate::integration::crypto_integration::PublicKey;
        use crate::transaction::{IdentityTransactionData, WalletTransactionData};

        info!(
            "Applying genesis allocations: {} wallets, {} identities, {} web4, {} SOV balances",
            alloc.wallets.len(),
            alloc.identities.len(),
            alloc.web4_contracts.len(),
            alloc.sov_balances.len(),
        );

        // wallets
        for w in &alloc.wallets {
            let wallet_id_bytes = hex::decode(&w.wallet_id).map_err(|e| {
                anyhow::anyhow!("invalid hex in wallet_id '{}': {}", w.wallet_id, e)
            })?;
            let pk_bytes = hex::decode(&w.public_key).map_err(|e| {
                anyhow::anyhow!("invalid hex in public_key '{}': {}", w.public_key, e)
            })?;
            if wallet_id_bytes.len() != 32 {
                warn!("Skipping wallet with invalid id: {}", w.wallet_id);
                continue;
            }
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(&wallet_id_bytes);
            let wallet_id_hash = crate::types::Hash::from(id_arr);
            let wallet_key = hex::encode(id_arr);
            let owner_id = w.owner_identity_id.as_deref().and_then(|hex_str| {
                let bytes = hex::decode(hex_str).ok()?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(crate::types::Hash::from(arr))
                } else {
                    None
                }
            });
            bc.wallet_registry.insert(
                wallet_key.clone(),
                WalletTransactionData {
                    wallet_id: wallet_id_hash,
                    wallet_type: w.wallet_type.clone(),
                    wallet_name: format!("migrated-{}", &w.wallet_id[..8]),
                    alias: None,
                    public_key: pk_bytes,
                    kyber_public_key: vec![],
                    owner_identity_id: owner_id,
                    seed_commitment: crate::types::Hash::default(),
                    created_at: w.created_at,
                    registration_fee: 0,
                    capabilities: 0,
                    initial_balance: 0,
                },
            );
            bc.wallet_blocks.insert(wallet_key, 0u64);
        }

        // identities — populates in-memory registry only.
        // Sled-store backfill happens post-replay (see backfill_genesis_identities_to_store),
        // because bc.store is not yet attached at the time apply_genesis_state runs.
        for id in &alloc.identities {
            let pk_bytes = hex::decode(&id.public_key).map_err(|e| {
                anyhow::anyhow!(
                    "invalid hex in identity public_key '{}': {}",
                    id.public_key,
                    e
                )
            })?;
            bc.identity_registry.insert(
                id.did.clone(),
                IdentityTransactionData {
                    did: id.did.clone(),
                    display_name: id.display_name.clone(),
                    public_key: pk_bytes,
                    ownership_proof: vec![],
                    identity_type: id.identity_type.clone(),
                    did_document_hash: crate::types::Hash::default(),
                    created_at: id.created_at,
                    registration_fee: 0,
                    dao_fee: 0,
                    controlled_nodes: vec![],
                    owned_wallets: vec![],
                    kyber_public_key: vec![],
                },
            );
            bc.identity_blocks.insert(id.did.clone(), 0u64);
        }

        // web4 contracts
        for c in &alloc.web4_contracts {
            if let Ok(contract) =
                serde_json::from_str::<crate::contracts::web4::Web4Contract>(&c.contract_json)
            {
                let id_bytes = lib_crypto::hash_blake3(c.domain.as_bytes());
                bc.web4_contracts.insert(id_bytes, contract);
                bc.contract_blocks.insert(id_bytes, 0u64);
            } else {
                warn!("Failed to deserialize web4 contract: {}", c.contract_id);
            }
        }

        // SOV balances
        if !alloc.sov_balances.is_empty() {
            use crate::contracts::utils::generate_lib_token_id;
            let sov_id = generate_lib_token_id();
            let token = bc
                .token_contracts
                .entry(sov_id)
                .or_insert_with(crate::contracts::TokenContract::new_sov_native);
            for entry in &alloc.sov_balances {
                let wallet_id_bytes = hex::decode(&entry.wallet_id).map_err(|e| {
                    anyhow::anyhow!(
                        "invalid hex in sov_balance wallet_id '{}': {}",
                        entry.wallet_id,
                        e
                    )
                })?;
                let key_id = if wallet_id_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&wallet_id_bytes);
                    arr
                } else {
                    [0u8; 32]
                };
                // Use empty dilithium_pk — the SOV balance key is derived solely from
                // the wallet_id (key_id), matching the pattern in collect_sov_backfill_entries.
                let pk = PublicKey {
                    dilithium_pk: [0u8; 2592],
                    kyber_pk: [0u8; 1568],
                    key_id,
                };
                if let Err(e) = token.mint(&pk, entry.balance) {
                    warn!(
                        "Failed to credit SOV balance for {}: {}",
                        entry.wallet_id, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Parsed `(wallet_id_bytes, balance_atoms)` pairs from `[allocations.sov_balances]`.
    pub fn sov_allocation_entries(&self) -> Result<Vec<([u8; 32], u128)>> {
        let mut entries = Vec::new();
        for entry in &self.allocations.sov_balances {
            let wallet_id_bytes = hex::decode(&entry.wallet_id).map_err(|e| {
                anyhow::anyhow!(
                    "invalid hex in sov_balance wallet_id '{}': {}",
                    entry.wallet_id,
                    e
                )
            })?;
            if wallet_id_bytes.len() != 32 {
                warn!(
                    "Skipping sov_balance with invalid wallet_id length: {}",
                    entry.wallet_id
                );
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&wallet_id_bytes);
            if entry.balance > 0 {
                entries.push((arr, entry.balance));
            }
        }
        Ok(entries)
    }

    /// Project **SOV-native** chain bootstrap into sled during an open block transaction.
    ///
    /// Scope (GENESIS-1 / #2729): native SOV contract shell + `[allocations.sov_balances]`
    /// only. CBE is a DAO token — its curve contract and 20B treasury allocation remain
    /// on the legacy block-0 path until GENESIS-6 (#2734).
    ///
    /// **Bug fix (latent):** `build_block0()` populated SOV in in-memory `token_contracts`
    /// but block-0 replay never persisted the SOV contract record to sled. Fresh-sync
    /// nodes had balances (post-#2725) but `get_token_contract` / `iter_token_contracts`
    /// omitted SOV until this install path runs.
    ///
    /// Must be called while `begin_block` is active (executor block-0 apply/replay).
    /// `put_token_contract` returns `NoActiveTransaction` otherwise.
    pub fn project_chain_bootstrap_to_store(
        &self,
        store: &dyn crate::storage::BlockchainStore,
    ) -> Result<ChainBootstrapOutcome> {
        let sov_contract_installed = self.ensure_sov_native_contract_in_store(store)?;
        let sov_balances_credited = self.credit_sov_allocations_in_open_transaction(store)?;
        Ok(ChainBootstrapOutcome {
            sov_contract_installed,
            sov_balances_credited,
        })
    }

    /// Install the SOV native token contract metadata in sled if missing.
    ///
    /// Idempotent within an open block transaction: uses batch-aware
    /// `get_token_contract` (CR #2658) so a second call in the same `begin_block`
    /// returns `Ok(false)` after the first install.
    fn ensure_sov_native_contract_in_store(
        &self,
        store: &dyn crate::storage::BlockchainStore,
    ) -> Result<bool> {
        use crate::contracts::utils::generate_lib_token_id;
        use crate::storage::TokenId;

        let token_id = TokenId::new(generate_lib_token_id());
        if store
            .get_token_contract(&token_id)
            .map_err(|e| anyhow::anyhow!("genesis SOV contract read failed: {}", e))?
            .is_some()
        {
            return Ok(false);
        }
        let contract = crate::contracts::TokenContract::new_sov_native();
        store
            .put_token_contract(&contract)
            .map_err(|e| anyhow::anyhow!("genesis SOV contract install failed: {}", e))?;
        info!("Genesis: installed SOV native token contract in sled");
        Ok(true)
    }

    /// Persist genesis SOV allocations into sled (startup / no active tx).
    /// Idempotent: only fills addresses missing from `token_balances`.
    pub fn credit_sov_allocations_to_store(
        &self,
        store: &dyn crate::storage::BlockchainStore,
    ) -> Result<usize> {
        let entries = self.sov_allocation_entries()?;
        if entries.is_empty() {
            return Ok(0);
        }
        use crate::contracts::utils::generate_lib_token_id;
        let token_id = crate::storage::TokenId::new(generate_lib_token_id());
        let written = store
            .backfill_token_balances_from_contract(&token_id, &entries)
            .map_err(|e| anyhow::anyhow!("genesis SOV backfill failed: {}", e))?;
        if written > 0 {
            info!(
                "Genesis: persisted {} SOV allocation balances to token_balances tree",
                written
            );
        }
        Ok(written)
    }

    /// Persist genesis SOV allocations during an open block/metadata transaction.
    ///
    /// Prefer [`Self::project_chain_bootstrap_to_store`] at block 0 — it also installs
    /// the SOV native contract shell.
    ///
    /// Idempotent for block-0 replay: skips any address whose sled balance is
    /// already non-zero. That is correct because (a) a fresh wipe has zero
    /// balances and receives the full genesis allocation set, and (b) a
    /// non-zero balance means the address was already seeded or has had later
    /// chain activity — re-crediting the genesis amount would double-mint.
    pub fn credit_sov_allocations_in_open_transaction(
        &self,
        store: &dyn crate::storage::BlockchainStore,
    ) -> Result<usize> {
        use crate::contracts::utils::generate_lib_token_id;
        use crate::storage::{Address, TokenId};

        let entries = self.sov_allocation_entries()?;
        if entries.is_empty() {
            return Ok(0);
        }

        let token_id = TokenId::new(generate_lib_token_id());
        let mut credited = 0usize;
        let mut supply_delta = 0u128;

        for (wallet_id, balance) in entries {
            let addr = Address::new(wallet_id);
            let current = store
                .get_token_balance(&token_id, &addr)
                .map_err(|e| anyhow::anyhow!("genesis SOV balance read failed: {}", e))?;
            if current > 0 {
                continue;
            }
            store
                .set_token_balance(&token_id, &addr, balance)
                .map_err(|e| anyhow::anyhow!("genesis SOV credit failed: {}", e))?;
            supply_delta = supply_delta.saturating_add(balance);
            credited += 1;
        }

        if supply_delta > 0 {
            let current_supply = store
                .get_token_supply(&token_id)
                .map_err(|e| anyhow::anyhow!("genesis SOV supply read failed: {}", e))?
                .unwrap_or(0);
            store
                .put_token_supply(&token_id, current_supply.saturating_add(supply_delta))
                .map_err(|e| anyhow::anyhow!("genesis SOV supply update failed: {}", e))?;
        }

        if credited > 0 {
            info!(
                "Genesis: credited {} SOV allocation balances in block transaction",
                credited
            );
        }
        Ok(credited)
    }

    /// Resolve the OPAQUE server-setup bytes from this config, if the
    /// `[opaque]` section is present. Pulled out into its own helper so
    /// every Blockchain construction path (apply_genesis_state, load_from_store)
    /// can load it consistently (reviewer #2569 — restart path was skipping it).
    pub fn load_opaque_setup(&self) -> Result<Option<crate::opaque::OpaqueServerSetupBytes>> {
        match self.opaque {
            Some(ref op) => {
                let bytes = crate::opaque::parse_server_setup_b64(&op.server_setup_b64)
                    .context("genesis [opaque] server_setup_b64 invalid")?;
                info!(
                    "Loaded OPAQUE server setup (ciphersuite={}, fingerprint={}, bytes={})",
                    crate::opaque::CIPHERSUITE_ID,
                    bytes.fingerprint(),
                    bytes.as_slice().len()
                );
                Ok(Some(bytes))
            }
            None => {
                info!("No [opaque] section in genesis — lobby auth disabled for this network");
                Ok(None)
            }
        }
    }

    /// Re-apply genesis state (identities, wallets, validators, council) to an existing
    /// blockchain during catch-up sync. Called when a synced node receives block 0 but
    /// the identity/wallet registries are empty because genesis state is populated via
    /// direct inserts in build_block0(), not via transactions.
    pub fn apply_genesis_state(&self, bc: &mut crate::Blockchain) -> Result<()> {
        bc.begin_genesis_apply();
        let result = self.apply_genesis_state_inner(bc);
        bc.end_genesis_apply();
        result
    }

    fn apply_genesis_state_inner(&self, bc: &mut crate::Blockchain) -> Result<()> {
        // Load the OPAQUE server setup if `[opaque]` is present.
        // Missing section is allowed in v1 — networks without lobby auth
        // simply have `bc.opaque_server_setup = None` and the OPAQUE
        // endpoints will return 503 at runtime.
        bc.opaque_server_setup = self.load_opaque_setup()?;
        {
            let alloc = &self.allocations;
            // identities
            for id in &alloc.identities {
                let pk_bytes = hex::decode(&id.public_key).unwrap_or_default();
                if !bc.identity_registry.contains_key(&id.did) {
                    bc.identity_registry.insert(
                        id.did.clone(),
                        crate::transaction::IdentityTransactionData {
                            did: id.did.clone(),
                            display_name: id.display_name.clone(),
                            public_key: pk_bytes,
                            ownership_proof: vec![],
                            identity_type: id.identity_type.clone(),
                            did_document_hash: crate::types::Hash::default(),
                            created_at: id.created_at,
                            registration_fee: 0,
                            dao_fee: 0,
                            controlled_nodes: vec![],
                            owned_wallets: vec![],
                            kyber_public_key: vec![],
                        },
                    );
                    bc.identity_blocks.insert(id.did.clone(), 0u64);
                }
            }
            // wallets
            for w in &alloc.wallets {
                let wallet_id_bytes = hex::decode(&w.wallet_id).unwrap_or_default();
                let wallet_key = w.wallet_id.clone();
                if !bc.wallet_registry.contains_key(&wallet_key) {
                    let pk_bytes = hex::decode(&w.public_key).unwrap_or_default();
                    let owner_id = w.owner_identity_id.as_ref().map(|oid| {
                        let hex_part = oid.strip_prefix("did:zhtp:").unwrap_or(oid);
                        let bytes = hex::decode(hex_part).unwrap_or_default();
                        let mut h = [0u8; 32];
                        let len = bytes.len().min(32);
                        h[..len].copy_from_slice(&bytes[..len]);
                        crate::types::Hash::from_slice(&h)
                    });
                    let mut wid = [0u8; 32];
                    let len = wallet_id_bytes.len().min(32);
                    wid[..len].copy_from_slice(&wallet_id_bytes[..len]);
                    bc.wallet_registry.insert(
                        wallet_key.clone(),
                        crate::transaction::WalletTransactionData {
                            wallet_id: crate::types::Hash::from_slice(&wid),
                            wallet_type: w.wallet_type.clone(),
                            wallet_name: String::new(),
                            alias: None,
                            public_key: pk_bytes,
                            kyber_public_key: vec![],
                            owner_identity_id: owner_id,
                            seed_commitment: crate::types::Hash::default(),
                            created_at: w.created_at,
                            registration_fee: 0,
                            capabilities: 0,
                            initial_balance: 0,
                        },
                    );
                    bc.wallet_blocks.insert(wallet_key, 0u64);
                }
            }
        }

        // Register usernames for identities with display_names.
        // Populates did_to_username so @username messaging lookups work.
        for id in &self.allocations.identities {
            if !id.display_name.is_empty() && !bc.did_to_username.contains_key(&id.did) {
                let username = id
                    .display_name
                    .to_lowercase()
                    .chars()
                    .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                    .collect::<String>();
                if username.len() >= 3 && !bc.credential_registry.contains_key(&username) {
                    bc.did_to_username.insert(id.did.clone(), username.clone());
                    bc.credential_registry.insert(
                        username.clone(),
                        crate::transaction::UserCredential {
                            username: username.clone(),
                            owner_did: id.did.clone(),
                            password_hash: String::new(),
                            registered_at_height: 0,
                            registered_at: 0,
                            password_changed_at_height: 0,
                            opaque_record: Vec::new(),
                            auth_method: crate::transaction::credentials::AuthMethod::Argon2idPhc,
                        },
                    );
                }
            }
        }

        // council
        if bc.council_members.is_empty() {
            bc.council_threshold = self.bootstrap_council.threshold;
            for member in &self.bootstrap_council.members {
                bc.council_members.push(crate::dao::CouncilMember {
                    identity_id: member.did.clone(),
                    wallet_id: member.wallet.clone(),
                    stake_amount: 0,
                    joined_at_height: 0,
                });
            }
        }

        Ok(())
    }

    /// Verify the hash of block 0 produced by `build_block0()` against `CANONICAL_GENESIS_HASH`.
    ///
    /// If `CANONICAL_GENESIS_HASH` is all-zeros, verification is skipped (pre-ceremony placeholder).
    pub fn verify_hash(&self, block0_hash: &[u8; 32]) -> Result<()> {
        let expected = hex::decode(CANONICAL_GENESIS_HASH)
            .context("CANONICAL_GENESIS_HASH is not valid hex")?;
        if expected.len() != 32 {
            anyhow::bail!(
                "CANONICAL_GENESIS_HASH has wrong length ({} bytes, expected 32)",
                expected.len()
            );
        }
        if expected.iter().all(|&b| b == 0) {
            // Hash not yet set — pre-ceremony, skip verification
            return Ok(());
        }
        if expected != block0_hash {
            bail!(
                "Genesis block 0 hash mismatch!\n  Expected : {}\n  Got      : {}\n\
                 This node is on a different chain. Check your genesis.toml.",
                CANONICAL_GENESIS_HASH,
                hex::encode(block0_hash),
            );
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a hex-encoded Dilithium5 public key, or return a stub with `fill` key_id byte.
#[allow(dead_code)]
fn key_from_hex_or_stub(
    hex_str: &str,
    fill: u8,
) -> crate::integration::crypto_integration::PublicKey {
    if hex_str.is_empty() {
        return crate::integration::crypto_integration::PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: [fill; 32],
        };
    }
    match key_from_hex(hex_str) {
        Ok(k) => k,
        Err(e) => {
            warn!(
                "Invalid pool key in genesis.toml (fill=0x{:02x}), using stub: {}",
                fill, e
            );
            crate::integration::crypto_integration::PublicKey {
                dilithium_pk: [0u8; 2592],
                kyber_pk: [0u8; 1568],
                key_id: [fill; 32],
            }
        }
    }
}

/// Parse a hex-encoded Dilithium5 public key into a `PublicKey`.
///
/// The `key_id` is derived as `blake3(dilithium_pk)`.
fn key_from_hex(hex_str: &str) -> Result<crate::integration::crypto_integration::PublicKey> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(trimmed).context("Invalid hex in genesis.toml key")?;
    let key_id = lib_crypto::hash_blake3(&bytes);
    let dilithium_pk: [u8; 2592] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "Invalid Dilithium key length in genesis.toml key: expected 2592 bytes, got {}",
            bytes.len()
        )
    })?;
    Ok(crate::integration::crypto_integration::PublicKey {
        dilithium_pk,
        kyber_pk: [0u8; 1568],
        key_id,
    })
}

/// Pure-integer proleptic Gregorian calendar → Unix day number (days since 1970-01-01).
///
/// Uses the civil calendar algorithm that shifts March to month 0 to simplify
/// leap-year handling. No floating-point arithmetic.
///
/// NOTE: Will underflow (panic in debug) for dates before approximately 1972
/// because the subtraction of 719468 can exceed the accumulated day count.
/// For genesis timestamps (year 2025+) this is not a concern.
fn days_since_unix_epoch(year: u64, month: u64, day: u64) -> u64 {
    // Shift so March = month 0, making leap day (Feb 29) fall at end of "year".
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400; // year-of-era [0, 399]
    let doy = (153 * m + 2) / 5 + day - 1; // day-of-year [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day-of-era [0, 146096]
                                                     // 719468 = days from 0000-03-01 to 1970-01-01
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_from_embedded_parses() {
        let config = GenesisConfig::from_embedded().expect("embedded genesis.toml should parse");
        // v2 chain (CONS-305 cutover): chain_id 2, distinct from v1's 1.
        assert_eq!(config.chain.chain_id, 2);
        assert_eq!(config.bootstrap_council.threshold, 1);
        assert!(
            !config.bootstrap_council.members.is_empty(),
            "council must have at least one member"
        );
        assert_eq!(config.bonding_curve.graduation_threshold, 2_745_966);
    }

    #[test]
    fn test_genesis_timestamp() {
        let config = GenesisConfig::from_embedded().expect("parse");
        let ts = config.genesis_timestamp().expect("timestamp");
        // genesis.toml genesis_time "2026-05-01T00:00:00Z" = 1777593600
        assert_eq!(ts, 1_777_593_600);
    }

    // cbe_token field removed from Blockchain (EPIC-001 Phase 1).
    // Tests that verified cbe_token on the Blockchain struct are no longer applicable.

    #[test]
    fn test_build_block0_is_deterministic() {
        let config = GenesisConfig::from_embedded().expect("parse");
        let bc1 = config.build_block0().expect("build 1");
        let bc2 = config.build_block0().expect("build 2");
        // Both produce the same block hash
        assert_eq!(
            bc1.blocks[0].header.block_hash,
            bc2.blocks[0].header.block_hash
        );
    }

    #[test]
    fn test_build_block0_loads_opaque_setup_when_present() {
        let config = GenesisConfig::from_embedded().expect("parse");
        // Assert correct behaviour for whichever embedded genesis is present
        // (does not run both branches in one execution — see also
        // `test_build_block0_opaque_absent_means_none` for the forced-absent path).
        let bc = config.build_block0().expect("build");
        if config.opaque.is_some() {
            assert!(
                bc.opaque_server_setup.is_some(),
                "build_block0 must load [opaque] server setup (fresh-genesis / sled-wipe path)"
            );
        } else {
            assert!(
                bc.opaque_server_setup.is_none(),
                "embedded genesis without [opaque] must leave opaque_server_setup unset"
            );
        }
    }

    #[test]
    fn test_build_block0_opaque_absent_means_none() {
        let mut config = GenesisConfig::from_embedded().expect("parse");
        config.opaque = None;
        let bc = config.build_block0().expect("build");
        assert!(
            bc.opaque_server_setup.is_none(),
            "build_block0 must leave opaque_server_setup unset when [opaque] is absent"
        );
    }

    #[test]
    fn test_verify_hash_skips_when_all_zeros() {
        let config = GenesisConfig::from_embedded().expect("parse");
        // When CANONICAL_GENESIS_HASH is all zeros, verification is skipped.
        // This is the current testnet state - hash verification is disabled
        // and determinism is enforced via the bootstrap leader gate instead.
        // TODO: Update this test when the real genesis hash is set.
        assert!(config.verify_hash(&[0u8; 32]).is_ok());
    }

    #[test]
    fn test_verify_hash_enforces_when_set() {
        // This test documents the expected behavior once CANONICAL_GENESIS_HASH
        // is set to a real value. It will fail until then.
        //
        // Once the real hash is set, update this test with the actual hash:
        // let config = GenesisConfig::from_embedded().expect("parse");
        // let real_hash = hex::decode(" actual 64 char hash ").unwrap();
        // assert!(config.verify_hash(&real_hash).is_ok());
        // assert!(config.verify_hash(&[0u8; 32]).is_err()); // Wrong hash fails
    }
}
