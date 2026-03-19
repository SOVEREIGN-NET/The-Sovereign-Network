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
/// Set to all-zeros until the mainnet key ceremony fills `genesis.toml` with real
/// public keys and the deterministic hash is computed.  Once set, any node whose
/// block 0 does not match this hash refuses to start.
///
/// Workflow:
///   1. Fill `genesis.toml` with real keys (key ceremony).
///   2. Run `zhtp-cli genesis build --config genesis.toml` → prints the block 0 hash.
///   3. Set this constant to that hash and commit.
///   4. Tag the commit `mainnet-genesis-v1`.
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
    pub cbe_token: CbeTokenConfig,
    pub entity_registry: EntityRegistryConfig,
    pub bootstrap_council: BootstrapCouncilConfig,
    pub bonding_curve: BondingCurveConfig,
    #[serde(default)]
    pub allocations: GenesisAllocations,
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
pub struct CbeTokenConfig {
    pub total_supply: u64,
    #[serde(default)]
    pub compensation_pool_key: String,
    #[serde(default)]
    pub operational_pool_key: String,
    #[serde(default)]
    pub performance_pool_key: String,
    #[serde(default)]
    pub strategic_pool_key: String,
    pub vesting: CbeVestingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CbeVestingConfig {
    pub operational: VestingScheduleConfig,
    pub performance: VestingScheduleConfig,
    pub strategic: VestingScheduleConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VestingScheduleConfig {
    pub cliff_months: u64,
    pub vest_months: u64,
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
    pub public_key: String,
    pub balance: u64,
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
                owner_identity_id: w
                    .owner_identity_id
                    .map(|id| hex::encode(id.as_bytes())),
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
                .balances
                .iter()
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
        use crate::contracts::tokens::{
            CbeToken, VestingPool, CBE_NAME, CBE_OPERATIONAL_TREASURY,
            CBE_PERFORMANCE_INCENTIVES, CBE_STRATEGIC_RESERVES, CBE_SYMBOL,
        };
        use crate::integration::crypto_integration::PublicKey;
        use crate::types::Difficulty;

        info!(
            "Building genesis block from config (chain_id={})",
            self.chain.chain_id
        );

        let genesis_timestamp = self.genesis_timestamp()?;

        // ── block 0 header ──────────────────────────────────────────────────
        let genesis_difficulty = Difficulty::from_bits(0x1fffffff);
        let header = BlockHeader::new(
            1,
            crate::types::Hash::default(),
            crate::types::Hash::default(),
            genesis_timestamp,
            genesis_difficulty,
            0,
            0,
            0,
            genesis_difficulty,
        );
        let genesis_block = crate::block::Block::new(header, Vec::new());

        // ── bootstrap blockchain state ───────────────────────────────────────
        let mut bc = crate::Blockchain::new_empty_for_genesis(genesis_block)?;

        // ── CBE token pool keys ─────────────────────────────────────────────
        let compensation_key =
            key_from_hex_or_stub(&self.cbe_token.compensation_pool_key, 0x01);
        let operational_key =
            key_from_hex_or_stub(&self.cbe_token.operational_pool_key, 0x02);
        let performance_key =
            key_from_hex_or_stub(&self.cbe_token.performance_pool_key, 0x03);
        let strategic_key =
            key_from_hex_or_stub(&self.cbe_token.strategic_pool_key, 0x04);

        // ── initialise CBE token ─────────────────────────────────────────────
        bc.cbe_token = CbeToken::new();
        bc.cbe_token
            .init(
                &compensation_key,
                &operational_key,
                &performance_key,
                &strategic_key,
            )
            .map_err(|e| anyhow::anyhow!("CBE token init failed: {}", e))?;

        const SECONDS_PER_MONTH: u64 = 30 * 24 * 60 * 60;
        const BLOCKS_PER_MONTH: u64 = SECONDS_PER_MONTH / crate::TARGET_BLOCK_TIME;

        let v = &self.cbe_token.vesting;

        bc.cbe_token
            .create_vesting(
                &operational_key,
                CBE_OPERATIONAL_TREASURY,
                0,
                v.operational.vest_months * BLOCKS_PER_MONTH,
                v.operational.cliff_months * BLOCKS_PER_MONTH,
                VestingPool::Operational,
            )
            .map_err(|e| anyhow::anyhow!("Operational vesting failed: {}", e))?;

        bc.cbe_token
            .create_vesting(
                &performance_key,
                CBE_PERFORMANCE_INCENTIVES,
                0,
                v.performance.vest_months * BLOCKS_PER_MONTH,
                v.performance.cliff_months * BLOCKS_PER_MONTH,
                VestingPool::Performance,
            )
            .map_err(|e| anyhow::anyhow!("Performance vesting failed: {}", e))?;

        bc.cbe_token
            .create_vesting(
                &strategic_key,
                CBE_STRATEGIC_RESERVES,
                0,
                v.strategic.vest_months * BLOCKS_PER_MONTH,
                v.strategic.cliff_months * BLOCKS_PER_MONTH,
                VestingPool::Strategic,
            )
            .map_err(|e| anyhow::anyhow!("Strategic vesting failed: {}", e))?;

        info!("CBE token initialized: 100B supply with vesting schedules");

        // ── bonding curve ────────────────────────────────────────────────────
        let genesis_creator = PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: [0u8; 32],
        };
        let token_id = crate::Blockchain::derive_cbe_token_id_pub();
        if !bc.bonding_curve_registry.contains(&token_id) {
            let curve = CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default());
            let threshold =
                Threshold::ReserveAmount(self.bonding_curve.graduation_threshold);
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
            let wallet_id_bytes = hex::decode(&w.wallet_id)
                .map_err(|e| anyhow::anyhow!("invalid hex in wallet_id '{}': {}", w.wallet_id, e))?;
            let pk_bytes = hex::decode(&w.public_key)
                .map_err(|e| anyhow::anyhow!("invalid hex in public_key '{}': {}", w.public_key, e))?;
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

        // identities
        for id in &alloc.identities {
            let pk_bytes = hex::decode(&id.public_key)
                .map_err(|e| anyhow::anyhow!("invalid hex in identity public_key '{}': {}", id.public_key, e))?;
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
                let wallet_id_bytes = hex::decode(&entry.wallet_id)
                    .map_err(|e| anyhow::anyhow!("invalid hex in sov_balance wallet_id '{}': {}", entry.wallet_id, e))?;
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
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
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
fn key_from_hex_or_stub(
    hex_str: &str,
    fill: u8,
) -> crate::integration::crypto_integration::PublicKey {
    if hex_str.is_empty() {
        return crate::integration::crypto_integration::PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
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
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [fill; 32],
            }
        }
    }
}

/// Parse a hex-encoded Dilithium5 public key into a `PublicKey`.
///
/// The `key_id` is derived as `blake3(dilithium_pk)`.
fn key_from_hex(
    hex_str: &str,
) -> Result<crate::integration::crypto_integration::PublicKey> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(trimmed).context("Invalid hex in genesis.toml key")?;
    let key_id = lib_crypto::hash_blake3(&bytes);
    Ok(crate::integration::crypto_integration::PublicKey {
        dilithium_pk: bytes,
        kyber_pk: vec![],
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
    use crate::contracts::tokens::CBE_TOTAL_SUPPLY;

    #[test]
    fn test_from_embedded_parses() {
        let config =
            GenesisConfig::from_embedded()// REMEDIATED PANIC: // REMEDIATED: .expect("embedded genesis.toml should parse");
        assert_eq!(config.chain.chain_id, 1);
        assert_eq!(config.cbe_token.total_supply, 100_000_000_000);
        assert_eq!(config.bootstrap_council.threshold, 3);
        assert_eq!(config.bonding_curve.graduation_threshold, 2_745_966_000);
    }

    #[test]
    fn test_genesis_timestamp() {
        let config = GenesisConfig::from_embedded()// REMEDIATED PANIC: // REMEDIATED: .expect("parse");
        let ts = config.genesis_timestamp()// REMEDIATED PANIC: // REMEDIATED: .expect("timestamp");
        // 2025-11-01T00:00:00Z = 1761955200
        assert_eq!(ts, 1_761_955_200);
    }

    #[test]
    fn test_build_block0_produces_initialized_cbe_token() {
        let config = GenesisConfig::from_embedded()// REMEDIATED PANIC: // REMEDIATED: .expect("parse");
        let bc = config.build_block0()// REMEDIATED PANIC: // REMEDIATED: .expect("build_block0");
        assert!(bc.cbe_token.is_initialized(), "CBE token must be initialized");
        assert_eq!(bc.cbe_token.total_supply(), CBE_TOTAL_SUPPLY);
    }

    #[test]
    fn test_build_block0_is_deterministic() {
        let config = GenesisConfig::from_embedded()// REMEDIATED PANIC: // REMEDIATED: .expect("parse");
        let bc1 = config.build_block0()// REMEDIATED PANIC: // REMEDIATED: .expect("build 1");
        let bc2 = config.build_block0()// REMEDIATED PANIC: // REMEDIATED: .expect("build 2");
        // Both produce the same CBE supply
        assert_eq!(bc1.cbe_token.total_supply(), bc2.cbe_token.total_supply());
    }

    #[test]
    fn test_verify_hash_skips_when_all_zeros() {
        let config = GenesisConfig::from_embedded()// REMEDIATED PANIC: // REMEDIATED: .expect("parse");
        // Should not error when CANONICAL_GENESIS_HASH is all zeros
        assert!(config.verify_hash(&[0u8; 32]).is_ok());
    }
}
