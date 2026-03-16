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

        // --- wallets ---
        let wallets = bc
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

        // --- identities ---
        let identities = bc
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

        // --- web4 contracts ---
        let web4_contracts = bc
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

        // --- SOV balances ---
        let sov_id = generate_lib_token_id();
        let sov_balances = if let Some(token) = bc.token_contracts.get(&sov_id) {
            token
                .balances
                .iter()
                .filter(|(_, &bal)| bal > 0)
                .map(|(pk, &bal)| SovBalanceAllocation {
                    wallet_id: hex::encode(pk.key_id),
                    public_key: hex::encode(&pk.dilithium_pk),
                    balance: bal,
                })
                .collect()
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
        let s = self
            .chain
            .genesis_time
            .trim_end_matches('Z')
            .trim_end_matches("+00:00");
        if s.len() >= 19 {
            let year: u64 = s[..4].parse().unwrap_or(2025);
            let month: u64 = s[5..7].parse().unwrap_or(11);
            let day: u64 = s[8..10].parse().unwrap_or(1);
            let hour: u64 = s[11..13].parse().unwrap_or(0);
            let min: u64 = s[14..16].parse().unwrap_or(0);
            let sec: u64 = s[17..19].parse().unwrap_or(0);
            let days_since_epoch = days_since_unix_epoch(year, month, day);
            return Ok(days_since_epoch * 86_400 + hour * 3_600 + min * 60 + sec);
        }
        // Fallback: fixed testnet genesis timestamp
        Ok(1_730_419_200)
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
        use crate::contracts::tokens::{CbeToken, VestingPool, CBE_NAME, CBE_SYMBOL};
        use crate::integration::crypto_integration::PublicKey;
        use crate::types::Difficulty;

        info!(
            "Building genesis block from config (chain_id={})",
            self.chain.chain_id
        );

        let genesis_timestamp = self.genesis_timestamp().unwrap_or(1_730_419_200);

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
                30_000_000_000,
                0,
                v.operational.vest_months * BLOCKS_PER_MONTH,
                v.operational.cliff_months * BLOCKS_PER_MONTH,
                VestingPool::Operational,
            )
            .map_err(|e| anyhow::anyhow!("Operational vesting failed: {}", e))?;

        bc.cbe_token
            .create_vesting(
                &performance_key,
                20_000_000_000,
                0,
                v.performance.vest_months * BLOCKS_PER_MONTH,
                v.performance.cliff_months * BLOCKS_PER_MONTH,
                VestingPool::Performance,
            )
            .map_err(|e| anyhow::anyhow!("Performance vesting failed: {}", e))?;

        bc.cbe_token
            .create_vesting(
                &strategic_key,
                10_000_000_000,
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
            let wallet_id_bytes = hex::decode(&w.wallet_id).unwrap_or_default();
            let pk_bytes = hex::decode(&w.public_key).unwrap_or_default();
            if wallet_id_bytes.len() != 32 {
                warn!("Skipping wallet with invalid id: {}", w.wallet_id);
                continue;
            }
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(&wallet_id_bytes);
            let wallet_id_hash = crate::types::Hash::from(id_arr);
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
                hex::encode(id_arr),
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
        }

        // identities
        for id in &alloc.identities {
            let pk_bytes = hex::decode(&id.public_key).unwrap_or_default();
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
        }

        // web4 contracts
        for c in &alloc.web4_contracts {
            if let Ok(contract) =
                serde_json::from_str::<crate::contracts::web4::Web4Contract>(&c.contract_json)
            {
                let id_bytes = lib_crypto::hash_blake3(c.contract_id.as_bytes());
                bc.web4_contracts.insert(id_bytes, contract);
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
                let pk_bytes = hex::decode(&entry.public_key).unwrap_or_default();
                let wallet_id_bytes = hex::decode(&entry.wallet_id).unwrap_or_default();
                let key_id = if wallet_id_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&wallet_id_bytes);
                    arr
                } else {
                    [0u8; 32]
                };
                let pk = PublicKey {
                    dilithium_pk: pk_bytes,
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

/// Gregorian-calendar days since 1970-01-01. Good enough for genesis timestamps.
fn days_since_unix_epoch(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 12 } else { month };
    let a = (y / 100) as i64;
    let b = 2 - a + a / 4;
    let jdn = (365.25 * (y + 4716) as f64) as i64
        + (30.6001 * (m + 1) as f64) as i64
        + day as i64
        + b
        - 1524;
    // Julian Day Number for 1970-01-01 is 2440588
    (jdn - 2_440_588).max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_embedded_parses() {
        let config =
            GenesisConfig::from_embedded().expect("embedded genesis.toml should parse");
        assert_eq!(config.chain.chain_id, 1);
        assert_eq!(config.cbe_token.total_supply, 100_000_000_000);
        assert_eq!(config.bootstrap_council.threshold, 3);
        assert_eq!(config.bonding_curve.graduation_threshold, 2_745_966_000);
    }

    #[test]
    fn test_genesis_timestamp() {
        let config = GenesisConfig::from_embedded().expect("parse");
        let ts = config.genesis_timestamp().expect("timestamp");
        // 2025-11-01T00:00:00Z = 1761955200
        assert_eq!(ts, 1_761_955_200);
    }

    #[test]
    fn test_build_block0_produces_initialized_cbe_token() {
        let config = GenesisConfig::from_embedded().expect("parse");
        let bc = config.build_block0().expect("build_block0");
        assert!(bc.cbe_token.is_initialized(), "CBE token must be initialized");
        assert_eq!(bc.cbe_token.total_supply(), 100_000_000_000);
    }

    #[test]
    fn test_build_block0_is_deterministic() {
        let config = GenesisConfig::from_embedded().expect("parse");
        let bc1 = config.build_block0().expect("build 1");
        let bc2 = config.build_block0().expect("build 2");
        // Both produce the same CBE supply
        assert_eq!(bc1.cbe_token.total_supply(), bc2.cbe_token.total_supply());
    }

    #[test]
    fn test_verify_hash_skips_when_all_zeros() {
        let config = GenesisConfig::from_embedded().expect("parse");
        // Should not error when CANONICAL_GENESIS_HASH is all zeros
        assert!(config.verify_hash(&[0u8; 32]).is_ok());
    }
}
