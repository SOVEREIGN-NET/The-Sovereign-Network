//! Sovereign Asset core types (ADR: docs/arch/sovereign-asset.md).

use serde::{Deserialize, Serialize};

/// How `asset_id` was assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetIdSource {
    /// SA-3+ launches: `asset_id = launch_tx_hash`.
    LaunchTx,
    /// Read projection from pre-SA-3 `TokenContract` / `BondingCurveToken` (`token_id`).
    LegacyTokenId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupplyMode {
    Fixed,
    Elastic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetAuthority {
    Creator { key_id: [u8; 32] },
    Governance { module_ref: [u8; 32] },
}

/// Bit flags for enabled optional modules (API discovery).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetModuleFlags(pub u8);

impl AssetModuleFlags {
    pub const CURVE: u8 = 1 << 0;
    pub const REWARDS: u8 = 1 << 1;
    pub const GOVERNANCE: u8 = 1 << 2;
    pub const KERNEL: u8 = 1 << 3;
    pub const MARKET: u8 = 1 << 4;

    pub fn has_curve(self) -> bool {
        self.0 & Self::CURVE != 0
    }
    pub fn has_rewards(self) -> bool {
        self.0 & Self::REWARDS != 0
    }
    pub fn has_governance(self) -> bool {
        self.0 & Self::GOVERNANCE != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurveModuleHeader {
    pub phase: String,
    pub sell_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardsModuleHeader {
    pub spend_delegate_key_id: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceVerifierKind {
    Single,
    Multisig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceModuleHeader {
    pub verifier: GovernanceVerifierKind,
    pub signers: u8,
    pub threshold: u8,
}

/// Unified asset view — consensus record (SA-3+) or legacy projection (SA-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignAsset {
    pub asset_id: [u8; 32],
    pub id_source: AssetIdSource,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub creator_key_id: [u8; 32],
    pub creator_did: Option<String>,
    pub treasury_key_id: Option<[u8; 32]>,
    pub launched_at_height: Option<u64>,
    pub supply_mode: SupplyMode,
    pub max_supply: u128,
    pub total_supply: u128,
    pub manifest_cid: Option<[u8; 32]>,
    pub manifest_hash: Option<[u8; 32]>,
    pub schema_version: u16,
    pub authority: AssetAuthority,
    pub module_flags: AssetModuleFlags,
    pub curve: Option<CurveModuleHeader>,
    pub rewards: Option<RewardsModuleHeader>,
    pub governance: Option<GovernanceModuleHeader>,
}

impl SovereignAsset {
    pub fn module_bitmask(&self) -> u8 {
        self.module_flags.0
    }
}