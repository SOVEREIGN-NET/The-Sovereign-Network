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

/// DAO economic class (epic Q7). Determines treasury split on every supply increase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DaoClass {
    #[default]
    Fp,
    Np,
}

pub const FP_TREASURY_BPS: u16 = 2_000;
pub const NP_TREASURY_BPS: u16 = 10_000;
pub const MAX_TRANSFER_BURN_BPS: u16 = 1_000;

impl DaoClass {
    pub fn treasury_bps(self) -> u16 {
        match self {
            DaoClass::Fp => FP_TREASURY_BPS,
            DaoClass::Np => NP_TREASURY_BPS,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DaoClass::Fp => "fp",
            DaoClass::Np => "np",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "fp" | "for_profit" | "for-profit" => Some(DaoClass::Fp),
            "np" | "non_profit" | "non-profit" => Some(DaoClass::Np),
            _ => None,
        }
    }

    pub fn from_dao_type(t: crate::types::dao::DAOType) -> Self {
        match t {
            crate::types::dao::DAOType::FP => DaoClass::Fp,
            crate::types::dao::DAOType::NP => DaoClass::Np,
        }
    }

    pub fn to_dao_type(self) -> crate::types::dao::DAOType {
        match self {
            DaoClass::Fp => crate::types::dao::DAOType::FP,
            DaoClass::Np => crate::types::dao::DAOType::NP,
        }
    }
}

/// Queued `burn_bps` change (epic Q8 — timelocked increases and decreases).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingBurnBpsUpdate {
    pub new_burn_bps: u16,
    pub effective_height: u64,
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
    /// Economic class (FP 80/20, NP 100% treasury). Appended for bincode compat.
    pub dao_class: DaoClass,
    /// Per-transfer burn rate in basis points (0..=MAX_TRANSFER_BURN_BPS).
    pub burn_bps: u16,
    pub pending_burn_bps: Option<PendingBurnBpsUpdate>,
}

impl SovereignAsset {
    pub fn module_bitmask(&self) -> u8 {
        self.module_flags.0
    }
}