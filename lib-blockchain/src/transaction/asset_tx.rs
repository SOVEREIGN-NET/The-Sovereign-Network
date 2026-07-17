//! Sovereign Asset transaction payloads (SA-3..SA-7).

use bincode::Options;
use serde::{Deserialize, Serialize};

use crate::contracts::approval_verifier::ApprovalProof;
use crate::contracts::sovereign_asset::{
    default_governance_threshold, validate_governance_verifier, CurveModuleState, CurvePhase,
    DaoClass, GovernanceVerifierState, MAX_TRANSFER_BURN_BPS, SupplyMode, FP_TREASURY_BPS,
    NP_TREASURY_BPS,
};

pub const ASSET_LAUNCH_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_LAUNCH_V1:";
pub const ASSET_LAUNCH_MEMO_PREFIX_V2: &[u8] = b"ZHTP_ASSET_LAUNCH_V2:";
pub const ASSET_MODULE_UPGRADE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_UPGRADE_V1:";
pub const ASSET_MANIFEST_UPDATE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_MANIFEST_V1:";
pub const ASSET_AUTHORITY_TRANSFER_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_AUTH_XFER_V1:";
pub const ASSET_AUTHORITY_TRANSFER_CANCEL_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_AUTH_XFER_CANCEL_V1:";
pub const ASSET_REWARDS_DELEGATE_ROTATE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_REWARDS_ROT_V1:";
pub const ASSET_REWARDS_POLICY_UPDATE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_REWARDS_POL_V1:";
pub const ASSET_BURN_BPS_UPDATE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_BURN_BPS_V1:";

pub const MAX_ASSET_MEMO_BYTES: usize = 8192;
pub const MAX_ASSET_NAME_BYTES: usize = 64;
pub const MAX_ASSET_SYMBOL_BYTES: usize = 10;
pub const ASSET_LAUNCH_TREASURY_BPS: u16 = 2_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurveLaunchConfig {
    pub threshold: u128,
    pub sell_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardsLaunchConfig {
    pub spend_delegate_key_id: [u8; 32],
    pub policy_cid: [u8; 32],
    pub policy_hash: [u8; 32],
    /// Canonical JSON policy document (DHT pin source). Stored on-chain keyed by `policy_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_document: Option<Vec<u8>>,
}

impl RewardsLaunchConfig {
    pub fn validate(&self) -> Result<(), String> {
        use crate::rewards_policy::{policy_hash, validate_rewards_policy};
        if self.spend_delegate_key_id == [0u8; 32] {
            return Err("rewards spend_delegate_key_id must be non-zero".to_string());
        }
        if self.policy_cid == [0u8; 32] {
            return Err("rewards policy_cid must be non-zero".to_string());
        }
        if self.policy_hash == [0u8; 32] {
            return Err("rewards policy_hash must be non-zero".to_string());
        }
        let doc = self
            .policy_document
            .as_ref()
            .ok_or_else(|| "rewards policy_document is required".to_string())?;
        let policy = validate_rewards_policy(doc)
            .map_err(|e| format!("invalid rewards policy_document: {e}"))?;
        let hash = policy_hash(&policy).map_err(|e| format!("policy hash failed: {e}"))?;
        if hash.as_array() != self.policy_hash {
            return Err("policy_document does not match policy_hash".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceLaunchConfig {
    pub verifier: GovernanceVerifierState,
    #[serde(default)]
    pub threshold: Option<u8>,
}

impl GovernanceLaunchConfig {
    pub fn resolved_verifier(&self) -> GovernanceVerifierState {
        match &self.verifier {
            GovernanceVerifierState::Single { .. } => self.verifier.clone(),
            GovernanceVerifierState::Multisig { signers, threshold } => {
                let t = self
                    .threshold
                    .unwrap_or_else(|| default_governance_threshold(signers.len()));
                let resolved = if *threshold == 0 { t } else { *threshold };
                GovernanceVerifierState::Multisig {
                    signers: signers.clone(),
                    threshold: resolved,
                }
            }
        }
    }
}

/// Legacy V1 wire layout — kept verbatim for historical chain replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AssetLaunchPayloadV1Wire {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub initial_supply: u128,
    pub treasury_key_id: [u8; 32],
    #[serde(default = "default_asset_launch_treasury_bps")]
    pub treasury_bps: u16,
    pub supply_mode: SupplyMode,
    pub manifest_cid: [u8; 32],
    pub manifest_hash: [u8; 32],
    #[serde(default)]
    pub curve: Option<CurveLaunchConfig>,
    #[serde(default)]
    pub rewards: Option<RewardsLaunchConfig>,
    #[serde(default)]
    pub governance: Option<GovernanceLaunchConfig>,
    #[serde(default)]
    pub transfer_authority: bool,
}

/// V2 wire layout — V1 fields + economic class and burn (epic Q1/Q7/Q8).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AssetLaunchPayloadV2Wire {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub initial_supply: u128,
    pub treasury_key_id: [u8; 32],
    #[serde(default = "default_asset_launch_treasury_bps")]
    pub treasury_bps: u16,
    pub supply_mode: SupplyMode,
    pub manifest_cid: [u8; 32],
    pub manifest_hash: [u8; 32],
    #[serde(default)]
    pub curve: Option<CurveLaunchConfig>,
    #[serde(default)]
    pub rewards: Option<RewardsLaunchConfig>,
    #[serde(default)]
    pub governance: Option<GovernanceLaunchConfig>,
    #[serde(default)]
    pub transfer_authority: bool,
    pub dao_class: DaoClass,
    pub burn_bps: u16,
}

/// Canonical launch payload (executor + API). New txes emit V2 wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetLaunchPayloadV1 {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub initial_supply: u128,
    pub treasury_key_id: [u8; 32],
    #[serde(default = "default_asset_launch_treasury_bps")]
    pub treasury_bps: u16,
    pub supply_mode: SupplyMode,
    pub manifest_cid: [u8; 32],
    pub manifest_hash: [u8; 32],
    #[serde(default)]
    pub curve: Option<CurveLaunchConfig>,
    #[serde(default)]
    pub rewards: Option<RewardsLaunchConfig>,
    #[serde(default)]
    pub governance: Option<GovernanceLaunchConfig>,
    #[serde(default)]
    pub transfer_authority: bool,
    pub dao_class: DaoClass,
    pub burn_bps: u16,
}

fn wire_v1_to_payload(v1: AssetLaunchPayloadV1Wire) -> AssetLaunchPayloadV1 {
    AssetLaunchPayloadV1 {
        name: v1.name,
        symbol: v1.symbol,
        decimals: v1.decimals,
        initial_supply: v1.initial_supply,
        treasury_key_id: v1.treasury_key_id,
        treasury_bps: v1.treasury_bps,
        supply_mode: v1.supply_mode,
        manifest_cid: v1.manifest_cid,
        manifest_hash: v1.manifest_hash,
        curve: v1.curve,
        rewards: v1.rewards,
        governance: v1.governance,
        transfer_authority: v1.transfer_authority,
        dao_class: DaoClass::Fp,
        burn_bps: 0,
    }
}

fn payload_to_wire_v2(payload: &AssetLaunchPayloadV1) -> AssetLaunchPayloadV2Wire {
    AssetLaunchPayloadV2Wire {
        name: payload.name.clone(),
        symbol: payload.symbol.clone(),
        decimals: payload.decimals,
        initial_supply: payload.initial_supply,
        treasury_key_id: payload.treasury_key_id,
        treasury_bps: payload.treasury_bps,
        supply_mode: payload.supply_mode,
        manifest_cid: payload.manifest_cid,
        manifest_hash: payload.manifest_hash,
        curve: payload.curve.clone(),
        rewards: payload.rewards.clone(),
        governance: payload.governance.clone(),
        transfer_authority: payload.transfer_authority,
        dao_class: payload.dao_class,
        burn_bps: payload.burn_bps,
    }
}

fn wire_v2_to_payload(v2: AssetLaunchPayloadV2Wire) -> AssetLaunchPayloadV1 {
    AssetLaunchPayloadV1 {
        name: v2.name,
        symbol: v2.symbol,
        decimals: v2.decimals,
        initial_supply: v2.initial_supply,
        treasury_key_id: v2.treasury_key_id,
        treasury_bps: v2.treasury_bps,
        supply_mode: v2.supply_mode,
        manifest_cid: v2.manifest_cid,
        manifest_hash: v2.manifest_hash,
        curve: v2.curve,
        rewards: v2.rewards,
        governance: v2.governance,
        transfer_authority: v2.transfer_authority,
        dao_class: v2.dao_class,
        burn_bps: v2.burn_bps,
    }
}

fn default_asset_launch_treasury_bps() -> u16 {
    ASSET_LAUNCH_TREASURY_BPS
}

impl AssetLaunchPayloadV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() || self.name.len() > MAX_ASSET_NAME_BYTES {
            return Err("invalid asset name".to_string());
        }
        if self.symbol.trim().is_empty() || self.symbol.len() > MAX_ASSET_SYMBOL_BYTES {
            return Err("invalid asset symbol".to_string());
        }
        if self.initial_supply == 0 {
            return Err("initial_supply must be > 0".to_string());
        }
        let expected_bps = self.dao_class.treasury_bps();
        if self.treasury_bps != expected_bps {
            return Err(format!(
                "treasury_bps must be {} for dao_class {}",
                expected_bps,
                self.dao_class.as_str()
            ));
        }
        if self.burn_bps > MAX_TRANSFER_BURN_BPS {
            return Err(format!(
                "burn_bps must be <= {}",
                MAX_TRANSFER_BURN_BPS
            ));
        }
        if self.treasury_key_id == [0u8; 32] {
            return Err("treasury_key_id must be non-zero".to_string());
        }
        if self.manifest_cid == [0u8; 32] || self.manifest_hash == [0u8; 32] {
            return Err("manifest_cid and manifest_hash are required".to_string());
        }
        if self.supply_mode == SupplyMode::Elastic && self.curve.is_none() {
            return Err("elastic supply_mode requires curve module at launch".to_string());
        }
        if let Some(rewards) = &self.rewards {
            rewards.validate()?;
        }
        if let Some(gov) = &self.governance {
            validate_governance_verifier(&gov.resolved_verifier())?;
        }
        if self.transfer_authority && self.governance.is_none() {
            return Err("transfer_authority requires governance module".to_string());
        }
        Ok(())
    }

    /// Stricter SovSwap-aligned constraints for the DAO launch user path (M2/M1).
    pub fn validate_dao_launch_ui_constraints(&self) -> Result<(), String> {
        use super::token_creation::{
            DAO_LAUNCH_MAX_SYMBOL_CHARS, DAO_LAUNCH_MIN_WHOLE_SUPPLY,
        };
        self.validate()?;
        if self.symbol.len() > DAO_LAUNCH_MAX_SYMBOL_CHARS {
            return Err(format!(
                "symbol length {} exceeds DAO launch max {}",
                self.symbol.len(),
                DAO_LAUNCH_MAX_SYMBOL_CHARS
            ));
        }
        if !self
            .symbol
            .chars()
            .all(|c| c.is_ascii_uppercase() && c.is_ascii_alphabetic())
        {
            return Err("symbol must be uppercase A-Z".to_string());
        }
        let scale = 10u128
            .checked_pow(self.decimals as u32)
            .ok_or_else(|| format!("decimals {} overflow for supply scale", self.decimals))?;
        let min_atoms = DAO_LAUNCH_MIN_WHOLE_SUPPLY
            .checked_mul(scale)
            .ok_or_else(|| "minimum supply atoms overflow".to_string())?;
        if self.initial_supply < min_atoms {
            return Err(format!(
                "initial_supply must be at least {} whole tokens ({} atoms at {} decimals)",
                DAO_LAUNCH_MIN_WHOLE_SUPPLY, min_atoms, self.decimals
            ));
        }
        Ok(())
    }

    pub fn split_initial_supply(&self) -> (u128, u128) {
        crate::execution::mint_and_allocate::split_mint_amount(self.initial_supply, self.dao_class)
    }

    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let wire = payload_to_wire_v2(self);
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(&wire)
            .map_err(|e| format!("serialize asset launch: {e}"))?;
        let mut memo = ASSET_LAUNCH_MEMO_PREFIX_V2.to_vec();
        memo.extend_from_slice(&encoded);
        if memo.len() > MAX_ASSET_MEMO_BYTES {
            return Err("asset launch memo too large".to_string());
        }
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        let payload = if let Some(v2_bytes) = memo.strip_prefix(ASSET_LAUNCH_MEMO_PREFIX_V2) {
            let v2: AssetLaunchPayloadV2Wire = bincode::DefaultOptions::new()
                .with_limit(MAX_ASSET_MEMO_BYTES as u64)
                .deserialize(v2_bytes)
                .map_err(|e| format!("invalid asset launch V2 payload: {e}"))?;
            wire_v2_to_payload(v2)
        } else if let Some(v1_bytes) = memo.strip_prefix(ASSET_LAUNCH_MEMO_PREFIX) {
            let v1: AssetLaunchPayloadV1Wire = bincode::DefaultOptions::new()
                .with_limit(MAX_ASSET_MEMO_BYTES as u64)
                .deserialize(v1_bytes)
                .map_err(|e| format!("invalid asset launch V1 payload: {e}"))?;
            wire_v1_to_payload(v1)
        } else {
            return Err("missing asset launch memo prefix (V1 or V2)".to_string());
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn initial_curve_state(&self) -> Option<CurveModuleState> {
        self.curve.as_ref().map(|c| CurveModuleState {
            phase: CurvePhase::Curve,
            reserve_balance: 0,
            treasury_balance: 0,
            threshold: c.threshold,
            sell_enabled: c.sell_enabled,
            amm_pool_id: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetUpgradeModule {
    Curve(CurveLaunchConfig),
    Rewards(RewardsLaunchConfig),
    Governance(GovernanceLaunchConfig),
    /// One-time bind for legacy assets launched without `treasury_key_id` (#2864).
    TreasuryBind { treasury_key_id: [u8; 32] },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetModuleUpgradePayloadV1 {
    pub asset_id: [u8; 32],
    pub module: AssetUpgradeModule,
    #[serde(default)]
    pub transfer_authority: bool,
}

impl AssetModuleUpgradePayloadV1 {
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("serialize asset upgrade: {e}"))?;
        let mut memo = ASSET_MODULE_UPGRADE_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(ASSET_MODULE_UPGRADE_MEMO_PREFIX) {
            return Err("missing asset upgrade memo prefix".to_string());
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .deserialize(&memo[ASSET_MODULE_UPGRADE_MEMO_PREFIX.len()..])
            .map_err(|e| format!("invalid asset upgrade payload: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetAuthorityProof {
    CreatorSig,
    Governance(ApprovalProof),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetManifestUpdatePayloadV1 {
    pub asset_id: [u8; 32],
    pub manifest_cid: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub authority_proof: AssetAuthorityProof,
}

impl AssetManifestUpdatePayloadV1 {
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("serialize manifest update: {e}"))?;
        let mut memo = ASSET_MANIFEST_UPDATE_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(ASSET_MANIFEST_UPDATE_MEMO_PREFIX) {
            return Err("missing manifest update memo prefix".to_string());
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .deserialize(&memo[ASSET_MANIFEST_UPDATE_MEMO_PREFIX.len()..])
            .map_err(|e| format!("invalid manifest update payload: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetAuthorityTransferPayloadV1 {
    pub asset_id: [u8; 32],
    pub new_verifier: GovernanceVerifierState,
    pub effective_height: Option<u64>,
    pub authority_proof: AssetAuthorityProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetAuthorityTransferCancelPayloadV1 {
    pub asset_id: [u8; 32],
}

impl AssetAuthorityTransferCancelPayloadV1 {
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("serialize authority transfer cancel: {e}"))?;
        let mut memo = ASSET_AUTHORITY_TRANSFER_CANCEL_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(ASSET_AUTHORITY_TRANSFER_CANCEL_MEMO_PREFIX) {
            return Err("missing authority transfer cancel memo prefix".to_string());
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .deserialize(&memo[ASSET_AUTHORITY_TRANSFER_CANCEL_MEMO_PREFIX.len()..])
            .map_err(|e| format!("invalid authority transfer cancel payload: {e}"))
    }
}

impl AssetAuthorityTransferPayloadV1 {
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("serialize authority transfer: {e}"))?;
        let mut memo = ASSET_AUTHORITY_TRANSFER_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(ASSET_AUTHORITY_TRANSFER_MEMO_PREFIX) {
            return Err("missing authority transfer memo prefix".to_string());
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .deserialize(&memo[ASSET_AUTHORITY_TRANSFER_MEMO_PREFIX.len()..])
            .map_err(|e| format!("invalid authority transfer payload: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetRewardsDelegateRotatePayloadV1 {
    pub asset_id: [u8; 32],
    pub new_delegate_key_id: [u8; 32],
    pub authority_proof: AssetAuthorityProof,
}

impl AssetRewardsDelegateRotatePayloadV1 {
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("serialize rewards delegate rotate: {e}"))?;
        let mut memo = ASSET_REWARDS_DELEGATE_ROTATE_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(ASSET_REWARDS_DELEGATE_ROTATE_MEMO_PREFIX) {
            return Err("missing rewards delegate rotate memo prefix".to_string());
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .deserialize(&memo[ASSET_REWARDS_DELEGATE_ROTATE_MEMO_PREFIX.len()..])
            .map_err(|e| format!("invalid rewards delegate rotate payload: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardsPolicyUpdateConfig {
    pub policy_cid: [u8; 32],
    pub policy_hash: [u8; 32],
    /// Canonical JSON policy document (DHT pin source). Stored on-chain keyed by `policy_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_document: Option<Vec<u8>>,
}

impl RewardsPolicyUpdateConfig {
    pub fn validate(&self) -> Result<(), String> {
        use crate::rewards_policy::{policy_hash, validate_rewards_policy};
        if self.policy_cid == [0u8; 32] {
            return Err("rewards policy_cid must be non-zero".to_string());
        }
        if self.policy_hash == [0u8; 32] {
            return Err("rewards policy_hash must be non-zero".to_string());
        }
        let doc = self
            .policy_document
            .as_ref()
            .ok_or_else(|| "rewards policy_document is required".to_string())?;
        let policy = validate_rewards_policy(doc)
            .map_err(|e| format!("invalid rewards policy_document: {e}"))?;
        let hash = policy_hash(&policy).map_err(|e| format!("policy hash failed: {e}"))?;
        if hash.as_array() != self.policy_hash {
            return Err("policy_document does not match policy_hash".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetRewardsPolicyUpdatePayloadV1 {
    pub asset_id: [u8; 32],
    pub policy: RewardsPolicyUpdateConfig,
    pub authority_proof: AssetAuthorityProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetBurnBpsUpdatePayloadV1 {
    pub asset_id: [u8; 32],
    pub new_burn_bps: u16,
    pub authority_proof: AssetAuthorityProof,
}

impl AssetBurnBpsUpdatePayloadV1 {
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        if self.new_burn_bps > MAX_TRANSFER_BURN_BPS {
            return Err(format!(
                "new_burn_bps must be <= {}",
                MAX_TRANSFER_BURN_BPS
            ));
        }
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("serialize burn bps update: {e}"))?;
        let mut memo = ASSET_BURN_BPS_UPDATE_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(ASSET_BURN_BPS_UPDATE_MEMO_PREFIX) {
            return Err("missing burn bps update memo prefix".to_string());
        }
        let payload: Self = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .deserialize(&memo[ASSET_BURN_BPS_UPDATE_MEMO_PREFIX.len()..])
            .map_err(|e| format!("invalid burn bps update payload: {e}"))?;
        if payload.new_burn_bps > MAX_TRANSFER_BURN_BPS {
            return Err(format!(
                "new_burn_bps must be <= {}",
                MAX_TRANSFER_BURN_BPS
            ));
        }
        Ok(payload)
    }
}

impl AssetRewardsPolicyUpdatePayloadV1 {
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        self.policy.validate()?;
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("serialize rewards policy update: {e}"))?;
        let mut memo = ASSET_REWARDS_POLICY_UPDATE_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(ASSET_REWARDS_POLICY_UPDATE_MEMO_PREFIX) {
            return Err("missing rewards policy update memo prefix".to_string());
        }
        let payload: Self = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .deserialize(&memo[ASSET_REWARDS_POLICY_UPDATE_MEMO_PREFIX.len()..])
            .map_err(|e| format!("invalid rewards policy update payload: {e}"))?;
        payload.policy.validate()?;
        Ok(payload)
    }
}

pub const ASSET_MANIFEST_SCHEMA: &str = "zhtp/asset-manifest/v1";

/// Build canonical DAO launch manifest JSON bytes (default manifest for CLI/SDK).
pub fn build_dao_launch_manifest_bytes(name: &str, symbol: &str, decimals: u8) -> Vec<u8> {
    let manifest = serde_json::json!({
        "schema": ASSET_MANIFEST_SCHEMA,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "interface": {
            "version": "1.0.0",
            "tx_kinds": ["TokenTransfer", "AssetTransfer", "RewardsClaim"]
        }
    });
    serde_json::to_vec(&manifest).expect("manifest json")
}

fn validate_manifest_launch_fields(
    value: &serde_json::Value,
    name: &str,
    symbol: &str,
    decimals: u8,
) -> Result<(), String> {
    if let Some(v) = value.get("name").and_then(|v| v.as_str()) {
        if v != name {
            return Err(format!("manifest name '{v}' does not match '{name}'"));
        }
    }
    if let Some(v) = value.get("symbol").and_then(|v| v.as_str()) {
        if v != symbol {
            return Err(format!("manifest symbol '{v}' does not match '{symbol}'"));
        }
    }
    if let Some(v) = value.get("decimals").and_then(|v| v.as_u64()) {
        if v != decimals as u64 {
            return Err(format!("manifest decimals {v} does not match {decimals}"));
        }
    }
    Ok(())
}

/// Derive `(manifest_cid, manifest_hash)` from manifest bytes.
///
/// When `launch` is `Some((name, symbol, decimals))`, cross-checks manifest fields.
pub fn manifest_cid_hash_from_bytes(
    bytes: &[u8],
    launch: Option<(&str, &str, u8)>,
) -> Result<([u8; 32], [u8; 32]), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid manifest JSON: {e}"))?;
    let schema = value
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if schema != ASSET_MANIFEST_SCHEMA {
        return Err(format!(
            "manifest schema must be {ASSET_MANIFEST_SCHEMA}, got '{schema}'"
        ));
    }
    if let Some((name, symbol, decimals)) = launch {
        validate_manifest_launch_fields(&value, name, symbol, decimals)?;
    }
    let hash = lib_crypto::hash_blake3(bytes);
    let mut cid = [0u8; 32];
    cid[..16].copy_from_slice(&hash[..16]);
    Ok((cid, hash))
}

/// Build default manifest cid/hash for a DAO launch (no custom manifest file).
pub fn build_dao_launch_manifest(
    name: &str,
    symbol: &str,
    decimals: u8,
) -> Result<([u8; 32], [u8; 32]), String> {
    let bytes = build_dao_launch_manifest_bytes(name, symbol, decimals);
    manifest_cid_hash_from_bytes(&bytes, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_launch() -> AssetLaunchPayloadV1 {
        AssetLaunchPayloadV1 {
            name: "Bubble".to_string(),
            symbol: "BUBL".to_string(),
            decimals: 18,
            initial_supply: 1_000 * 10u128.pow(18),
            treasury_key_id: [0xAA; 32],
            treasury_bps: ASSET_LAUNCH_TREASURY_BPS,
            supply_mode: SupplyMode::Fixed,
            manifest_cid: [0x11; 32],
            manifest_hash: [0x22; 32],
            curve: None,
            rewards: None,
            governance: None,
            transfer_authority: false,
            dao_class: DaoClass::Fp,
            burn_bps: 0,
        }
    }

    #[test]
    fn np_launch_split_is_all_treasury() {
        let mut np = sample_launch();
        np.dao_class = DaoClass::Np;
        np.treasury_bps = NP_TREASURY_BPS;
        let (creator, treasury) = np.split_initial_supply();
        assert_eq!(creator, 0);
        assert_eq!(treasury, np.initial_supply);
    }

    #[test]
    fn fp_launch_rejects_wrong_treasury_bps() {
        let mut bad = sample_launch();
        bad.dao_class = DaoClass::Np;
        bad.treasury_bps = FP_TREASURY_BPS;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn asset_launch_dao_ui_constraints_match_m2_rules() {
        assert!(sample_launch().validate_dao_launch_ui_constraints().is_ok());
        let mut long = sample_launch();
        long.symbol = "TOOLONG".to_string();
        assert!(long.validate_dao_launch_ui_constraints().is_err());
    }

    #[test]
    fn legacy_v1_launch_memo_decodes_with_fp_defaults() {
        let v1 = AssetLaunchPayloadV1Wire {
            name: "Legacy".to_string(),
            symbol: "LEG".to_string(),
            decimals: 8,
            initial_supply: 1_000,
            treasury_key_id: [0xAA; 32],
            treasury_bps: ASSET_LAUNCH_TREASURY_BPS,
            supply_mode: SupplyMode::Fixed,
            manifest_cid: [0x11; 32],
            manifest_hash: [0x22; 32],
            curve: None,
            rewards: None,
            governance: None,
            transfer_authority: false,
        };
        let encoded = bincode::DefaultOptions::new()
            .serialize(&v1)
            .expect("legacy wire serialize");
        let mut memo = ASSET_LAUNCH_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        let decoded = AssetLaunchPayloadV1::decode_memo(&memo).expect("legacy decode");
        assert_eq!(decoded.dao_class, DaoClass::Fp);
        assert_eq!(decoded.burn_bps, 0);
        assert_eq!(decoded.name, "Legacy");
    }

    #[test]
    fn v2_launch_memo_round_trip() {
        let payload = sample_launch();
        let memo = payload.encode_memo().expect("encode");
        assert!(memo.starts_with(ASSET_LAUNCH_MEMO_PREFIX_V2));
        let decoded = AssetLaunchPayloadV1::decode_memo(&memo).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn manifest_cid_hash_from_bytes_valid_schema() {
        let manifest = serde_json::json!({
            "schema": ASSET_MANIFEST_SCHEMA,
            "name": "Test",
            "symbol": "TST",
            "decimals": 18
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let (cid, hash) = manifest_cid_hash_from_bytes(&bytes, None).unwrap();
        assert_eq!(cid[..16], hash[..16]);
        assert_eq!(hash, lib_crypto::hash_blake3(&bytes));
    }

    #[test]
    fn manifest_cid_hash_from_bytes_rejects_wrong_schema() {
        let manifest = serde_json::json!({"schema": "other/v1"});
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(manifest_cid_hash_from_bytes(&bytes, None).is_err());
    }

    #[test]
    fn manifest_cross_validation_rejects_mismatch() {
        let manifest = serde_json::json!({
            "schema": ASSET_MANIFEST_SCHEMA,
            "name": "Other",
            "symbol": "TST",
            "decimals": 18
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(manifest_cid_hash_from_bytes(&bytes, Some(("Test", "TST", 18))).is_err());
    }

    #[test]
    fn build_dao_launch_manifest_matches_schema() {
        let (cid, hash) = build_dao_launch_manifest("Bubble", "BUBL", 18).unwrap();
        assert_ne!(cid, [0u8; 32]);
        assert_ne!(hash, [0u8; 32]);
        let bytes = build_dao_launch_manifest_bytes("Bubble", "BUBL", 18);
        assert_eq!(hash, lib_crypto::hash_blake3(&bytes));
    }

    #[test]
    fn treasury_bind_upgrade_memo_round_trip() {
        let payload = AssetModuleUpgradePayloadV1 {
            asset_id: [0xAB; 32],
            module: AssetUpgradeModule::TreasuryBind {
                treasury_key_id: [0xCC; 32],
            },
            transfer_authority: false,
        };
        let memo = payload.encode_memo().expect("encode");
        let decoded = AssetModuleUpgradePayloadV1::decode_memo(&memo).expect("decode");
        assert_eq!(decoded, payload);
    }
}