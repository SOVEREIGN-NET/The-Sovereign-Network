//! Sovereign Asset transaction payloads (SA-3..SA-7).

use bincode::Options;
use serde::{Deserialize, Serialize};

use crate::contracts::approval_verifier::ApprovalProof;
use crate::contracts::sovereign_asset::{
    default_governance_threshold, validate_governance_verifier, CurveModuleState, CurvePhase,
    GovernanceVerifierState, SupplyMode,
};

pub const ASSET_LAUNCH_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_LAUNCH_V1:";
pub const ASSET_MODULE_UPGRADE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_UPGRADE_V1:";
pub const ASSET_MANIFEST_UPDATE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_MANIFEST_V1:";
pub const ASSET_AUTHORITY_TRANSFER_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_AUTH_XFER_V1:";
pub const ASSET_REWARDS_DELEGATE_ROTATE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_REWARDS_ROT_V1:";
pub const ASSET_REWARDS_POLICY_UPDATE_MEMO_PREFIX: &[u8] = b"ZHTP_ASSET_REWARDS_POL_V1:";

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
        if self.treasury_bps != ASSET_LAUNCH_TREASURY_BPS {
            return Err(format!("treasury_bps must be {}", ASSET_LAUNCH_TREASURY_BPS));
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
        let bps = self.treasury_bps as u128;
        let treasury = self
            .initial_supply
            .checked_mul(bps)
            .map(|p| p / 10_000u128)
            .unwrap_or(0);
        let creator = self.initial_supply.saturating_sub(treasury);
        (creator, treasury)
    }

    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("serialize asset launch: {e}"))?;
        let mut memo = ASSET_LAUNCH_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        if memo.len() > MAX_ASSET_MEMO_BYTES {
            return Err("asset launch memo too large".to_string());
        }
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(ASSET_LAUNCH_MEMO_PREFIX) {
            return Err("missing asset launch memo prefix".to_string());
        }
        let payload: Self = bincode::DefaultOptions::new()
            .with_limit(MAX_ASSET_MEMO_BYTES as u64)
            .deserialize(&memo[ASSET_LAUNCH_MEMO_PREFIX.len()..])
            .map_err(|e| format!("invalid asset launch payload: {e}"))?;
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
        }
    }

    #[test]
    fn asset_launch_dao_ui_constraints_match_m2_rules() {
        assert!(sample_launch().validate_dao_launch_ui_constraints().is_ok());
        let mut long = sample_launch();
        long.symbol = "TOOLONG".to_string();
        assert!(long.validate_dao_launch_ui_constraints().is_err());
    }
}