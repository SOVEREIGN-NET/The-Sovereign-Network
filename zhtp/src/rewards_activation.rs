//! Chain-native rewards handler activation (DAO N3 / SA-4, #2813).
//!
//! Operators bind a spend-delegate keystore to an on-chain asset via
//! `rewards_activation.toml` under the node data dir (written by
//! `zhtp-cli node configure-rewards`). The rewards handler does not activate
//! without this file — env-var ticker/keystore hacks are removed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use lib_blockchain::Blockchain;
use lib_blockchain::contracts::sovereign_asset::RewardsModuleState;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub const ACTIVATION_FILENAME: &str = "rewards_activation.toml";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardsActivationFile {
    /// Sovereign asset / token id (32-byte hex).
    pub asset_id: String,
    /// Directory containing `user_identity.json` + `user_private_key.json` for the spend delegate.
    pub delegate_keystore_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedActivation {
    pub asset_id: [u8; 32],
    pub delegate_keystore_dir: PathBuf,
    pub source: ActivationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationSource {
    ConfigFile,
}

pub fn activation_config_path() -> PathBuf {
    crate::node_data_path(ACTIVATION_FILENAME)
}

pub fn write_activation_config(asset_id: &[u8; 32], delegate_keystore_dir: &Path) -> std::io::Result<()> {
    let file = RewardsActivationFile {
        asset_id: hex::encode(asset_id),
        delegate_keystore_dir: delegate_keystore_dir.display().to_string(),
    };
    let path = activation_config_path();
    let body = toml::to_string_pretty(&file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, body)
}

pub fn read_activation_file() -> Option<RewardsActivationFile> {
    let path = activation_config_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!("rewards: failed to read {}: {e}", path.display());
            return None;
        }
    };
    match toml::from_str(&raw) {
        Ok(file) => Some(file),
        Err(e) => {
            warn!("rewards: failed to parse {}: {e}", path.display());
            None
        }
    }
}

/// Asset id from `rewards_activation.toml` when present (no keystore validation).
pub fn configured_asset_id_from_file() -> Option<[u8; 32]> {
    let file = read_activation_file()?;
    parse_asset_id_hex(&file.asset_id).ok()
}

pub fn resolve_activation() -> Option<ResolvedActivation> {
    let file = read_activation_file()?;
    let asset_id = match parse_asset_id_hex(&file.asset_id) {
        Ok(id) => id,
        Err(e) => {
            warn!("rewards_activation.toml has invalid asset_id: {e}");
            return None;
        }
    };
    let dir = PathBuf::from(&file.delegate_keystore_dir);
    if !dir.is_dir() {
        warn!(
            "rewards_activation.toml delegate_keystore_dir '{}' is not a directory — ignoring",
            file.delegate_keystore_dir
        );
        return None;
    }
    Some(ResolvedActivation {
        asset_id,
        delegate_keystore_dir: dir,
        source: ActivationSource::ConfigFile,
    })
}

fn eligible_asset_entry(
    blockchain: &Blockchain,
    asset_id: [u8; 32],
    state: &RewardsModuleState,
) -> Option<ChainEligibleAsset> {
    let balance = match blockchain.token_balance(&asset_id, &state.spend_delegate_key_id) {
        Ok(balance) => balance,
        Err(e) => {
            warn!(
                "rewards: token_balance lookup failed for asset {} delegate {}: {e}",
                hex::encode(&asset_id[..8]),
                hex::encode(&state.spend_delegate_key_id[..8]),
            );
            return None;
        }
    };
    if balance == 0 {
        return None;
    }
    Some(ChainEligibleAsset {
        asset_id,
        spend_delegate_key_id: state.spend_delegate_key_id,
        delegate_balance: balance,
        policy_hash: state.policy_hash,
    })
}

/// Assets with on-chain rewards module and a funded spend delegate (no keystore required).
///
/// Primary scan: `asset_rewards/` sled rows (pure `AssetLaunch` path).
/// Legacy fallback: `token_contracts` entries that also carry rewards module state (BUBL
/// `TokenCreation` migration).
pub fn scan_chain_eligible_assets(blockchain: &Blockchain) -> Vec<ChainEligibleAsset> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for asset_id in blockchain.list_rewards_module_asset_ids() {
        seen.insert(asset_id);
        let Some(state) = blockchain.get_rewards_module_state(&asset_id) else {
            continue;
        };
        if let Some(entry) = eligible_asset_entry(blockchain, asset_id, &state) {
            out.push(entry);
        }
    }

    for (asset_id, _) in blockchain.iter_token_contract_entries() {
        if seen.contains(&asset_id) {
            continue;
        }
        let Some(state) = blockchain.get_rewards_module_state(&asset_id) else {
            continue;
        };
        if let Some(entry) = eligible_asset_entry(blockchain, asset_id, &state) {
            out.push(entry);
        }
    }

    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEligibleAsset {
    pub asset_id: [u8; 32],
    pub spend_delegate_key_id: [u8; 32],
    pub delegate_balance: u128,
    pub policy_hash: [u8; 32],
}

pub fn validate_activation_against_chain(
    blockchain: &Blockchain,
    asset_id: &[u8; 32],
    signer_key_id: &[u8; 32],
) -> Result<RewardsModuleState, String> {
    let Some(state) = blockchain.get_rewards_module_state(asset_id) else {
        return Err(format!(
            "asset {} has no on-chain RewardsModuleState",
            hex::encode(asset_id)
        ));
    };
    if state.spend_delegate_key_id != *signer_key_id {
        return Err(format!(
            "keystore key_id {} does not match on-chain spend_delegate {}",
            hex::encode(signer_key_id),
            hex::encode(state.spend_delegate_key_id)
        ));
    }
    Ok(state)
}

pub fn parse_asset_id_hex(hex_str: &str) -> Result<[u8; 32], String> {
    let trimmed = hex_str.trim();
    if trimmed.len() != 64 {
        return Err("asset_id must be 64 hex chars (32 bytes)".to_string());
    }
    let bytes = hex::decode(trimmed).map_err(|_| "asset_id is not valid hex".to_string())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_asset_id_roundtrip() {
        let id = [0xab_u8; 32];
        let hex = hex::encode(id);
        assert_eq!(parse_asset_id_hex(&hex).unwrap(), id);
    }

    #[test]
    fn activation_file_roundtrip_toml() {
        let asset_id = [0x42_u8; 32];
        let file = RewardsActivationFile {
            asset_id: hex::encode(asset_id),
            delegate_keystore_dir: "/tmp/delegate".to_string(),
        };
        let raw = toml::to_string(&file).expect("serialize");
        let parsed: RewardsActivationFile = toml::from_str(&raw).expect("parse");
        assert_eq!(parse_asset_id_hex(&parsed.asset_id).unwrap(), asset_id);
    }
}