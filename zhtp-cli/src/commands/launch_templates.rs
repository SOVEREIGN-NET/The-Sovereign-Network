//! DAO launch tokenomics templates (D4 #2825).
//!
//! Versioned JSON presets shared by CLI and mobile app. Split preview uses the
//! same `AssetLaunchPayloadV1::split_initial_supply` path as the executor.

use crate::error::{CliError, CliResult};
use lib_blockchain::transaction::asset_tx::{AssetLaunchPayloadV1, ASSET_LAUNCH_TREASURY_BPS};
use lib_blockchain::contracts::sovereign_asset::SupplyMode;
use serde::Deserialize;
use std::path::{Path, PathBuf};

const TEMPLATE_SCHEMA: &str = "zhtp/dao-launch-template/v1";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DaoLaunchTemplate {
    pub schema: String,
    pub id: String,
    pub label: String,
    pub description: String,
    pub whole_supply: u128,
    pub decimals: u8,
    pub supply_mode: String,
    pub treasury_bps: u16,
    #[serde(default)]
    pub rewards_policy_example: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLaunchParams {
    pub supply_atoms: u128,
    pub decimals: u8,
    pub supply_mode: String,
    pub rewards_policy_example: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LaunchSplitPreview {
    pub template_id: String,
    pub template_label: String,
    pub initial_supply_atoms: String,
    pub treasury_bps: u16,
    pub creator_allocation_atoms: String,
    pub treasury_allocation_atoms: String,
    pub creator_percent: String,
    pub treasury_percent: String,
    pub rewards_policy_example: Option<String>,
}

fn templates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../schemas/zhtp/dao-launch-template/examples")
}

pub fn list_template_ids() -> Vec<&'static str> {
    vec!["unicorn", "balanced", "foundation"]
}

pub fn load_template(id: &str) -> CliResult<DaoLaunchTemplate> {
    let normalized = id.trim().to_ascii_lowercase();
    let path = templates_dir().join(format!("{normalized}.json"));
    let bytes = std::fs::read(&path)
        .map_err(|e| CliError::ConfigError(format!("read template {}: {e}", path.display())))?;
    let template: DaoLaunchTemplate = serde_json::from_slice(&bytes)
        .map_err(|e| CliError::ConfigError(format!("invalid template JSON: {e}")))?;
    validate_template(&template)?;
    Ok(template)
}

fn validate_template(template: &DaoLaunchTemplate) -> CliResult<()> {
    if template.schema != TEMPLATE_SCHEMA {
        return Err(CliError::ConfigError(format!(
            "template schema must be {TEMPLATE_SCHEMA}, got '{}'",
            template.schema
        )));
    }
    if template.treasury_bps != ASSET_LAUNCH_TREASURY_BPS {
        return Err(CliError::ConfigError(format!(
            "template treasury_bps must be {ASSET_LAUNCH_TREASURY_BPS} (canonical 80/20)"
        )));
    }
    if template.supply_mode.to_ascii_lowercase() != "fixed" {
        return Err(CliError::ConfigError(
            "templates only support fixed supply_mode".to_string(),
        ));
    }
    if template.whole_supply == 0 {
        return Err(CliError::ConfigError(
            "template whole_supply must be non-zero".to_string(),
        ));
    }
    Ok(())
}

pub fn whole_tokens_to_atoms(whole_supply: u128, decimals: u8) -> CliResult<u128> {
    let scale = 10u128
        .checked_pow(decimals as u32)
        .ok_or_else(|| CliError::ConfigError(format!("decimals {decimals} overflow for supply scale")))?;
    whole_supply
        .checked_mul(scale)
        .ok_or_else(|| CliError::ConfigError("supply atoms overflow".to_string()))
}

pub fn resolve_launch_params(
    template_id: Option<&str>,
    supply_override: Option<u128>,
    decimals_override: Option<u8>,
) -> CliResult<Option<(DaoLaunchTemplate, ResolvedLaunchParams)>> {
    let Some(id) = template_id else {
        return Ok(None);
    };
    let template = load_template(id)?;
    let decimals = decimals_override.unwrap_or(template.decimals);
    let supply_atoms = match supply_override {
        Some(atoms) => atoms,
        None => whole_tokens_to_atoms(template.whole_supply, decimals)?,
    };
    Ok(Some((
        template.clone(),
        ResolvedLaunchParams {
            supply_atoms,
            decimals,
            supply_mode: template.supply_mode.clone(),
            rewards_policy_example: template.rewards_policy_example.clone(),
        },
    )))
}

/// Preview 80/20 split using the executor's `AssetLaunchPayloadV1::split_initial_supply`.
pub fn preview_split(
    template: &DaoLaunchTemplate,
    initial_supply: u128,
    decimals: u8,
) -> CliResult<LaunchSplitPreview> {
    let payload = AssetLaunchPayloadV1 {
        name: "Preview".to_string(),
        symbol: "PREV".to_string(),
        decimals,
        initial_supply,
        treasury_key_id: [0x01; 32],
        treasury_bps: template.treasury_bps,
        supply_mode: SupplyMode::Fixed,
        manifest_cid: [0x11; 32],
        manifest_hash: [0x22; 32],
        curve: None,
        rewards: None,
        governance: None,
        transfer_authority: false,
    };
    payload
        .validate_dao_launch_ui_constraints()
        .map_err(|e| CliError::ConfigError(format!("launch preview validation: {e}")))?;
    let (creator, treasury) = payload.split_initial_supply();
    let bps = template.treasury_bps as u128;
    let creator_pct = 10000u128.saturating_sub(bps);
    Ok(LaunchSplitPreview {
        template_id: template.id.clone(),
        template_label: template.label.clone(),
        initial_supply_atoms: initial_supply.to_string(),
        treasury_bps: template.treasury_bps,
        creator_allocation_atoms: creator.to_string(),
        treasury_allocation_atoms: treasury.to_string(),
        creator_percent: format!("{:.2}", creator_pct as f64 / 100.0),
        treasury_percent: format!("{:.2}", bps as f64 / 100.0),
        rewards_policy_example: template.rewards_policy_example.clone(),
    })
}

pub fn resolve_rewards_policy_example_path(example: &str) -> PathBuf {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    repo_root.join(example)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_all_builtin_templates() {
        for id in list_template_ids() {
            let t = load_template(id).expect("load");
            assert_eq!(t.schema, TEMPLATE_SCHEMA);
            assert_eq!(t.treasury_bps, ASSET_LAUNCH_TREASURY_BPS);
        }
    }

    #[test]
    fn preview_split_matches_eighty_twenty() {
        let template = load_template("balanced").unwrap();
        let atoms = whole_tokens_to_atoms(template.whole_supply, template.decimals).unwrap();
        let preview = preview_split(&template, atoms, template.decimals).unwrap();
        let supply: u128 = preview.initial_supply_atoms.parse().unwrap();
        let creator: u128 = preview.creator_allocation_atoms.parse().unwrap();
        let treasury: u128 = preview.treasury_allocation_atoms.parse().unwrap();
        assert_eq!(creator + treasury, supply);
        assert_eq!(treasury, supply / 5);
        assert_eq!(creator, supply - supply / 5);
    }

    #[test]
    fn resolve_launch_params_uses_template_defaults() {
        let (template, resolved) =
            resolve_launch_params(Some("foundation"), None, None).unwrap().unwrap();
        assert_eq!(template.id, "foundation");
        assert_eq!(resolved.decimals, 18);
        assert_eq!(
            resolved.supply_atoms,
            whole_tokens_to_atoms(10_000_000, 18).unwrap()
        );
    }
}