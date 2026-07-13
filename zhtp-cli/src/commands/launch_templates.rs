//! DAO launch tokenomics templates (D4 #2825).
//!
//! Versioned JSON presets shared by CLI and mobile app. Templates are embedded at
//! compile time via `include_str!` so deployed binaries work without a source tree.
//! Split preview uses `AssetLaunchPayloadV1::split_initial_supply` — same path as the executor.

use crate::error::{CliError, CliResult};
use lib_blockchain::contracts::sovereign_asset::{DaoClass, SupplyMode};
use lib_blockchain::transaction::asset_tx::{AssetLaunchPayloadV1, ASSET_LAUNCH_TREASURY_BPS};
use serde::Deserialize;

const TEMPLATE_SCHEMA: &str = "zhtp/dao-launch-template/v1";

/// Single source of truth for built-in template ids (embedded via `include_str!` below).
pub const BUILTIN_TEMPLATE_IDS: &[&str] = &["unicorn", "balanced", "foundation"];

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

pub fn list_template_ids() -> &'static [&'static str] {
    BUILTIN_TEMPLATE_IDS
}

fn template_json_for_id(id: &str) -> Option<&'static str> {
    match id.trim().to_ascii_lowercase().as_str() {
        "unicorn" => Some(include_str!(
            "../../../schemas/zhtp/dao-launch-template/examples/unicorn.json"
        )),
        "balanced" => Some(include_str!(
            "../../../schemas/zhtp/dao-launch-template/examples/balanced.json"
        )),
        "foundation" => Some(include_str!(
            "../../../schemas/zhtp/dao-launch-template/examples/foundation.json"
        )),
        _ => None,
    }
}

pub fn load_template(id: &str) -> CliResult<DaoLaunchTemplate> {
    let normalized = id.trim().to_ascii_lowercase();
    let json = template_json_for_id(&normalized).ok_or_else(|| {
        CliError::ConfigError(format!(
            "unknown template '{id}' (expected: {})",
            BUILTIN_TEMPLATE_IDS.join(" | ")
        ))
    })?;
    let template: DaoLaunchTemplate = serde_json::from_str(json)
        .map_err(|e| CliError::ConfigError(format!("invalid template JSON: {e}")))?;
    validate_template(&template)?;
    Ok(template)
}

pub(crate) fn validate_template(template: &DaoLaunchTemplate) -> CliResult<()> {
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
        .ok_or_else(|| {
            CliError::ConfigError(format!("decimals {decimals} overflow for supply scale"))
        })?;
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
pub fn preview_launch(
    name: &str,
    symbol: &str,
    initial_supply: u128,
    decimals: u8,
    template: Option<&DaoLaunchTemplate>,
) -> CliResult<LaunchSplitPreview> {
    let treasury_bps = template
        .map(|t| t.treasury_bps)
        .unwrap_or(ASSET_LAUNCH_TREASURY_BPS);
    let payload = AssetLaunchPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals,
        initial_supply,
        treasury_key_id: [0x01; 32],
        treasury_bps,
        supply_mode: SupplyMode::Fixed,
        manifest_cid: [0x11; 32],
        manifest_hash: [0x22; 32],
        curve: None,
        rewards: None,
        governance: None,
        transfer_authority: false,
        dao_class: DaoClass::Fp,
        burn_bps: 0,
    };
    payload
        .validate_dao_launch_ui_constraints()
        .map_err(|e| CliError::ConfigError(format!("launch preview validation: {e}")))?;
    let (creator, treasury) = payload.split_initial_supply();
    let creator_percent = if initial_supply == 0 {
        0.0
    } else {
        (creator as f64 / initial_supply as f64) * 100.0
    };
    let treasury_percent = if initial_supply == 0 {
        0.0
    } else {
        (treasury as f64 / initial_supply as f64) * 100.0
    };
    Ok(LaunchSplitPreview {
        template_id: template
            .map(|t| t.id.clone())
            .unwrap_or_else(|| "custom".to_string()),
        template_label: template
            .map(|t| t.label.clone())
            .unwrap_or_else(|| "Custom".to_string()),
        initial_supply_atoms: initial_supply.to_string(),
        treasury_bps,
        creator_allocation_atoms: creator.to_string(),
        treasury_allocation_atoms: treasury.to_string(),
        creator_percent: format!("{creator_percent:.2}"),
        treasury_percent: format!("{treasury_percent:.2}"),
        rewards_policy_example: template.and_then(|t| t.rewards_policy_example.clone()),
    })
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
    fn load_template_rejects_unknown_id() {
        let err = load_template("../../../../etc/hosts").unwrap_err();
        assert!(err.to_string().contains("unknown template"));
        assert!(err.to_string().contains("unicorn"));
    }

    #[test]
    fn validate_template_rejects_bad_schema() {
        let template = DaoLaunchTemplate {
            schema: "other/v1".to_string(),
            id: "x".to_string(),
            label: "X".to_string(),
            description: "x".to_string(),
            whole_supply: 1,
            decimals: 18,
            supply_mode: "fixed".to_string(),
            treasury_bps: ASSET_LAUNCH_TREASURY_BPS,
            rewards_policy_example: None,
        };
        assert!(validate_template(&template).is_err());
    }

    #[test]
    fn validate_template_rejects_noncanonical_treasury_bps() {
        let template = DaoLaunchTemplate {
            schema: TEMPLATE_SCHEMA.to_string(),
            id: "x".to_string(),
            label: "X".to_string(),
            description: "x".to_string(),
            whole_supply: 1,
            decimals: 18,
            supply_mode: "fixed".to_string(),
            treasury_bps: 1000,
            rewards_policy_example: None,
        };
        assert!(validate_template(&template).is_err());
    }

    #[test]
    fn preview_split_matches_eighty_twenty() {
        let template = load_template("balanced").unwrap();
        let atoms = whole_tokens_to_atoms(template.whole_supply, template.decimals).unwrap();
        let preview = preview_launch("Bubble", "BUBL", atoms, template.decimals, Some(&template))
            .unwrap();
        let supply: u128 = preview.initial_supply_atoms.parse().unwrap();
        let creator: u128 = preview.creator_allocation_atoms.parse().unwrap();
        let treasury: u128 = preview.treasury_allocation_atoms.parse().unwrap();
        assert_eq!(creator + treasury, supply);
        assert_eq!(treasury, supply / 5);
        assert_eq!(creator, supply - supply / 5);
    }

    #[test]
    fn preview_validates_real_symbol_not_placeholder() {
        let template = load_template("balanced").unwrap();
        let atoms = whole_tokens_to_atoms(template.whole_supply, template.decimals).unwrap();
        let long_symbol = "A".repeat(32);
        assert!(preview_launch("Bubble", &long_symbol, atoms, template.decimals, Some(&template)).is_err());
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

    #[test]
    fn resolve_launch_params_honors_supply_and_decimals_overrides() {
        let (_, resolved) = resolve_launch_params(Some("unicorn"), Some(999), Some(6))
            .unwrap()
            .unwrap();
        assert_eq!(resolved.supply_atoms, 999);
        assert_eq!(resolved.decimals, 6);
    }
}