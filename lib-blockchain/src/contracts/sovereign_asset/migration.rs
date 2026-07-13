//! Bincode migration shims for `SovereignAsset` sled records.
//!
//! `#[serde(default)]` does not apply to bincode — new fields must be appended
//! at the end of the struct and legacy bytes decoded via an explicit fallback.

use serde::Deserialize;

use super::types::{
    AssetAuthority, AssetIdSource, AssetModuleFlags, CurveModuleHeader, DaoClass,
    GovernanceModuleHeader, RewardsModuleHeader, SovereignAsset, SupplyMode,
};

/// Pre-Q7 sled layout (no `dao_class`, `burn_bps`, or `pending_burn_bps`).
#[derive(serde::Serialize, Deserialize)]
struct LegacySovereignAsset {
    asset_id: [u8; 32],
    id_source: AssetIdSource,
    name: String,
    symbol: String,
    decimals: u8,
    creator_key_id: [u8; 32],
    creator_did: Option<String>,
    treasury_key_id: Option<[u8; 32]>,
    launched_at_height: Option<u64>,
    supply_mode: SupplyMode,
    max_supply: u128,
    total_supply: u128,
    manifest_cid: Option<[u8; 32]>,
    manifest_hash: Option<[u8; 32]>,
    schema_version: u16,
    authority: AssetAuthority,
    module_flags: AssetModuleFlags,
    curve: Option<CurveModuleHeader>,
    rewards: Option<RewardsModuleHeader>,
    governance: Option<GovernanceModuleHeader>,
}

fn from_legacy(legacy: LegacySovereignAsset) -> SovereignAsset {
    SovereignAsset {
        asset_id: legacy.asset_id,
        id_source: legacy.id_source,
        name: legacy.name,
        symbol: legacy.symbol,
        decimals: legacy.decimals,
        creator_key_id: legacy.creator_key_id,
        creator_did: legacy.creator_did,
        treasury_key_id: legacy.treasury_key_id,
        launched_at_height: legacy.launched_at_height,
        supply_mode: legacy.supply_mode,
        max_supply: legacy.max_supply,
        total_supply: legacy.total_supply,
        manifest_cid: legacy.manifest_cid,
        manifest_hash: legacy.manifest_hash,
        schema_version: legacy.schema_version,
        authority: legacy.authority,
        module_flags: legacy.module_flags,
        curve: legacy.curve,
        rewards: legacy.rewards,
        governance: legacy.governance,
        dao_class: DaoClass::Fp,
        burn_bps: 0,
        pending_burn_bps: None,
    }
}

/// Deserialize a `SovereignAsset` from sled, migrating legacy records when needed.
pub fn deserialize_sovereign_asset(bytes: &[u8]) -> Result<SovereignAsset, String> {
    match bincode::deserialize::<SovereignAsset>(bytes) {
        Ok(asset) => Ok(asset),
        Err(_) => {
            let legacy: LegacySovereignAsset = bincode::deserialize(bytes)
                .map_err(|e| format!("sovereign asset deserialize failed: {e}"))?;
            Ok(from_legacy(legacy))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::sovereign_asset::types::PendingBurnBpsUpdate;

    fn legacy_sample() -> LegacySovereignAsset {
        LegacySovereignAsset {
            asset_id: [0xAB; 32],
            id_source: AssetIdSource::LaunchTx,
            name: "Legacy".into(),
            symbol: "LEG".into(),
            decimals: 8,
            creator_key_id: [0xCC; 32],
            creator_did: None,
            treasury_key_id: Some([0xEE; 32]),
            launched_at_height: Some(100),
            supply_mode: SupplyMode::Fixed,
            max_supply: 1_000_000,
            total_supply: 500_000,
            manifest_cid: Some([0x11; 32]),
            manifest_hash: Some([0x22; 32]),
            schema_version: 1,
            authority: AssetAuthority::Creator {
                key_id: [0xCC; 32],
            },
            module_flags: AssetModuleFlags(0),
            curve: None,
            rewards: None,
            governance: None,
        }
    }

    #[test]
    fn legacy_sled_bytes_round_trip_with_defaults() {
        let bytes = bincode::serialize(&legacy_sample()).expect("legacy serialize");
        let asset = deserialize_sovereign_asset(&bytes).expect("legacy migrate");
        assert_eq!(asset.symbol, "LEG");
        assert_eq!(asset.dao_class, DaoClass::Fp);
        assert_eq!(asset.burn_bps, 0);
        assert!(asset.pending_burn_bps.is_none());
    }

    #[test]
    fn current_layout_round_trip() {
        let mut asset = from_legacy(legacy_sample());
        asset.dao_class = DaoClass::Np;
        asset.burn_bps = 100;
        asset.pending_burn_bps = Some(PendingBurnBpsUpdate {
            new_burn_bps: 200,
            effective_height: 99_000,
        });
        let bytes = bincode::serialize(&asset).expect("current serialize");
        let decoded = deserialize_sovereign_asset(&bytes).expect("current decode");
        assert_eq!(decoded.dao_class, DaoClass::Np);
        assert_eq!(decoded.burn_bps, 100);
        assert_eq!(decoded.pending_burn_bps, asset.pending_burn_bps);
    }
}