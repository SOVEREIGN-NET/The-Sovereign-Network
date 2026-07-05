//! Legacy read projection: `TokenContract` / `BondingCurveToken` → `SovereignAsset`.

use super::types::{
    AssetAuthority, AssetIdSource, AssetModuleFlags, CurveModuleHeader, RewardsModuleHeader,
    SovereignAsset, SupplyMode,
};
use crate::contracts::bonding_curve::token::BondingCurveToken;
use crate::contracts::bonding_curve::types::Phase;
use crate::contracts::tokens::TokenContract;
use crate::contracts::utils::generate_lib_token_id;

pub const BUBL_SYMBOL: &str = "BUBL";
pub const BUBL_NAME: &str = "Bubble";

/// Skip native SOV and empty placeholder ids.
pub fn is_sov_native_token_id(token_id: &[u8; 32]) -> bool {
    *token_id == [0u8; 32] || *token_id == generate_lib_token_id()
}

fn phase_label(phase: Phase) -> String {
    match phase {
        Phase::Curve => "curve".to_string(),
        Phase::Graduated => "graduated".to_string(),
        Phase::AMM => "amm".to_string(),
    }
}

/// Project a custom `TokenContract` row into a unified asset view.
pub fn project_from_token_contract(
    token: &TokenContract,
    launched_at_height: Option<u64>,
) -> Option<SovereignAsset> {
    if is_sov_native_token_id(&token.token_id) {
        return None;
    }

    let mut module_flags = AssetModuleFlags(0);
    let mut rewards = None;

    if token.symbol.eq_ignore_ascii_case(BUBL_SYMBOL) && token.name.eq_ignore_ascii_case(BUBL_NAME)
    {
        module_flags.0 |= AssetModuleFlags::REWARDS;
        rewards = Some(RewardsModuleHeader {
            spend_delegate_key_id: None,
        });
    }

    let (supply_mode, max_supply) = if token.max_supply == u128::MAX {
        (SupplyMode::Elastic, u128::MAX)
    } else {
        (SupplyMode::Fixed, token.max_supply)
    };

    Some(SovereignAsset {
        asset_id: token.token_id,
        id_source: AssetIdSource::LegacyTokenId,
        name: token.name.clone(),
        symbol: token.symbol.clone(),
        decimals: token.decimals,
        creator_key_id: token.creator.key_id,
        creator_did: token.creator_did.clone(),
        treasury_key_id: None,
        launched_at_height,
        supply_mode,
        max_supply,
        total_supply: token.total_supply,
        manifest_cid: None,
        manifest_hash: None,
        schema_version: 0,
        authority: AssetAuthority::Creator {
            key_id: token.creator.key_id,
        },
        module_flags,
        curve: None,
        rewards,
        governance: None,
    })
}

/// Project a `BondingCurveToken` row; merges curve module onto token projection when both exist.
pub fn project_from_bonding_curve_token(curve: &BondingCurveToken) -> SovereignAsset {
    let mut module_flags = AssetModuleFlags(AssetModuleFlags::CURVE);

    SovereignAsset {
        asset_id: curve.token_id,
        id_source: AssetIdSource::LegacyTokenId,
        name: curve.name.clone(),
        symbol: curve.symbol.clone(),
        decimals: curve.decimals,
        creator_key_id: curve.creator.key_id,
        creator_did: curve.creator_did.clone(),
        treasury_key_id: None,
        launched_at_height: Some(curve.deployed_at_block),
        supply_mode: SupplyMode::Elastic,
        max_supply: curve.total_supply,
        total_supply: curve.total_supply,
        manifest_cid: None,
        manifest_hash: None,
        schema_version: 0,
        authority: AssetAuthority::Creator {
            key_id: curve.creator.key_id,
        },
        module_flags,
        curve: Some(CurveModuleHeader {
            phase: phase_label(curve.phase),
            sell_enabled: curve.sell_enabled,
        }),
        rewards: None,
        governance: None,
    }
}

/// Merge curve projection over token projection for the same `token_id`.
pub fn merge_curve_into_asset(mut base: SovereignAsset, curve: &BondingCurveToken) -> SovereignAsset {
    base.supply_mode = SupplyMode::Elastic;
    base.module_flags.0 |= AssetModuleFlags::CURVE;
    base.curve = Some(CurveModuleHeader {
        phase: phase_label(curve.phase),
        sell_enabled: curve.sell_enabled,
    });
    if base.launched_at_height.is_none() {
        base.launched_at_height = Some(curve.deployed_at_block);
    }
    if base.creator_did.is_none() {
        base.creator_did = curve.creator_did.clone();
    }
    base.total_supply = curve.total_supply;
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::crypto_integration::PublicKey;

    fn test_creator(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: [id; 32],
        }
    }

    #[test]
    fn project_bubl_class_token() {
        let token_id = crate::contracts::utils::generate_custom_token_id(BUBL_NAME, BUBL_SYMBOL);
        let mut token = TokenContract::new_custom(
            BUBL_NAME.to_string(),
            BUBL_SYMBOL.to_string(),
            0,
            test_creator(1),
        );
        token.token_id = token_id;
        token.decimals = 18;
        token.total_supply = 1_000_000;
        token.max_supply = 1_000_000_000;

        let asset = project_from_token_contract(&token, Some(389)).expect("project");
        assert_eq!(asset.symbol, "BUBL");
        assert_eq!(asset.supply_mode, SupplyMode::Fixed);
        assert!(asset.module_flags.has_rewards());
        assert!(!asset.module_flags.has_curve());
        assert_eq!(asset.id_source, AssetIdSource::LegacyTokenId);
    }

    #[test]
    fn skips_sov_native() {
        let sov = TokenContract::new_sov_native();
        assert!(project_from_token_contract(&sov, None).is_none());
    }

    #[test]
    fn elastic_max_supply_projects_as_elastic() {
        let mut token = TokenContract::new_custom(
            "Elastic".to_string(),
            "ELAS".to_string(),
            0,
            test_creator(2),
        );
        token.max_supply = u128::MAX;
        token.total_supply = 42;

        let asset = project_from_token_contract(&token, None).expect("project");
        assert_eq!(asset.supply_mode, SupplyMode::Elastic);
        assert_eq!(asset.max_supply, u128::MAX);
        assert_eq!(asset.total_supply, 42);
    }
}