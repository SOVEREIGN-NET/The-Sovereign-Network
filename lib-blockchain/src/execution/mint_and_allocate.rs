//! Class-aware supply increases for Sovereign Assets (epic Q1 / Q7).

use crate::contracts::sovereign_asset::{DaoClass, SovereignAsset, SupplyMode};
use crate::execution::errors::{TxApplyError, TxApplyResult};
use crate::execution::tx_apply::{apply_token_mint, StateMutator};
use crate::storage::{Address, TokenId};

/// Split a mint amount into (recipient, treasury) per `dao_class`.
pub fn split_mint_amount(amount: u128, dao_class: DaoClass) -> (u128, u128) {
    let bps = dao_class.treasury_bps() as u128;
    let treasury = amount
        .checked_mul(bps)
        .map(|p| p / 10_000u128)
        .unwrap_or(0);
    let recipient = amount.saturating_sub(treasury);
    (recipient, treasury)
}

/// Mint `amount` atoms, allocate per class, and persist updated `total_supply`.
pub fn mint_and_allocate(
    mutator: &StateMutator<'_>,
    asset: &mut SovereignAsset,
    recipient_key_id: [u8; 32],
    amount: u128,
) -> TxApplyResult<(u128, u128)> {
    if amount == 0 {
        return Err(TxApplyError::InvalidType(
            "mint amount must be greater than 0".to_string(),
        ));
    }

    let new_supply = asset.total_supply.checked_add(amount).ok_or_else(|| {
        TxApplyError::InvalidType("total_supply overflow on mint".to_string())
    })?;
    if asset.supply_mode == SupplyMode::Fixed && new_supply > asset.max_supply {
        return Err(TxApplyError::InvalidType(
            "fixed supply asset cannot exceed max_supply".to_string(),
        ));
    }

    let treasury_key_id = asset.treasury_key_id.ok_or_else(|| {
        TxApplyError::InvalidType("sovereign asset missing treasury_key_id".to_string())
    })?;

    let (recipient_alloc, treasury_alloc) = split_mint_amount(amount, asset.dao_class);
    let token_id = TokenId::new(asset.asset_id);

    if recipient_alloc > 0 {
        apply_token_mint(
            mutator,
            &token_id,
            &Address::new(recipient_key_id),
            recipient_alloc,
        )?;
    }
    if treasury_alloc > 0 {
        apply_token_mint(
            mutator,
            &token_id,
            &Address::new(treasury_key_id),
            treasury_alloc,
        )?;
    }

    asset.total_supply = new_supply;
    mutator.put_sovereign_asset(asset)?;
    Ok((recipient_alloc, treasury_alloc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::sovereign_asset::{
        AssetAuthority, AssetIdSource, AssetModuleFlags, SupplyMode,
    };

    #[test]
    fn fp_split_is_eighty_twenty() {
        let (r, t) = split_mint_amount(1_000, DaoClass::Fp);
        assert_eq!(r, 800);
        assert_eq!(t, 200);
    }

    #[test]
    fn np_split_is_all_treasury() {
        let (r, t) = split_mint_amount(1_000, DaoClass::Np);
        assert_eq!(r, 0);
        assert_eq!(t, 1_000);
    }

    #[test]
    fn mint_and_allocate_updates_total_supply() {
        use crate::storage::{BlockchainStore, SledStore};
        use std::sync::Arc;

        let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open_temporary().unwrap());
        store.begin_block(0).unwrap();
        let mutator = StateMutator::new(store.as_ref());

        let asset_id = [0x01; 32];
        let mut asset = SovereignAsset {
            asset_id,
            id_source: AssetIdSource::LaunchTx,
            name: "T".into(),
            symbol: "T".into(),
            decimals: 8,
            creator_key_id: [0xCC; 32],
            creator_did: None,
            treasury_key_id: Some([0xAA; 32]),
            launched_at_height: Some(1),
            supply_mode: SupplyMode::Elastic,
            max_supply: u128::MAX,
            total_supply: 1_000,
            manifest_cid: Some([1; 32]),
            manifest_hash: Some([2; 32]),
            schema_version: 1,
            authority: AssetAuthority::Creator {
                key_id: [0xCC; 32],
            },
            module_flags: AssetModuleFlags(0),
            curve: None,
            rewards: None,
            governance: None,
            dao_class: DaoClass::Fp,
            burn_bps: 0,
            pending_burn_bps: None,
        };
        mutator.put_sovereign_asset(&asset).unwrap();

        let (r, t) = mint_and_allocate(&mutator, &mut asset, [0xBB; 32], 500).unwrap();
        assert_eq!(r, 400);
        assert_eq!(t, 100);
        assert_eq!(asset.total_supply, 1_500);

        store.commit_block().unwrap();
    }
}