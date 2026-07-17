use super::*;
use crate::contracts::bonding_curve::{
    BondingCurveToken, Phase, PiecewiseLinearCurve, GRADUATION_THRESHOLD_USD,
};
use crate::contracts::tokens::CBE_SYMBOL;

/// Micro-USD per whole USD (oracle reserve precision).
const MICRO_USD_PER_USD: u128 = 1_000_000;

/// Reserve value that meets the graduation threshold at $1/SOV oracle price.
/// Derived from the single source of truth: GRADUATION_THRESHOLD_USD.
fn reserve_at_threshold() -> u128 {
    GRADUATION_THRESHOLD_USD * MICRO_USD_PER_USD
}

/// Reserve value below the graduation threshold.
fn reserve_below_threshold() -> u128 {
    reserve_at_threshold() / 2
}

fn create_test_cbe_token(reserve_micro_usd: u128) -> BondingCurveToken {
    BondingCurveToken {
        token_id: [1u8; 32],
        name: "Test CBE".to_string(),
        symbol: CBE_SYMBOL.to_string(),
        decimals: 18,
        phase: Phase::Curve,
        total_supply: 1_000_000_000u128,
        reserve_balance: reserve_micro_usd,
        treasury_balance: 0u128,
        curve_type: crate::contracts::bonding_curve::CurveType::PiecewiseLinear(
            PiecewiseLinearCurve::cbe_default(),
        ),
        threshold: crate::contracts::bonding_curve::Threshold::ReserveAmount(1_000_000u128),
        sell_enabled: true,
        amm_pool_id: None,
        creator: PublicKey::new([1u8; 2592]),
        creator_did: None,
        deployed_at_block: 1,
        deployed_at_timestamp: 1,
        graduation_pending_since_block: None,
        last_oracle_price: None,
        last_oracle_price_timestamp: None,
    }
}

fn setup_fresh_oracle(blockchain: &mut Blockchain, epoch_id: u64) {
    blockchain
        .oracle_state
        .try_finalize_price(crate::oracle::FinalizedOraclePrice {
            epoch_id,
            sov_usd_price: 100_000_000, // $1.00 in oracle price precision
            cbe_usd_price: None,
        });
    blockchain.oracle_state.config.max_price_staleness_epochs = 10;
    blockchain.oracle_state.config.epoch_duration_secs = 300;
}

#[test]
fn cbe_graduation_rejects_missing_finalized_price() {
    let mut blockchain = Blockchain::default();
    let token = create_test_cbe_token(reserve_at_threshold());
    blockchain.bonding_curve_registry.register(token).unwrap();

    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], 1_700_000_000);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no fresh finalized oracle price"),
        "Error: {}",
        err_msg
    );
}

#[test]
fn cbe_graduation_rejects_stale_finalized_price() {
    let mut blockchain = Blockchain::default();
    let token = create_test_cbe_token(reserve_at_threshold());
    blockchain.bonding_curve_registry.register(token).unwrap();

    // Epoch 0 finalized, but timestamp is far ahead → stale
    setup_fresh_oracle(&mut blockchain, 0);
    blockchain.oracle_state.config.max_price_staleness_epochs = 5;

    let block_timestamp = 10 * 300; // 10 epochs ahead
    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], block_timestamp);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no fresh finalized oracle price"),
        "Error: {}",
        err_msg
    );
}

#[test]
fn cbe_graduation_accepts_fresh_finalized_price() {
    let mut blockchain = Blockchain::default();
    let token = create_test_cbe_token(reserve_at_threshold());
    blockchain.bonding_curve_registry.register(token).unwrap();

    setup_fresh_oracle(&mut blockchain, 5);

    let block_timestamp = 10 * 300;
    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], block_timestamp);

    assert!(result.is_ok(), "Expected Ok but got: {:?}", result);
}

#[test]
fn cbe_graduation_rejects_reserve_below_threshold() {
    let mut blockchain = Blockchain::default();
    let token = create_test_cbe_token(reserve_below_threshold());
    blockchain.bonding_curve_registry.register(token).unwrap();

    setup_fresh_oracle(&mut blockchain, 10);

    let block_timestamp = 10 * 300;
    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], block_timestamp);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("below threshold"), "Error: {}", err_msg);
}

#[test]
fn cbe_graduation_accepts_reserve_at_threshold_boundary() {
    let mut blockchain = Blockchain::default();
    let token = create_test_cbe_token(reserve_at_threshold());
    blockchain.bonding_curve_registry.register(token).unwrap();

    setup_fresh_oracle(&mut blockchain, 10);

    let block_timestamp = 10 * 300;
    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], block_timestamp);

    assert!(
        result.is_ok(),
        "Expected Ok for exact threshold boundary but got: {:?}",
        result
    );
}

#[test]
fn cbe_graduation_skips_non_cbe_tokens() {
    let mut blockchain = Blockchain::default();
    let mut token = create_test_cbe_token(reserve_at_threshold());
    token.symbol = "OTHER".to_string();
    blockchain.bonding_curve_registry.register(token).unwrap();

    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], 1_700_000_000);

    assert!(result.is_ok(), "Non-CBE tokens should skip oracle gate");
}

#[test]
fn cbe_graduation_skips_already_graduated() {
    let mut blockchain = Blockchain::default();
    let mut token = create_test_cbe_token(reserve_at_threshold());
    token.phase = Phase::Graduated;
    blockchain.bonding_curve_registry.register(token).unwrap();

    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], 1_700_000_000);

    assert!(
        result.is_ok(),
        "Already graduated tokens should skip oracle gate"
    );
}

/// Dual-state fixture: legacy bonding-curve row and sovereign curve module disagree on reserve.
/// Post economic-rules activation the curve-module reserve wins; pre-activation uses legacy.
#[test]
fn resolve_reserve_prefers_curve_module_after_activation_when_dual_state() {
    use crate::contracts::sovereign_asset::{
        AssetAuthority, AssetIdSource, AssetModuleFlags, CurveModuleState, CurvePhase, DaoClass,
        SovereignAsset, SupplyMode,
    };
    use crate::storage::{SledStore, TokenId};
    use std::sync::Arc;

    let store = Arc::new(SledStore::open_temporary().unwrap());
    let token_id = [0xCBu8; 32];
    let legacy_reserve = 111u128;
    let curve_reserve = 999u128;

    let mut legacy = create_test_cbe_token(legacy_reserve);
    legacy.token_id = token_id;

    let asset = SovereignAsset {
        asset_id: token_id,
        id_source: AssetIdSource::LaunchTx,
        name: "CBE Equity".to_string(),
        symbol: CBE_SYMBOL.to_string(),
        decimals: 18,
        creator_key_id: [0x01; 32],
        creator_did: None,
        treasury_key_id: Some([0x02; 32]),
        launched_at_height: Some(1),
        supply_mode: SupplyMode::Elastic,
        max_supply: u128::MAX,
        total_supply: 0,
        manifest_cid: None,
        manifest_hash: None,
        schema_version: 1,
        authority: AssetAuthority::Creator {
            key_id: [0x01; 32],
        },
        module_flags: AssetModuleFlags(AssetModuleFlags::CURVE),
        curve: None,
        rewards: None,
        governance: None,
        dao_class: DaoClass::Fp,
        burn_bps: 0,
        pending_burn_bps: None,
    };

    store.begin_block(0).expect("begin");
    store
        .put_bonding_curve_token(&TokenId::new(token_id), &legacy)
        .expect("seed legacy token");
    store.put_sovereign_asset(&asset).expect("seed asset");
    store
        .put_curve_module_state(
            &token_id,
            &CurveModuleState {
                phase: CurvePhase::Curve,
                reserve_balance: curve_reserve,
                treasury_balance: 0,
                threshold: 1,
                sell_enabled: true,
                amm_pool_id: None,
            },
        )
        .expect("seed curve state");
    store.commit_block().expect("commit");

    let bc = Blockchain::new_with_store(store).expect("blockchain with store");

    // In unit tests GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT is 0, so height 0 is active.
    let post = bc
        .resolve_cbe_graduation_reserve(token_id, 0)
        .expect("resolve post-activation")
        .expect("reserve present");
    assert_eq!(
        post, curve_reserve,
        "post-activation must use curve-module reserve when dual state exists"
    );

    // Curve-flagged asset without curve side-table row → fall through to legacy.
    let store2 = Arc::new(SledStore::open_temporary().unwrap());
    store2.begin_block(0).expect("begin");
    store2
        .put_bonding_curve_token(&TokenId::new(token_id), &legacy)
        .expect("seed legacy");
    store2.put_sovereign_asset(&asset).expect("seed asset without curve state");
    store2.commit_block().expect("commit");
    let bc2 = Blockchain::new_with_store(store2).expect("bc2");
    let fallback = bc2
        .resolve_cbe_graduation_reserve(token_id, 0)
        .expect("resolve fallback")
        .expect("legacy reserve");
    assert_eq!(
        fallback, legacy_reserve,
        "missing curve side-table must fall through to legacy, not hard-fail"
    );
}
