use super::*;
use crate::contracts::bonding_curve::{BondingCurveToken, Phase, PiecewiseLinearCurve};
use crate::contracts::tokens::CBE_SYMBOL;

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

#[test]
fn cbe_graduation_rejects_missing_finalized_price() {
    let mut blockchain = Blockchain::default();
    let token = create_test_cbe_token(300_000_000_000);
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
    let token = create_test_cbe_token(300_000_000_000);
    blockchain.bonding_curve_registry.register(token).unwrap();

    blockchain
        .oracle_state
        .try_finalize_price(crate::oracle::FinalizedOraclePrice {
            epoch_id: 0,
            sov_usd_price: 100_000_000,
            cbe_usd_price: None,
        });

    blockchain.oracle_state.config.max_price_staleness_epochs = 5;
    blockchain.oracle_state.config.epoch_duration_secs = 300;

    let block_timestamp = 10 * 300;
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
    let token = create_test_cbe_token(300_000_000_000);
    blockchain.bonding_curve_registry.register(token).unwrap();

    blockchain
        .oracle_state
        .try_finalize_price(crate::oracle::FinalizedOraclePrice {
            epoch_id: 5,
            sov_usd_price: 100_000_000,
            cbe_usd_price: None,
        });

    blockchain.oracle_state.config.max_price_staleness_epochs = 10;
    blockchain.oracle_state.config.epoch_duration_secs = 300;

    let block_timestamp = 10 * 300;
    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], block_timestamp);

    assert!(result.is_ok(), "Expected Ok but got: {:?}", result);
}

#[test]
fn cbe_graduation_rejects_reserve_below_threshold() {
    let mut blockchain = Blockchain::default();
    let token = create_test_cbe_token(200_000_000_000);
    blockchain.bonding_curve_registry.register(token).unwrap();

    blockchain
        .oracle_state
        .try_finalize_price(crate::oracle::FinalizedOraclePrice {
            epoch_id: 10,
            sov_usd_price: 100_000_000,
            cbe_usd_price: None,
        });

    blockchain.oracle_state.config.max_price_staleness_epochs = 10;
    blockchain.oracle_state.config.epoch_duration_secs = 300;

    let block_timestamp = 10 * 300;
    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], block_timestamp);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("below threshold"), "Error: {}", err_msg);
}

#[test]
fn cbe_graduation_accepts_reserve_at_threshold_boundary() {
    let mut blockchain = Blockchain::default();
    let token = create_test_cbe_token(269_000_000_000);
    blockchain.bonding_curve_registry.register(token).unwrap();

    blockchain
        .oracle_state
        .try_finalize_price(crate::oracle::FinalizedOraclePrice {
            epoch_id: 10,
            sov_usd_price: 100_000_000,
            cbe_usd_price: None,
        });

    blockchain.oracle_state.config.max_price_staleness_epochs = 10;
    blockchain.oracle_state.config.epoch_duration_secs = 300;

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
    let mut token = create_test_cbe_token(300_000_000_000);
    token.symbol = "OTHER".to_string();
    blockchain.bonding_curve_registry.register(token).unwrap();

    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], 1_700_000_000);

    assert!(result.is_ok(), "Non-CBE tokens should skip oracle gate");
}

#[test]
fn cbe_graduation_skips_already_graduated() {
    let mut blockchain = Blockchain::default();
    let mut token = create_test_cbe_token(300_000_000_000);
    token.phase = Phase::Graduated;
    blockchain.bonding_curve_registry.register(token).unwrap();

    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], 1_700_000_000);

    assert!(
        result.is_ok(),
        "Already graduated tokens should skip oracle gate"
    );
}
