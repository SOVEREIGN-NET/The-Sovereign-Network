//! Oracle Price Staleness Tests (ORACLE-5)
//!
//! Tests for price staleness gating per Oracle Spec v1 §11.

use lib_blockchain::{
    oracle::{FinalizedOraclePrice, OracleState},
    Blockchain,
};

/// Test that latest_fresh_price returns None when price is stale.
#[test]
fn latest_fresh_price_returns_none_when_stale() {
    let mut state = OracleState::default();

    // Set staleness window to 2 epochs
    state.config.max_price_staleness_epochs = 2;

    // Finalize price at epoch 0
    state.try_finalize_price(FinalizedOraclePrice {
        epoch_id: 0,
        sov_usd_price: 100_000_000,
        cbe_usd_price: None,
    });

    // At epoch 2, price is still fresh (age = 2)
    assert!(state.latest_fresh_price(2).is_some());

    // At epoch 3, price is stale (age = 3 > 2)
    assert!(state.latest_fresh_price(3).is_none());
}

/// Test that latest_fresh_price returns price when fresh.
#[test]
fn latest_fresh_price_returns_price_when_fresh() {
    let mut state = OracleState::default();
    state.config.max_price_staleness_epochs = 5;

    state.try_finalize_price(FinalizedOraclePrice {
        epoch_id: 10,
        sov_usd_price: 150_000_000,
        cbe_usd_price: None,
    });

    // At epoch 12, price is fresh (age = 2 <= 5)
    let fresh = state.latest_fresh_price(12);
    assert!(fresh.is_some());
    assert_eq!(fresh.unwrap().sov_usd_price, 150_000_000);

    // At epoch 15, price is still fresh (age = 5 <= 5)
    let fresh = state.latest_fresh_price(15);
    assert!(fresh.is_some());
}

/// Test staleness with no finalized price.
#[test]
fn latest_fresh_price_none_when_no_finalized() {
    let state = OracleState::default();

    assert!(state.latest_fresh_price(100).is_none());
}

/// Test CBE graduation blocked with stale price.
#[test]
fn cbe_graduation_blocked_with_stale_price() {
    use lib_blockchain::contracts::bonding_curve::{BondingCurveToken, CurveType, Phase};
    use lib_blockchain::contracts::tokens::CBE_SYMBOL;
    use lib_crypto::PublicKey;

    let mut blockchain = Blockchain::default();

    // Create CBE token with $300K reserve
    let token = BondingCurveToken {
        token_id: [1u8; 32],
        name: "Test CBE".to_string(),
        symbol: CBE_SYMBOL.to_string(),
        decimals: 8,
        phase: Phase::Curve,
        total_supply: 1_000_000_000,
        reserve_balance: 300_000_000_000, // $300K micro-USD
        curve_type: CurveType::Linear {
            base_price: 1,
            slope: 1,
        },
        threshold: lib_blockchain::contracts::bonding_curve::Threshold::ReserveAmount(1_000_000),
        sell_enabled: true,
        amm_pool_id: None,
        creator: PublicKey::new(vec![1u8; 32]),
        creator_did: None,
        deployed_at_block: 1,
        deployed_at_timestamp: 1,
    };

    blockchain.bonding_curve_registry.register(token).unwrap();

    // Set a finalized price at epoch 0
    blockchain
        .oracle_state
        .try_finalize_price(FinalizedOraclePrice {
            epoch_id: 0,
            sov_usd_price: 100_000_000, // $1.00
            cbe_usd_price: None,
        });

    // Configure short staleness window
    blockchain.oracle_state.config.max_price_staleness_epochs = 5;
    blockchain.oracle_state.config.epoch_duration_secs = 300;

    // Try to graduate at epoch 10 (stale: age = 10 > 5)
    let block_timestamp = 10 * 300;
    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], block_timestamp);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no fresh finalized oracle price"),
        "Expected stale/fresh error, got: {}",
        err_msg
    );
}

/// Test CBE graduation proceeds with fresh price.
#[test]
fn cbe_graduation_proceeds_with_fresh_price() {
    use lib_blockchain::contracts::bonding_curve::{BondingCurveToken, CurveType, Phase};
    use lib_blockchain::contracts::tokens::CBE_SYMBOL;
    use lib_crypto::PublicKey;

    let mut blockchain = Blockchain::default();

    let token = BondingCurveToken {
        token_id: [1u8; 32],
        name: "Test CBE".to_string(),
        symbol: CBE_SYMBOL.to_string(),
        decimals: 8,
        phase: Phase::Curve,
        total_supply: 1_000_000_000,
        reserve_balance: 300_000_000_000, // $300K micro-USD
        curve_type: CurveType::Linear {
            base_price: 1,
            slope: 1,
        },
        threshold: lib_blockchain::contracts::bonding_curve::Threshold::ReserveAmount(1_000_000),
        sell_enabled: true,
        amm_pool_id: None,
        creator: PublicKey::new(vec![1u8; 32]),
        creator_did: None,
        deployed_at_block: 1,
        deployed_at_timestamp: 1,
    };

    blockchain.bonding_curve_registry.register(token).unwrap();

    // Set finalized price at epoch 8
    blockchain
        .oracle_state
        .try_finalize_price(FinalizedOraclePrice {
            epoch_id: 8,
            sov_usd_price: 100_000_000,
            cbe_usd_price: None,
        });

    blockchain.oracle_state.config.max_price_staleness_epochs = 5;
    blockchain.oracle_state.config.epoch_duration_secs = 300;

    // Try to graduate at epoch 10 (fresh: age = 2 <= 5)
    let block_timestamp = 10 * 300;
    let result = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], block_timestamp);

    assert!(result.is_ok(), "Expected Ok but got: {:?}", result);
}

/// Test staleness at exact boundary (inclusive).
#[test]
fn staleness_at_exact_boundary() {
    let mut state = OracleState::default();
    state.config.max_price_staleness_epochs = 3;

    state.try_finalize_price(FinalizedOraclePrice {
        epoch_id: 10,
        sov_usd_price: 100_000_000,
        cbe_usd_price: None,
    });

    // At epoch 13, age = 3, which equals max_staleness (inclusive boundary)
    assert!(state.latest_fresh_price(13).is_some());

    // At epoch 14, age = 4, which exceeds max_staleness
    assert!(state.latest_fresh_price(14).is_none());
}

/// Test that default staleness config is reasonable (2 epochs).
#[test]
fn default_staleness_config() {
    let state = OracleState::default();
    assert_eq!(state.config.max_price_staleness_epochs, 2);
}
