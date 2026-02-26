use lib_blockchain::{
    Blockchain, FinalizedOraclePrice,
    contracts::bonding_curve::{BondingCurveToken, CurveType, Threshold},
};

fn make_cbe_token(reserve_balance: u64) -> BondingCurveToken {
    let mut token = BondingCurveToken::deploy(
        [1u8; 32],
        "Community Bonding Engine".to_string(),
        "CBE".to_string(),
        CurveType::Linear {
            base_price: 100_000_000,
            slope: 1,
        },
        Threshold::ReserveAmount(1),
        true,
        lib_crypto::PublicKey::new(vec![7u8; 32]),
        1,
        1_700_000_000,
    )
    .expect("deploy CBE");
    token.reserve_balance = reserve_balance;
    token
}

#[test]
fn graduation_requires_finalized_oracle_price() {
    let mut blockchain = Blockchain::new().expect("blockchain init");
    let token = make_cbe_token(10_000 * 100_000_000);
    blockchain.bonding_curve_registry.register(token).expect("register token");

    let err = blockchain
        .validate_cbe_graduation_oracle_gate([1u8; 32], 3_000)
        .expect_err("missing finalized price must fail");
    assert!(err.to_string().contains("requires finalized oracle price"));
}

#[test]
fn graduation_rejects_stale_oracle_price() {
    let mut blockchain = Blockchain::new().expect("blockchain init");
    let token = make_cbe_token(10_000 * 100_000_000);
    blockchain.bonding_curve_registry.register(token).expect("register token");

    let current_epoch = blockchain.oracle_state.epoch_id(3_000);
    blockchain.oracle_state.finalized_prices.insert(
        current_epoch - 3,
        FinalizedOraclePrice {
            epoch_id: current_epoch - 3,
            sov_usd_price: 27 * 100_000_000,
        },
    );
    blockchain.oracle_state.config.max_price_staleness_epochs = 2;

    let err = blockchain
        .validate_cbe_graduation_oracle_gate([1u8; 32], 3_000)
        .expect_err("stale price must fail");
    assert!(err.to_string().contains("stale"));
}

#[test]
fn graduation_rejects_below_threshold_and_accepts_above_threshold() {
    let mut blockchain = Blockchain::new().expect("blockchain init");
    let token = make_cbe_token(9_900 * 100_000_000);
    blockchain.bonding_curve_registry.register(token).expect("register token");

    let current_epoch = blockchain.oracle_state.epoch_id(3_000);
    blockchain.oracle_state.finalized_prices.insert(
        current_epoch,
        FinalizedOraclePrice {
            epoch_id: current_epoch,
            sov_usd_price: 27 * 100_000_000,
        },
    );

    let below = blockchain.validate_cbe_graduation_oracle_gate([1u8; 32], 3_000);
    assert!(below.is_err(), "below threshold must fail");

    if let Some(token_mut) = blockchain.bonding_curve_registry.get_mut(&[1u8; 32]) {
        token_mut.reserve_balance = 10_000 * 100_000_000;
    }

    blockchain
        .validate_cbe_graduation_oracle_gate([1u8; 32], 3_000)
        .expect("above threshold with fresh finalized price must pass");
}
