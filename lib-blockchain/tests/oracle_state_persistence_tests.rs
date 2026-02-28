use lib_blockchain::{Blockchain, FinalizedOraclePrice};

#[test]
fn oracle_state_round_trip_persists_finalized_prices() {
    let mut blockchain = Blockchain::default();
    blockchain.oracle_state.finalized_prices.insert(
        7,
        FinalizedOraclePrice {
            epoch_id: 7,
            sov_usd_price: 218_000_000,
        },
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("blockchain_oracle_v4.dat");

    #[allow(deprecated)]
    blockchain.save_to_file(&path).expect("save_to_file");

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load_from_file");

    let price = loaded
        .oracle_state
        .finalized_prices
        .get(&7)
        .expect("epoch 7 finalized price must persist");
    assert_eq!(price.epoch_id, 7);
    assert_eq!(price.sov_usd_price, 218_000_000);
}

#[test]
fn oracle_state_unsaved_updates_do_not_survive_restart() {
    let mut blockchain = Blockchain::default();
    blockchain.oracle_state.finalized_prices.insert(
        5,
        FinalizedOraclePrice {
            epoch_id: 5,
            sov_usd_price: 210_000_000,
        },
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("blockchain_oracle_v4_unsaved.dat");

    #[allow(deprecated)]
    blockchain.save_to_file(&path).expect("save_to_file");

    // Simulate an uncommitted post-save mutation that should not survive restart.
    blockchain.oracle_state.finalized_prices.insert(
        6,
        FinalizedOraclePrice {
            epoch_id: 6,
            sov_usd_price: 215_000_000,
        },
    );

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load_from_file");

    assert!(
        loaded.oracle_state.finalized_prices.get(&5).is_some(),
        "committed finalized price must persist"
    );
    assert!(
        loaded.oracle_state.finalized_prices.get(&6).is_none(),
        "unsaved oracle update must not leak across restart"
    );
}
