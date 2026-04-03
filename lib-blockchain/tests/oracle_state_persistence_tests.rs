use lib_blockchain::{Blockchain, FinalizedOraclePrice};

#[test]
fn oracle_state_round_trip_persists_finalized_prices() {
    let mut blockchain = Blockchain::default();
    // Use the public try_finalize_price API to insert a finalized price.
    blockchain
        .oracle_state
        .try_finalize_price(FinalizedOraclePrice {
            epoch_id: 7,
            sov_usd_price: 218_000_000,
            cbe_usd_price: None,
        });

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("blockchain_oracle_v4.dat");

    #[allow(deprecated)]
    blockchain.save_to_file(&path).expect("save_to_file");

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load_from_file");

    let price = loaded
        .oracle_state
        .finalized_price(7)
        .expect("epoch 7 finalized price must persist");
    assert_eq!(price.epoch_id, 7);
    assert_eq!(price.sov_usd_price, 218_000_000);
}
