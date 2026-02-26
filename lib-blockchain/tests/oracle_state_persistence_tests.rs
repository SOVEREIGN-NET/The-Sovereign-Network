use lib_blockchain::{Blockchain, FinalizedPrice};

#[test]
fn oracle_state_round_trip_persists_finalized_prices() {
    let mut blockchain = Blockchain::default();
    blockchain.oracle_state.finalized_prices.insert(
        7,
        FinalizedPrice {
            epoch_id: 7,
            price: 218_000_000,
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
    assert_eq!(price.price, 218_000_000);
}

