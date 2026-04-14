use super::*;
use std::io::Write;

#[test]
fn load_v3_file_applies_default_oracle_state() {
    let mut blockchain = Blockchain::default();
    blockchain.oracle_state.config.epoch_duration_secs = 999;
    blockchain
        .oracle_state
        .try_finalize_price(crate::oracle::FinalizedOraclePrice {
            epoch_id: 1,
            sov_usd_price: 123_000_000,
            cbe_usd_price: None,
        });

    let storage_v3 = BlockchainStorageV3::from_blockchain(&blockchain);
    let serialized = bincode::serialize(&storage_v3).expect("serialize v3 storage");

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("legacy_v3.dat");
    let mut file_data = Vec::with_capacity(6 + serialized.len());
    file_data.extend_from_slice(&Blockchain::FILE_MAGIC);
    file_data.extend_from_slice(&3u16.to_le_bytes());
    file_data.extend_from_slice(&serialized);

    let mut f = std::fs::File::create(&path).expect("create file");
    f.write_all(&file_data).expect("write file");
    f.sync_all().expect("sync file");

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load v3 file");
    assert_eq!(
        loaded.oracle_state,
        crate::oracle::OracleState::default(),
        "v3 payloads must load with default oracle state"
    );
}

#[test]
fn test_blockchain_storage_v4_oracle_pending_update() {
    let mut bc = Blockchain::new().unwrap();
    bc.oracle_state
        .committee
        .set_members_for_test(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);

    let result =
        bc.oracle_state
            .schedule_committee_update(vec![[5u8; 32], [6u8; 32], [7u8; 32]], 10, 0, None);
    assert!(result.is_ok());

    println!(
        "Before: pending_update = {:?}",
        bc.oracle_state.committee.pending_update()
    );

    let storage = BlockchainStorageV7::from_blockchain(&bc);
    println!(
        "Storage: pending_update = {:?}",
        storage.v6.oracle_state.committee.pending_update()
    );

    let bc2 = storage.to_blockchain();
    println!(
        "After: pending_update = {:?}",
        bc2.oracle_state.committee.pending_update()
    );

    assert!(
        bc2.oracle_state.committee.pending_update().is_some(),
        "pending_update should survive V7 round-trip"
    );
}

#[test]
fn load_legacy_v5_file_migrates_to_current_storage_layout() {
    let mut bc = Blockchain::new().unwrap();
    bc.onramp_state = crate::onramp::OnRampState::default();

    let storage_v5 = LegacyBlockchainStorageV5 {
        v4: BlockchainStorageV4 {
            v3: BlockchainStorageV3::from_blockchain(&bc),
            oracle_state: bc.oracle_state.clone(),
            exchange_state: bc.exchange_state.clone(),
            oracle_slash_events: bc.oracle_slash_events.clone(),
            oracle_slashing_config: bc.oracle_slashing_config.clone(),
            oracle_banned_validators: bc.oracle_banned_validators.clone(),
            last_oracle_epoch_processed: bc.last_oracle_epoch_processed,
        },
        onramp_state: bc.onramp_state.clone(),
    };
    let serialized = bincode::serialize(&storage_v5).expect("serialize legacy v5 storage");

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("legacy_v5.dat");
    let mut file_data = Vec::with_capacity(6 + serialized.len());
    file_data.extend_from_slice(&Blockchain::FILE_MAGIC);
    file_data.extend_from_slice(&5u16.to_le_bytes());
    file_data.extend_from_slice(&serialized);

    let mut f = std::fs::File::create(&path).expect("create file");
    f.write_all(&file_data).expect("write file");
    f.sync_all().expect("sync file");

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load legacy v5 file");
    assert_eq!(loaded.onramp_state, bc.onramp_state);
    assert!(loaded.entity_registry.is_none());
    // cbe_token field removed from Blockchain (EPIC-001 Phase 1)
}

#[test]
fn load_legacy_v6_file_migrates_to_current_storage_layout() {
    let bc = Blockchain::new().unwrap();

    let storage_v6 = BlockchainStorageV6 {
        v3: BlockchainStorageV3::from_blockchain(&bc),
        oracle_state: bc.oracle_state.clone(),
        exchange_state: bc.exchange_state.clone(),
        onramp_state: bc.onramp_state.clone(),
        oracle_slash_events: bc.oracle_slash_events.clone(),
        oracle_slashing_config: bc.oracle_slashing_config.clone(),
        oracle_banned_validators: bc.oracle_banned_validators.clone(),
        last_oracle_epoch_processed: bc.last_oracle_epoch_processed,
        entity_registry: bc.entity_registry.clone(),
    };
    let serialized = bincode::serialize(&storage_v6).expect("serialize legacy v6 storage");

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("legacy_v6.dat");
    let mut file_data = Vec::with_capacity(6 + serialized.len());
    file_data.extend_from_slice(&Blockchain::FILE_MAGIC);
    file_data.extend_from_slice(&6u16.to_le_bytes());
    file_data.extend_from_slice(&serialized);

    let mut f = std::fs::File::create(&path).expect("create file");
    f.write_all(&file_data).expect("write file");
    f.sync_all().expect("sync file");

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load legacy v6 file");
    // cbe_token field removed from Blockchain (EPIC-001 Phase 1)
}

#[test]
fn test_blockchain_save_load_oracle_pending_update() {
    let mut bc = Blockchain::new().unwrap();
    bc.oracle_state
        .committee
        .set_members_for_test(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);

    let result =
        bc.oracle_state
            .schedule_committee_update(vec![[5u8; 32], [6u8; 32], [7u8; 32]], 10, 0, None);
    assert!(result.is_ok());

    bc.last_oracle_epoch_processed = bc.last_committed_timestamp();

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("test.dat");

    #[allow(deprecated)]
    bc.save_to_file(&path).expect("save should succeed");

    #[allow(deprecated)]
    let bc2 = Blockchain::load_from_file(&path).expect("load should succeed");

    assert!(
        bc2.oracle_state.committee.pending_update().is_some(),
        "pending_update should survive save/load, got: {:?}",
        bc2.oracle_state.committee.pending_update()
    );
}

#[test]
fn load_from_file_does_not_mint_or_repair_sov_balances() {
    let mut bc = Blockchain::new().unwrap();
    bc.ensure_sov_token_contract();

    let missing_wallet = [0x41u8; 32];
    let partial_wallet = [0x42u8; 32];
    let missing_initial_balance = 500 * 100_000_000;
    let partial_initial_balance = 700 * 100_000_000;
    let partial_existing_balance = 125 * 100_000_000;

    for (wallet_id, initial_balance) in [
        (missing_wallet, missing_initial_balance),
        (partial_wallet, partial_initial_balance),
    ] {
        bc.wallet_registry.insert(
            hex::encode(wallet_id),
            crate::transaction::WalletTransactionData {
                wallet_id: Hash::new(wallet_id),
                wallet_type: "Primary".to_string(),
                wallet_name: format!("Wallet-{}", hex::encode(&wallet_id[..4])),
                alias: None,
                public_key: vec![wallet_id[0]; 32],
                owner_identity_id: None,
                seed_commitment: Hash::zero(),
                created_at: 1_700_000_000,
                registration_fee: 0,
                capabilities: 0,
                initial_balance,
            },
        );
    }

    let sov_token_id = crate::contracts::utils::generate_lib_token_id();
    let missing_recipient = Blockchain::wallet_key_for_sov(&missing_wallet);
    let partial_recipient = Blockchain::wallet_key_for_sov(&partial_wallet);
    {
        let token = bc
            .token_contracts
            .get_mut(&sov_token_id)
            .expect("SOV token should exist");
        token
            .set_balance(&partial_recipient, partial_existing_balance);
        token.total_supply = partial_existing_balance;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("no_supply_repair.dat");

    #[allow(deprecated)]
    bc.save_to_file(&path).expect("save should succeed");

    #[allow(deprecated)]
    let loaded = Blockchain::load_from_file(&path).expect("load should succeed");

    let token = loaded
        .token_contracts
        .get(&sov_token_id)
        .expect("loaded SOV token should exist");
    assert_eq!(
        token.balance_of(&missing_recipient),
        0,
        "load_from_file must not mint missing balances from wallet metadata"
    );
    assert_eq!(
        token.balance_of(&partial_recipient),
        partial_existing_balance,
        "load_from_file must not repair underfunded balances from wallet metadata"
    );
    assert_eq!(
        token.total_supply, partial_existing_balance,
        "load_from_file must preserve serialized supply without startup repair"
    );
}
