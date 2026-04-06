use super::*;
use crate::block::{Block, BlockHeader};
use crate::transaction::{token_creation::TokenCreationPayloadV1, DaoExecutionData};
use crate::types::ContractCall;
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

fn test_pubkey(seed: u8) -> PublicKey {
    PublicKey::new([seed; 2592])
}

fn test_signature(pubkey: &PublicKey) -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: pubkey.clone(),
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: 1_700_000_000,
    }
}

fn contract_execution_tx(signer: &PublicKey, method: &str, params: Vec<u8>) -> Transaction {
    let call = ContractCall::token_call(method.to_string(), params);
    let payload = bincode::serialize(&(call, test_signature(signer)))
        .expect("contract call payload should serialize");
    let mut memo = b"ZHTP".to_vec();
    memo.extend_from_slice(&payload);

    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(signer),
        memo,
        payload: crate::transaction::TransactionPayload::None,
    }
}

#[test]
fn contract_execution_is_deterministic() {
    #[derive(serde::Serialize)]
    struct CreateTokenParams {
        name: String,
        symbol: String,
        initial_supply: u64,
        decimals: u8,
    }

    #[derive(serde::Serialize)]
    struct MintParams {
        token_id: [u8; 32],
        to: Vec<u8>,
        amount: u64,
    }

    let creator = test_pubkey(0x41);
    let recipient = test_pubkey(0x42);
    let token_name = "ReplayToken";
    let token_symbol = "RPT";
    let token_id = crate::contracts::utils::generate_custom_token_id(token_name, token_symbol);

    let create_params = CreateTokenParams {
        name: token_name.to_string(),
        symbol: token_symbol.to_string(),
        initial_supply: 1_000,
        decimals: 8,
    };
    let mint_params = MintParams {
        token_id,
        to: bincode::serialize(&recipient).expect("recipient should serialize"),
        amount: 250,
    };

    let txs = vec![
        contract_execution_tx(
            &creator,
            "create_custom_token",
            bincode::serialize(&create_params).expect("create params should serialize"),
        ),
        contract_execution_tx(
            &creator,
            "mint",
            bincode::serialize(&mint_params).expect("mint params should serialize"),
        ),
    ];

    let mut direct = Blockchain::default();
    for tx in &txs {
        direct
            .process_contract_execution(tx, 10)
            .expect("direct contract execution should succeed");
    }

    let mut replayed = Blockchain::default();
    for tx in &txs {
        replayed
            .process_contract_execution(tx, 10)
            .expect("replayed contract execution should succeed");
    }

    let direct_token = direct
        .token_contracts
        .get(&token_id)
        .expect("token should exist in direct path");
    let replayed_token = replayed
        .token_contracts
        .get(&token_id)
        .expect("token should exist in replay path");

    assert_eq!(direct_token.total_supply, 1_250);
    assert_eq!(direct_token.balance_of(&creator), 1_000);
    assert_eq!(direct_token.balance_of(&recipient), 250);

    assert_eq!(replayed_token.total_supply, direct_token.total_supply);
    assert_eq!(
        replayed_token.balance_of(&creator),
        direct_token.balance_of(&creator)
    );
    assert_eq!(
        replayed_token.balance_of(&recipient),
        direct_token.balance_of(&recipient)
    );
}

#[test]
fn contract_blocks_populated_during_replay() {
    #[derive(serde::Serialize)]
    struct CreateTokenParams {
        name: String,
        symbol: String,
        initial_supply: u64,
        decimals: u8,
    }

    let creator = test_pubkey(0x43);
    let token_name = "BlockHeightToken";
    let token_symbol = "BHT";
    let token_id = crate::contracts::utils::generate_custom_token_id(token_name, token_symbol);

    let create_params = CreateTokenParams {
        name: token_name.to_string(),
        symbol: token_symbol.to_string(),
        initial_supply: 5_000,
        decimals: 8,
    };

    let tx = contract_execution_tx(
        &creator,
        "create_custom_token",
        bincode::serialize(&create_params).expect("create params should serialize"),
    );

    let mut blockchain = Blockchain::default();
    blockchain
        .process_contract_execution(&tx, 42)
        .expect("contract execution should succeed");

    assert!(
        blockchain.token_contracts.contains_key(&token_id),
        "Token contract should exist"
    );
    assert_eq!(
        blockchain.get_contract_block_height(&token_id),
        Some(42),
        "Contract deployment height should be tracked"
    );
}

fn dao_registry_tx(execution_type: &str, token_seed: u8, treasury_seed: u8) -> Transaction {
    let token_key_id = [token_seed; 32];
    let treasury_key_id = [treasury_seed; 32];
    let metadata_hash = [0xabu8; 32];
    let event = serde_json::json!({
        "token_id": hex::encode(token_key_id),
        "class": "np",
        "metadata_hash": hex::encode(metadata_hash),
        "treasury_key_id": hex::encode(treasury_key_id),
    });
    let dao_execution = DaoExecutionData {
        proposal_id: Hash::default(),
        executor: "did:sov:test".to_string(),
        execution_type: execution_type.to_string(),
        recipient: None,
        amount: None,
        executed_at: 1_700_000_000,
        executed_at_height: 0,
        multisig_signatures: vec![serde_json::to_vec(&event).unwrap()],
    };
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::DaoExecution,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(&test_pubkey(0x70)),
        memo: vec![],
        payload: crate::transaction::TransactionPayload::DaoExecution(dao_execution),
    }
}

fn token_creation_tx(
    signer: &PublicKey,
    name: &str,
    symbol: &str,
    supply: u64,
    treasury_recipient: [u8; 32],
) -> Transaction {
    let payload = TokenCreationPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        initial_supply: supply,
        decimals: 8,
        treasury_allocation_bps: 2_000,
        treasury_recipient,
    };

    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenCreation,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(signer),
        memo: payload
            .encode_memo()
            .expect("token creation payload should encode"),
        payload: crate::transaction::TransactionPayload::None,
    }
}

#[test]
fn token_creation_self_treasury_rejected_in_legacy_flow() {
    let creator = test_pubkey(0x51);
    let tx = token_creation_tx(&creator, "LegacySelf", "LSELF", 1000, creator.key_id);
    let block = Block {
        header: BlockHeader {
            version: 1,
            previous_hash: Hash::default().into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1_700_000_100,
            height: 12,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash: Hash::default(),
        },
        transactions: vec![tx],
    };

    let mut blockchain = Blockchain::default();
    let result = blockchain.process_token_transactions(&block);
    assert!(
        result.is_err(),
        "Legacy token flow must reject treasury recipient equal to creator"
    );
}

#[test]
fn dao_registry_index_incremental_matches_rebuild() {
    let block1 = Block {
        header: BlockHeader {
            version: 1,
            previous_hash: Hash::default().into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1_700_000_010,
            height: 10,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash: Hash::default(),
        },
        transactions: vec![dao_registry_tx(
            Blockchain::DAO_REGISTRY_REGISTER_EXEC,
            0x11,
            0x22,
        )],
    };
    let block2 = Block {
        header: BlockHeader {
            version: 1,
            previous_hash: Hash::default().into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1_700_000_020,
            height: 11,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash: Hash::default(),
        },
        transactions: vec![dao_registry_tx(
            Blockchain::DAO_FACTORY_CREATE_EXEC,
            0x33,
            0x44,
        )],
    };

    let mut incremental = Blockchain::default();
    for tx in &block1.transactions {
        incremental.index_dao_registry_entry_from_tx(tx, block1.header.height);
    }
    for tx in &block2.transactions {
        incremental.index_dao_registry_entry_from_tx(tx, block2.header.height);
    }

    let mut rebuilt = Blockchain::default();
    rebuilt.blocks.push(block1);
    rebuilt.blocks.push(block2);
    rebuilt.rebuild_dao_registry_index();

    assert_eq!(incremental.dao_registry_index, rebuilt.dao_registry_index);
    let entries = rebuilt.list_dao_registry_entries();
    assert_eq!(entries.len(), 2);
    assert!(entries[0].created_at <= entries[1].created_at);
}
