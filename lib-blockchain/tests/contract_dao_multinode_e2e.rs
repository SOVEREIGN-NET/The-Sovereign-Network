use anyhow::Result;
use lib_blockchain::types::mining::get_mining_config_from_env;
use lib_blockchain::types::{ContractCall, ContractType, Hash};
use lib_blockchain::transaction::{
    DaoExecutionData, DaoProposalData, DaoVoteData, Transaction,
    TransactionOutput, CONTRACT_DEPLOYMENT_MEMO_PREFIX, ContractDeploymentPayloadV1,
};
use lib_blockchain::{Block, BlockHeader, Blockchain, TransactionType};
use lib_crypto::{PublicKey, Signature, SignatureAlgorithm};

fn test_public_key(seed: u8) -> PublicKey {
    PublicKey::new(vec![seed; 1312])
}

fn test_signature(seed: u8) -> Signature {
    Signature {
        signature: vec![seed; 64],
        public_key: test_public_key(seed),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: 1,
    }
}

fn mk_output(seed: u8) -> TransactionOutput {
    TransactionOutput {
        commitment: Hash::from([seed; 32]),
        note: Hash::default(),
        recipient: test_public_key(seed),
    }
}

fn mk_contract_deploy_tx() -> Transaction {
    let payload = ContractDeploymentPayloadV1 {
        contract_type: "wasm".to_string(),
        code: vec![0, 97, 115, 109],
        abi: br#"{\"contract\":\"demo\",\"version\":\"1.0.0\"}"#.to_vec(),
        init_args: vec![],
        gas_limit: 100_000,
        memory_limit_bytes: 65_536,
    };

    Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: TransactionType::ContractDeployment,
        inputs: vec![],
        outputs: vec![mk_output(1)],
        fee: 0,
        signature: test_signature(1),
        memo: payload.encode_memo().expect("valid deployment payload"),
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
    }
}

fn mk_contract_call_tx() -> Transaction {
    let call = ContractCall::new(
        ContractType::Governance,
        "ping".to_string(),
        vec![1, 2, 3],
        lib_blockchain::types::CallPermissions::Public,
    );
    let call_sig = test_signature(2);
    let mut memo = b"ZHTP".to_vec();
    memo.extend(bincode::serialize(&(call, call_sig)).expect("serialize call"));

    Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![mk_output(2)],
        fee: 0,
        signature: test_signature(2),
        memo,
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
    }
}

fn mk_dao_lifecycle_txs(proposal_id: Hash) -> Vec<Transaction> {
    let proposal = DaoProposalData {
        proposal_id,
        proposer: "did:zhtp:proposer".to_string(),
        title: "Treasury allocation".to_string(),
        description: "Fund ecosystem operations".to_string(),
        proposal_type: "treasury_allocation".to_string(),
        voting_period_blocks: 100,
        quorum_required: 60,
        execution_params: None,
        created_at: 1,
        created_at_height: 1,
    };
    let vote = DaoVoteData {
        vote_id: Hash::from([9; 32]),
        proposal_id,
        voter: "did:zhtp:voter-1".to_string(),
        vote_choice: "Yes".to_string(),
        voting_power: 100,
        justification: Some("approved".to_string()),
        timestamp: 2,
    };
    let execution = DaoExecutionData {
        proposal_id,
        executor: "did:zhtp:executor".to_string(),
        execution_type: "TreasurySpending".to_string(),
        recipient: Some("did:zhtp:recipient".to_string()),
        amount: Some(42),
        executed_at: 3,
        executed_at_height: 1,
        multisig_signatures: vec![vec![1, 2, 3]],
    };

    vec![
        Transaction::new_dao_proposal(
            proposal,
            vec![],
            vec![mk_output(10)],
            0,
            test_signature(10),
            b"dao proposal".to_vec(),
        ),
        Transaction::new_dao_vote(
            vote,
            vec![],
            vec![mk_output(11)],
            0,
            test_signature(11),
            b"dao vote".to_vec(),
        ),
        Transaction::new_dao_execution(
            execution,
            vec![],
            vec![mk_output(12)],
            0,
            test_signature(12),
            b"dao execution".to_vec(),
        ),
    ]
}

fn build_block_with_transactions(parent: &Block, txs: Vec<Transaction>, extra_nonce: u64) -> Block {
    let mining_config = get_mining_config_from_env();
    let mut header = BlockHeader::new(
        1,
        parent.hash(),
        lib_blockchain::transaction::hashing::calculate_transaction_merkle_root(&txs),
        parent.timestamp() + 10 + extra_nonce,
        mining_config.difficulty,
        parent.height() + 1,
        txs.len() as u32,
        0,
        mining_config.difficulty,
    );
    header.set_nonce(0);
    Block::new(header, txs)
}

#[tokio::test]
async fn test_multinode_contract_dao_lifecycle_sync_and_replay_convergence() -> Result<()> {
    let mut node_a = Blockchain::new()?;
    let genesis = node_a.latest_block().expect("genesis exists").clone();

    let proposal_id = Hash::from([7; 32]);
    let mut txs = vec![mk_contract_deploy_tx(), mk_contract_call_tx()];
    txs.extend(mk_dao_lifecycle_txs(proposal_id));

    let block = build_block_with_transactions(&genesis, txs, 0);
    node_a.add_block(block).await?;

    let export = node_a.export_chain()?;

    // Node B sync/import
    let mut node_b = Blockchain::new()?;
    node_b.evaluate_and_merge_chain(export.clone()).await?;

    // Node C replay/import from Node B export
    let mut node_c = Blockchain::new()?;
    let export_b = node_b.export_chain()?;
    node_c.evaluate_and_merge_chain(export_b).await?;

    // Deterministic convergence checks across nodes
    assert_eq!(node_a.height, node_b.height);
    assert_eq!(node_b.height, node_c.height);
    assert_eq!(node_a.blocks.len(), node_b.blocks.len());
    assert_eq!(node_b.blocks.len(), node_c.blocks.len());

    let a_tip = node_a.latest_block().unwrap().hash();
    let b_tip = node_b.latest_block().unwrap().hash();
    let c_tip = node_c.latest_block().unwrap().hash();
    assert_eq!(a_tip, b_tip);
    assert_eq!(b_tip, c_tip);

    // Lifecycle artifacts should be preserved across sync/replay.
    let lifecycle_types = [
        TransactionType::ContractDeployment,
        TransactionType::ContractExecution,
        TransactionType::DaoProposal,
        TransactionType::DaoVote,
        TransactionType::DaoExecution,
    ];
    for tx_type in lifecycle_types {
        let a_count = node_a
            .blocks
            .iter()
            .flat_map(|b| b.transactions.iter())
            .filter(|tx| tx.transaction_type == tx_type)
            .count();
        let b_count = node_b
            .blocks
            .iter()
            .flat_map(|b| b.transactions.iter())
            .filter(|tx| tx.transaction_type == tx_type)
            .count();
        let c_count = node_c
            .blocks
            .iter()
            .flat_map(|b| b.transactions.iter())
            .filter(|tx| tx.transaction_type == tx_type)
            .count();
        assert_eq!(a_count, 1, "missing lifecycle tx on node A: {:?}", tx_type);
        assert_eq!(a_count, b_count, "node B diverged for {:?}", tx_type);
        assert_eq!(b_count, c_count, "node C diverged for {:?}", tx_type);
    }

    Ok(())
}

#[test]
fn test_contract_deployment_rejection_path_invalid_memo_payload() -> Result<()> {
    let blockchain = Blockchain::new()?;

    let mut bad_memo = CONTRACT_DEPLOYMENT_MEMO_PREFIX.to_vec();
    bad_memo.extend([0xde, 0xad, 0xbe, 0xef]); // not valid bincode payload

    let invalid_tx = Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: TransactionType::ContractDeployment,
        inputs: vec![],
        outputs: vec![mk_output(42)],
        fee: 0,
        signature: test_signature(42),
        memo: bad_memo,
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
            bonding_curve_deploy_data: None,
            bonding_curve_buy_data: None,
            bonding_curve_sell_data: None,
            bonding_curve_graduate_data: None,
    };

    assert!(
        !blockchain.verify_transaction(&invalid_tx)?,
        "Invalid deployment memo must be rejected"
    );

    Ok(())
}
