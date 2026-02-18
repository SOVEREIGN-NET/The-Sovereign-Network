use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::storage::{BlockchainStore, SledStore};
use lib_blockchain::transaction::{DaoExecutionData, Transaction};
use lib_blockchain::types::{Difficulty, Hash, TransactionType};
use lib_crypto::types::keys::PublicKey;
use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};
use serde_json::json;

const EXEC_REGISTER: &str = "dao_delegate_register_v1";
const EXEC_REVOKE: &str = "dao_delegate_revoke_v1";

fn test_pubkey(id: u8) -> PublicKey {
    PublicKey::new(vec![id; 32])
}

fn test_signature(pubkey: &PublicKey, timestamp: u64) -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: pubkey.clone(),
        algorithm: SignatureAlgorithm::Dilithium5,
        timestamp,
    }
}

fn dao_execution_tx(
    proposal_seed: u8,
    executor_key: u8,
    did: &str,
    execution_type: &str,
    metadata: serde_json::Value,
    timestamp: u64,
    height: u64,
) -> Transaction {
    let proposal_id = Hash::new([proposal_seed; 32]);
    let execution_data = DaoExecutionData {
        proposal_id,
        executor: format!("did:zhtp:executor_{executor_key}"),
        execution_type: execution_type.to_string(),
        recipient: Some(did.to_string()),
        amount: None,
        executed_at: timestamp,
        executed_at_height: height,
        multisig_signatures: vec![serde_json::to_vec(&metadata).expect("metadata json")],
    };

    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::DaoExecution,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: test_signature(&test_pubkey(executor_key), timestamp),
        memo: format!("dao:delegate:{execution_type}").into_bytes(),
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: Some(execution_data),
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
    }
}

fn block(height: u64, txs: Vec<Transaction>) -> Block {
    let mut block_hash_bytes = [0u8; 32];
    block_hash_bytes[..8].copy_from_slice(&height.to_be_bytes());
    let header = BlockHeader {
        version: 1,
        height,
        timestamp: 1_700_100_000 + height,
        previous_block_hash: if height == 0 {
            Hash::zero()
        } else {
            let mut prev = [0u8; 32];
            prev[..8].copy_from_slice(&(height - 1).to_be_bytes());
            Hash::new(prev)
        },
        merkle_root: Hash::zero(),
        state_root: Hash::default(),
        block_hash: Hash::new(block_hash_bytes),
        nonce: 0,
        difficulty: Difficulty::from_bits(0),
        cumulative_difficulty: Difficulty::from_bits(0),
        transaction_count: txs.len() as u32,
        block_size: 0,
        fee_model_version: 2,
    };
    Block::new(header, txs)
}

fn reconstruct_active_delegates(
    executions: &[DaoExecutionData],
) -> BTreeMap<String, (String, String, String, u64)> {
    let mut delegates = BTreeMap::new();

    for exec in executions {
        let Some(did) = exec.recipient.clone() else {
            continue;
        };

        if exec.execution_type == EXEC_REGISTER {
            let metadata = exec
                .multisig_signatures
                .first()
                .and_then(|raw| serde_json::from_slice::<serde_json::Value>(raw).ok())
                .unwrap_or_else(|| json!({}));
            let delegate_id = metadata
                .get("delegate_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| hex::encode(exec.proposal_id.as_bytes()));
            let name = metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unnamed")
                .to_string();
            let bio = metadata
                .get("bio")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            delegates.insert(did, (delegate_id, name, bio, exec.executed_at));
        } else if exec.execution_type == EXEC_REVOKE {
            delegates.remove(&did);
        }
    }

    delegates
}

#[test]
fn test_delegate_replay_determinism_from_chain_history() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let did_alice = "did:zhtp:alice";
    let did_bob = "did:zhtp:bob";

    store.begin_block(0)?;
    store.append_block(&block(
        0,
        vec![
            dao_execution_tx(
                0x11,
                1,
                did_alice,
                EXEC_REGISTER,
                json!({"version":1,"delegate_id":"alice-v1","name":"Alice","bio":"first"}),
                1_700_100_001,
                0,
            ),
            dao_execution_tx(
                0x22,
                2,
                did_bob,
                EXEC_REGISTER,
                json!({"version":1,"delegate_id":"bob-v1","name":"Bob","bio":"helper"}),
                1_700_100_002,
                0,
            ),
        ],
    ))?;
    store.commit_block()?;

    store.begin_block(1)?;
    store.append_block(&block(
        1,
        vec![dao_execution_tx(
            0x33,
            1,
            did_alice,
            EXEC_REVOKE,
            json!({"version":1,"reason":"user_requested"}),
            1_700_100_010,
            1,
        )],
    ))?;
    store.commit_block()?;

    store.begin_block(2)?;
    store.append_block(&block(
        2,
        vec![dao_execution_tx(
            0x44,
            1,
            did_alice,
            EXEC_REGISTER,
            json!({"version":1,"delegate_id":"alice-v2","name":"Alice 2","bio":"rejoined"}),
            1_700_100_020,
            2,
        )],
    ))?;
    store.commit_block()?;

    let node_a = lib_blockchain::Blockchain::load_from_store(store.clone())?
        .expect("node A should load from store");
    let node_b = lib_blockchain::Blockchain::load_from_store(store)?
        .expect("node B should load from store");

    let state_a = reconstruct_active_delegates(&node_a.get_dao_executions());
    let state_b = reconstruct_active_delegates(&node_b.get_dao_executions());

    assert_eq!(state_a, state_b, "delegate state must be deterministic across nodes");
    assert_eq!(state_a.len(), 2);
    assert_eq!(state_a.get(did_alice).unwrap().0, "alice-v2");
    assert_eq!(state_a.get(did_alice).unwrap().1, "Alice 2");
    assert_eq!(state_a.get(did_bob).unwrap().0, "bob-v1");

    Ok(())
}

#[test]
fn test_delegate_restart_reconstruction_equivalence() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(tmp.path())?);

    let did = "did:zhtp:restart-user";

    store.begin_block(0)?;
    store.append_block(&block(
        0,
        vec![dao_execution_tx(
            0x55,
            3,
            did,
            EXEC_REGISTER,
            json!({"version":1,"delegate_id":"restart-v1","name":"RestartUser","bio":"before restart"}),
            1_700_200_000,
            0,
        )],
    ))?;
    store.commit_block()?;

    let before_restart = lib_blockchain::Blockchain::load_from_store(store.clone())?
        .expect("before restart should load");
    let expected_state = reconstruct_active_delegates(&before_restart.get_dao_executions());

    let after_restart = lib_blockchain::Blockchain::load_from_store(store)?
        .expect("after restart should load");
    let actual_state = reconstruct_active_delegates(&after_restart.get_dao_executions());

    assert_eq!(expected_state, actual_state, "restart must preserve delegate reconstruction state");
    assert!(actual_state.contains_key(did));

    Ok(())
}
