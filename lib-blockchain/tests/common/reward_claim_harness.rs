//! Shared RewardClaim integration-test harness (mempool + executor paths).

use std::sync::Arc;

use lib_blockchain::block::Block;
use lib_blockchain::contracts::utils::generate_custom_token_id;
use lib_blockchain::contracts::TokenContract;
use lib_blockchain::storage::{
    convert_legacy_identity, Address, BlockchainStore, SledStore, TokenId,
};
use lib_blockchain::transaction::reward_claim::{
    expected_amount_for_event, RewardClaimData, RewardEventKind, REWARD_CLAIM_MEMO,
};
use lib_blockchain::transaction::signing::sign_transaction;
use lib_blockchain::transaction::{IdentityTransactionData, Transaction};
use lib_blockchain::types::Hash;
use lib_blockchain::Blockchain;
use lib_crypto::{KeyPair, PublicKey, SignatureAlgorithm};
use tempfile::tempdir;

use super::block_builders;

const TEST_CREATED_AT: u64 = 1_700_000_000;

/// Treasury signer + beneficiary for welcome-claim scenarios.
pub struct RewardClaimActors {
    pub treasury: KeyPair,
    pub beneficiary: KeyPair,
    pub owner_did: String,
    pub token_id: [u8; 32],
}

impl RewardClaimActors {
    pub fn generate() -> Self {
        let treasury = KeyPair::generate().expect("treasury keypair");
        let beneficiary = KeyPair::generate().expect("beneficiary keypair");
        let owner_did = did_from_key_id(&beneficiary.public_key.key_id);
        let token_id = generate_custom_token_id("Bubble", "BUBL");
        Self {
            treasury,
            beneficiary,
            owner_did,
            token_id,
        }
    }
}

pub fn did_from_key_id(key_id: &[u8; 32]) -> String {
    format!("did:zhtp:{}", hex::encode(key_id))
}

pub fn identity_data(did: &str, pubkey: &PublicKey) -> IdentityTransactionData {
    IdentityTransactionData {
        did: did.to_string(),
        display_name: "reward_claim_test".to_string(),
        public_key: pubkey.dilithium_pk.to_vec(),
        ownership_proof: vec![],
        identity_type: "human".to_string(),
        did_document_hash: Hash::zero(),
        created_at: TEST_CREATED_AT,
        registration_fee: 0,
        dao_fee: 0,
        controlled_nodes: vec![],
        owned_wallets: vec![],
        kyber_public_key: Vec::new(),
    }
}

fn bubl_token_contract(treasury: &PublicKey) -> TokenContract {
    let token = TokenContract::new_custom(
        "Bubble".to_string(),
        "BUBL".to_string(),
        0,
        treasury.clone(),
    );
    assert_eq!(token.token_id, generate_custom_token_id("Bubble", "BUBL"));
    token
}

fn register_identity_shadow(blockchain: &mut Blockchain, did: &str, pubkey: &PublicKey) {
    blockchain.insert_identity_shadow(did.to_string(), identity_data(did, pubkey));
    blockchain.identity_blocks.insert(did.to_string(), 0);
}

fn put_identity_direct(store: &dyn BlockchainStore, did: &str, pubkey: &PublicKey) {
    let (consensus, metadata) = convert_legacy_identity(&identity_data(did, pubkey));
    store
        .put_identity_direct(&consensus.did_hash, &consensus)
        .expect("seed identity");
    store
        .put_identity_metadata_direct(&consensus.did_hash, &metadata)
        .expect("seed identity metadata");
}

fn register_actor_identities_shadow(blockchain: &mut Blockchain, actors: &RewardClaimActors) {
    let treasury_did = did_from_key_id(&actors.treasury.public_key.key_id);
    register_identity_shadow(blockchain, &treasury_did, &actors.treasury.public_key);
    register_identity_shadow(blockchain, &actors.owner_did, &actors.beneficiary.public_key);
}

fn register_actor_identities_store(store: &dyn BlockchainStore, actors: &RewardClaimActors) {
    let treasury_did = did_from_key_id(&actors.treasury.public_key.key_id);
    put_identity_direct(store, &treasury_did, &actors.treasury.public_key);
    put_identity_direct(store, &actors.owner_did, &actors.beneficiary.public_key);
}

fn attach_ephemeral_store(blockchain: &mut Blockchain) -> Arc<dyn BlockchainStore> {
    // Leak tempdir for test lifetime — store path must remain valid.
    let dir = Box::leak(Box::new(tempdir().expect("tempdir for mempool sled")));
    let store: Arc<dyn BlockchainStore> = Arc::new(
        SledStore::open(dir.path().join("mempool_store")).expect("ephemeral sled store"),
    );
    blockchain.set_store(store.clone());
    store
}

fn install_bubl_mempool_fixtures(blockchain: &mut Blockchain, actors: &RewardClaimActors) {
    let bubl = bubl_token_contract(&actors.treasury.public_key);
    blockchain.insert_token_contract(actors.token_id, bubl);
    blockchain.insert_token_nonce_shadow(
        actors.token_id,
        actors.treasury.public_key.key_id,
        0,
    );
}

/// Seed rewards module + policy document (legacy BUBL policy) with no token contract.
fn put_rewards_module_with_legacy_policy(
    store: &dyn BlockchainStore,
    actors: &RewardClaimActors,
    block_height: u64,
) {
    use lib_blockchain::contracts::sovereign_asset::RewardsModuleState;
    use lib_blockchain::rewards_policy::{legacy_bubl_policy, policy_hash, validate_rewards_policy_value};

    let policy = legacy_bubl_policy();
    validate_rewards_policy_value(&policy).expect("legacy policy valid");
    let policy_hash_arr = policy_hash(&policy).expect("policy hash").as_array();
    let policy_document = serde_json::to_vec(&policy).expect("policy json");
    let mut policy_cid_input = b"zhtp/rewards-policy/cid/v1\0".to_vec();
    policy_cid_input.extend_from_slice(&policy_document);
    let policy_cid = lib_crypto::hash_blake3(&policy_cid_input);

    store
        .begin_block(block_height)
        .expect("begin rewards fixture block");
    store
        .put_rewards_module_state(
            &actors.token_id,
            &RewardsModuleState {
                spend_delegate_key_id: actors.treasury.public_key.key_id,
                policy_cid,
                policy_hash: policy_hash_arr,
                nonce: 0,
                pending_policy: None,
            },
        )
        .expect("seed rewards module without token contract");
    store
        .put_rewards_policy_document(&policy_hash_arr, &policy_document)
        .expect("seed rewards policy document");
    store.commit_block().expect("commit rewards fixture block");
}

/// Identities + rewards-module state for `token_id`, but **no** `token_contracts`
/// row — mirrors pure AssetLaunch (discoverable rewards, applyable via module).
pub fn mempool_blockchain_rewards_module_without_token_contract(
    actors: &RewardClaimActors,
) -> Blockchain {
    let mut blockchain = Blockchain::new().expect("blockchain construct");
    let store = attach_ephemeral_store(&mut blockchain);
    register_actor_identities_store(store.as_ref(), actors);
    register_actor_identities_shadow(&mut blockchain, actors);
    // Empty store expects height 0 (genesis slot) for the first begin_block.
    put_rewards_module_with_legacy_policy(store.as_ref(), actors, 0);
    blockchain.insert_token_nonce_shadow(
        actors.token_id,
        actors.treasury.public_key.key_id,
        0,
    );
    blockchain
}

/// Executor fixture: identities + rewards module + policy + treasury balance,
/// **no** `token_contracts` row. Returns the setup block at height 1.
pub fn seed_executor_store_rewards_module_without_token_contract(
    store: &Arc<dyn BlockchainStore>,
    genesis: &Block,
    actors: &RewardClaimActors,
) -> Block {
    register_actor_identities_store(store.as_ref(), actors);

    let treasury_addr = Address::new(actors.treasury.public_key.key_id);
    let welcome_amount = expected_amount_for_event(RewardEventKind::Welcome, 1);

    // Height 1: fund treasury balances (no TokenContract object).
    store.begin_block(1).expect("begin setup block");
    store
        .set_token_balance(
            &TokenId::new(actors.token_id),
            &treasury_addr,
            welcome_amount.saturating_mul(2),
        )
        .expect("fund treasury");
    // Install rewards module + policy inside same block window.
    {
        use lib_blockchain::contracts::sovereign_asset::RewardsModuleState;
        use lib_blockchain::rewards_policy::{
            legacy_bubl_policy, policy_hash, validate_rewards_policy_value,
        };

        let policy = legacy_bubl_policy();
        validate_rewards_policy_value(&policy).expect("legacy policy valid");
        let policy_hash_arr = policy_hash(&policy).expect("policy hash").as_array();
        let policy_document = serde_json::to_vec(&policy).expect("policy json");
        let mut policy_cid_input = b"zhtp/rewards-policy/cid/v1\0".to_vec();
        policy_cid_input.extend_from_slice(&policy_document);
        let policy_cid = lib_crypto::hash_blake3(&policy_cid_input);

        store
            .put_rewards_module_state(
                &actors.token_id,
                &RewardsModuleState {
                    spend_delegate_key_id: actors.treasury.public_key.key_id,
                    policy_cid,
                    policy_hash: policy_hash_arr,
                    nonce: 0,
                    pending_policy: None,
                },
            )
            .expect("seed rewards module");
        store
            .put_rewards_policy_document(&policy_hash_arr, &policy_document)
            .expect("seed policy document");
    }
    let setup_block = block_builders::block_at_height(1, genesis.header.block_hash);
    store.append_block(&setup_block).expect("append setup block");
    store.commit_block().expect("commit setup block");
    setup_block
}

/// In-memory blockchain with treasury identity + BUBL contract, but beneficiary
/// `owner_did` deliberately absent from the registry (halt regression harness).
pub fn mempool_blockchain_unregistered_beneficiary(actors: &RewardClaimActors) -> Blockchain {
    let mut blockchain = Blockchain::new().expect("blockchain construct");
    let store = attach_ephemeral_store(&mut blockchain);
    let treasury_did = did_from_key_id(&actors.treasury.public_key.key_id);
    put_identity_direct(store.as_ref(), &treasury_did, &actors.treasury.public_key);
    register_identity_shadow(&mut blockchain, &treasury_did, &actors.treasury.public_key);
    install_bubl_mempool_fixtures(&mut blockchain, actors);
    blockchain
}

/// Beneficiary exists in shadow only (phantom) — `identity_exists` true, sled false.
pub fn mempool_blockchain_shadow_phantom_beneficiary(actors: &RewardClaimActors) -> Blockchain {
    let mut blockchain = Blockchain::new().expect("blockchain construct");
    let store = attach_ephemeral_store(&mut blockchain);
    let treasury_did = did_from_key_id(&actors.treasury.public_key.key_id);
    put_identity_direct(store.as_ref(), &treasury_did, &actors.treasury.public_key);
    register_identity_shadow(&mut blockchain, &treasury_did, &actors.treasury.public_key);
    register_identity_shadow(
        &mut blockchain,
        &actors.owner_did,
        &actors.beneficiary.public_key,
    );
    install_bubl_mempool_fixtures(&mut blockchain, actors);
    blockchain
}

/// In-memory blockchain with identities + BUBL contract for mempool admission tests.
pub fn mempool_blockchain(actors: &RewardClaimActors) -> Blockchain {
    let mut blockchain = Blockchain::new().expect("blockchain construct");
    let store = attach_ephemeral_store(&mut blockchain);
    register_actor_identities_store(store.as_ref(), actors);
    register_actor_identities_shadow(&mut blockchain, actors);
    install_bubl_mempool_fixtures(&mut blockchain, actors);
    blockchain
}

/// Beneficiary registered; treasury/spend-delegate key deliberately absent from
/// identity maps — production path after store-backed restart (delegate is a
/// keystore, not a user identity).
pub fn mempool_blockchain_unregistered_treasury(actors: &RewardClaimActors) -> Blockchain {
    let mut blockchain = Blockchain::new().expect("blockchain construct");
    let store = attach_ephemeral_store(&mut blockchain);
    put_identity_direct(store.as_ref(), &actors.owner_did, &actors.beneficiary.public_key);
    register_identity_shadow(
        &mut blockchain,
        &actors.owner_did,
        &actors.beneficiary.public_key,
    );
    install_bubl_mempool_fixtures(&mut blockchain, actors);
    blockchain
}

/// Persist identities, BUBL contract, treasury balance; returns the setup block at height 1.
pub fn seed_executor_store(
    store: &Arc<dyn BlockchainStore>,
    genesis: &Block,
    actors: &RewardClaimActors,
) -> Block {
    register_actor_identities_store(store.as_ref(), actors);

    let bubl = bubl_token_contract(&actors.treasury.public_key);
    let treasury_addr = Address::new(actors.treasury.public_key.key_id);
    let welcome_amount = expected_amount_for_event(RewardEventKind::Welcome, 1);

    store.begin_block(1).expect("begin setup block");
    store.put_token_contract(&bubl).expect("install BUBL contract");
    store
        .set_token_balance(
            &TokenId::new(actors.token_id),
            &treasury_addr,
            welcome_amount.saturating_mul(2),
        )
        .expect("fund treasury");
    let setup_block = block_builders::block_at_height(1, genesis.header.block_hash);
    store.append_block(&setup_block).expect("append setup block");
    store.commit_block().expect("commit setup block");
    setup_block
}

/// Signed welcome `RewardClaim` for `actors.beneficiary` at `nonce`.
pub fn welcome_claim_tx(actors: &RewardClaimActors, nonce: u64) -> Transaction {
    welcome_claim_tx_from(actors, nonce, &actors.treasury)
}

/// Welcome claim signed by `signer` with `data.from == signer.key_id`.
///
/// Use a non-treasury signer to assert mempool rejects unauthorized claims
/// (must not reach apply / halt).
pub fn welcome_claim_tx_from(
    actors: &RewardClaimActors,
    nonce: u64,
    signer: &KeyPair,
) -> Transaction {
    let data = RewardClaimData {
        event: RewardEventKind::Welcome,
        owner_did: actors.owner_did.clone(),
        recipient_key_id: actors.beneficiary.public_key.key_id,
        token_id: actors.token_id,
        from: signer.public_key.key_id,
        amount: expected_amount_for_event(RewardEventKind::Welcome, 1),
        nonce,
        peer_did: None,
    };

    let mut tx = Transaction::new_reward_claim_with_chain_id(
        0x03,
        data,
        lib_crypto::Signature {
            signature: Vec::new(),
            public_key: signer.public_key.clone(),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        },
        REWARD_CLAIM_MEMO.to_vec(),
    );
    sign_transaction(&mut tx, &signer.private_key).expect("sign reward claim");
    tx
}