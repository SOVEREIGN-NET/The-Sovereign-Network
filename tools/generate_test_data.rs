/// Sovereign Network Test Data Generator
///
/// Generates realistic test data files using actual Sovereign Network data schemas.
/// Each file matches the real serialization format of network types:
///   - Transactions with UTXO inputs, ZK proofs, 46 transaction types
///   - Blocks with proper header chaining (prev_hash → block_hash)
///   - Governance proposals with ConfigField enum + PendingChange
///   - ZkWitness shard manifests with Merkle roots
///   - Mesh network messages with 32 MessageType variants
///   - DID identity records (did:zhtp:{blake3_hex})
///   - CBE token economics, UBI claims
///   - Kademlia DHT routing (20-byte UIDs, k-buckets)
///   - Node performance metrics (CSV)
///   - Validator event logs (structured text)

use rand::Rng;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

fn main() {
    let dir = Path::new("test_data");
    fs::create_dir_all(dir).expect("Failed to create test_data directory");

    println!("Sovereign Network Test Data Generator");
    println!("=====================================\n");

    let generators: Vec<(&str, fn(&Path))> = vec![
        ("blockchain_transactions.json", generate_blockchain_transactions),
        ("blocks.json", generate_blocks),
        ("governance_proposals.json", generate_governance_proposals),
        ("shard_manifests.json", generate_shard_manifests),
        ("network_mesh_messages.json", generate_network_messages),
        ("identity_records.json", generate_identity_records),
        ("token_economics.json", generate_token_economics),
        ("network_metrics.csv", generate_network_metrics),
        ("dht_routing.json", generate_dht_routing),
        ("validator_events.log", generate_validator_log),
    ];

    for (name, gen_fn) in &generators {
        let path = dir.join(name);
        gen_fn(dir);
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        println!("  [OK] {:38} {:>8} bytes", name, size);
    }

    // Print total
    let total: u64 = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok().map(|m| m.len()))
        .sum();
    println!("\n  Total test data: {} bytes ({:.2} KB)", total, total as f64 / 1024.0);
    println!("\nDone. Files written to test_data/");
}

// ============================================================================
// Helper functions for realistic random data
// ============================================================================

/// Generate a random BLAKE3 hash as 64-char hex string
fn rand_hash() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    let hash = blake3::hash(&bytes);
    hash.to_hex().to_string()
}

/// Generate a deterministic hash from a seed string
fn hash_from(seed: &str) -> String {
    blake3::hash(seed.as_bytes()).to_hex().to_string()
}

/// Generate a random DID in Sovereign Network format
fn rand_did() -> String {
    format!("did:zhtp:{}", &rand_hash()[..48])
}

/// Generate a compact hex-encoded public key (Dilithium5 key_id, 32 bytes)
fn rand_key_id() -> String {
    rand_hash()
}

/// Pick a random element from a slice
fn pick<'a>(options: &[&'a str]) -> &'a str {
    options[rand::thread_rng().gen_range(0..options.len())]
}

/// Generate a random IPv4:port address
fn rand_addr() -> String {
    let mut rng = rand::thread_rng();
    format!(
        "{}.{}.{}.{}:{}",
        rng.gen_range(10..255),
        rng.gen_range(0..255),
        rng.gen_range(0..255),
        rng.gen_range(1..255),
        rng.gen_range(8000..65535)
    )
}

/// Generate a random 20-byte UID (Kademlia) as hex
fn rand_uid() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

/// Random transaction type from the real 46-variant enum
fn rand_tx_type() -> &'static str {
    let types = [
        "Transfer", "Coinbase", "TokenTransfer",
        "IdentityRegistration", "IdentityUpdate", "IdentityRevocation",
        "ContractDeployment", "ContractExecution",
        "SessionCreation", "SessionTermination", "ContentUpload",
        "UbiDistribution", "WalletRegistration",
        "ValidatorRegistration", "ValidatorUpdate", "ValidatorUnregister",
        "DaoProposal", "DaoVote", "DaoExecution", "DifficultyUpdate",
        "UBIClaim", "ProfitDeclaration", "GovernanceConfigUpdate",
        "WalletUpdate", "TokenMint", "TokenCreation", "TokenSwap",
        "CreatePool", "AddLiquidity", "RemoveLiquidity",
        "BondingCurveDeploy", "BondingCurveBuy", "BondingCurveSell",
        "BondingCurveGraduate",
        "UpdateOracleCommittee", "UpdateOracleConfig",
        "OracleAttestation", "CancelOracleUpdate",
        "InitEntityRegistry", "RecordOnRampTrade",
        "TreasuryAllocation", "InitCbeToken",
        "CreateEmploymentContract", "ProcessPayroll",
        "DaoStake", "DaoUnstake",
    ];
    let mut rng = rand::thread_rng();
    types[rng.gen_range(0..types.len())]
}

/// Random ConfigField from the real governance enum
fn rand_config_field() -> &'static str {
    let fields = [
        "TransferFeeBps", "BurnFeeBps", "FeeCap", "MinFee",
        "TransferPolicy", "FeeRecipient", "TreasuryAddress",
        "MaxSupply", "AuthorityAdd", "AuthorityRemove",
        "BlockSizeLimit", "TxCountLimit", "BaseFeePerByte",
    ];
    let mut rng = rand::thread_rng();
    fields[rng.gen_range(0..fields.len())]
}

/// Random MessageType from the real 32-variant network enum
fn rand_message_type() -> &'static str {
    let types = [
        "PeerDiscovery", "PeerAnnounce", "PeerChallenge", "PeerResponse",
        "BlockPropagate", "BlockRequest", "BlockResponse",
        "TransactionPropagate", "TransactionRequest",
        "ConsensusVote", "ConsensusProposal", "ConsensusCommit",
        "ShardRequest", "ShardResponse", "ShardSync",
        "DhtPing", "DhtFindNode", "DhtFindValue", "DhtStore",
        "IdentityVerify", "IdentityAttest",
        "TokenTransfer", "TokenMint",
        "GovernanceVote", "GovernanceProposal",
        "MeshRoute", "MeshRelay", "MeshDiscover",
        "OracleRequest", "OracleResponse", "OracleAttestation",
        "Heartbeat",
    ];
    let mut rng = rand::thread_rng();
    types[rng.gen_range(0..types.len())]
}

/// Generate a realistic ZK proof object (compact representation)
fn rand_zk_proof() -> Value {
    let mut rng = rand::thread_rng();
    let proof_size = rng.gen_range(128..512);
    let proof_bytes: Vec<u8> = (0..proof_size).map(|_| rng.gen()).collect();
    let public_inputs: Vec<u64> = (0..rng.gen_range(2..8)).map(|_| rng.gen_range(0..u64::MAX)).collect();
    json!({
        "proof_system": "Plonky2",
        "proof_data": hex::encode(&proof_bytes),
        "public_inputs": public_inputs,
        "verification_key": hex::encode(&proof_bytes[..64.min(proof_bytes.len())]),
        "circuit_digest": rand_hash()
    })
}

/// Generate a ZkTransactionProof (3 ZK proofs: amount, balance, nullifier)
fn rand_zk_tx_proof() -> Value {
    json!({
        "amount_proof": rand_zk_proof(),
        "balance_proof": rand_zk_proof(),
        "nullifier_proof": rand_zk_proof()
    })
}

/// Generate a compact public key representation (key_id + fingerprint)
fn rand_public_key() -> Value {
    let key_id = rand_key_id();
    // In real serialization, dilithium_pk is 2592 bytes and kyber_pk is 1568 bytes.
    // For test data, we include truncated hex representations that show the format.
    let mut rng = rand::thread_rng();
    let mut dilithium_sample = vec![0u8; 128]; // First 128 bytes of 2592
    let mut kyber_sample = vec![0u8; 64]; // First 64 bytes of 1568
    rng.fill(dilithium_sample.as_mut_slice());
    rng.fill(kyber_sample.as_mut_slice());
    json!({
        "key_id": key_id,
        "dilithium_pk_prefix": hex::encode(&dilithium_sample),
        "kyber_pk_prefix": hex::encode(&kyber_sample),
        "algorithm": "Dilithium5+Kyber1024",
        "size_bytes": 4192
    })
}

/// Generate a Signature object
fn rand_signature() -> Value {
    let mut rng = rand::thread_rng();
    let sig_size = rng.gen_range(2420..4627); // Dilithium5 signature range
    let sig_bytes: Vec<u8> = (0..128.min(sig_size)).map(|_| rng.gen()).collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({
        "signature": hex::encode(&sig_bytes),
        "signature_size": sig_size,
        "public_key": rand_public_key(),
        "algorithm": "Dilithium5",
        "timestamp": now - rng.gen_range(0..86400 * 30)
    })
}

/// Generate a UTXO TransactionInput
fn rand_tx_input() -> Value {
    json!({
        "previous_output": rand_hash(),
        "output_index": rand::thread_rng().gen_range(0..4u32),
        "nullifier": rand_hash(),
        "zk_proof": rand_zk_tx_proof()
    })
}

/// Generate a TransactionOutput
fn rand_tx_output() -> Value {
    json!({
        "commitment": rand_hash(),
        "note": rand_hash(),
        "recipient": rand_public_key()
    })
}

/// Base timestamp (2025-01-01 UTC)
fn base_timestamp() -> u64 {
    1735689600
}

// ============================================================================
// File generators
// ============================================================================

/// 1. Blockchain Transactions — 200 mixed-type transactions
fn generate_blockchain_transactions(dir: &Path) {
    let mut rng = rand::thread_rng();
    let mut txs = Vec::new();

    for i in 0..200 {
        let tx_type = rand_tx_type();
        let num_inputs = match tx_type {
            "Coinbase" | "IdentityRegistration" | "WalletRegistration" => 0,
            _ => rng.gen_range(1..4),
        };
        let num_outputs = rng.gen_range(1..5);

        let inputs: Vec<Value> = (0..num_inputs).map(|_| rand_tx_input()).collect();
        let outputs: Vec<Value> = (0..num_outputs).map(|_| rand_tx_output()).collect();

        let fee = match tx_type {
            "Coinbase" => 0u64,
            "IdentityRegistration" => 1000 + rng.gen_range(0..500),
            "TokenCreation" => 1000,
            "ContractDeployment" => rng.gen_range(500..5000),
            _ => 100 + rng.gen_range(0..200) * rng.gen_range(1..10),
        };

        let payload = generate_tx_payload(tx_type, i);

        let tx = json!({
            "version": 8,
            "chain_id": if rng.gen_bool(0.7) { 1 } else if rng.gen_bool(0.5) { 2 } else { 3 },
            "transaction_type": tx_type,
            "inputs": inputs,
            "outputs": outputs,
            "fee": fee,
            "signature": rand_signature(),
            "memo": if rng.gen_bool(0.3) {
                hex::encode(format!("tx-{}-{}", tx_type.to_lowercase(), i))
            } else {
                String::new()
            },
            "payload": payload,
            "tx_hash": hash_from(&format!("tx-{}", i)),
            "size_bytes": rng.gen_range(256..4096)
        });
        txs.push(tx);
    }

    let data = json!({
        "version": "sovereign-network-v8",
        "chain_id": 1,
        "network": "mainnet",
        "transaction_count": txs.len(),
        "transactions": txs
    });

    let path = dir.join("blockchain_transactions.json");
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

/// Generate transaction payload based on type
fn generate_tx_payload(tx_type: &str, idx: usize) -> Value {
    let mut rng = rand::thread_rng();
    match tx_type {
        "IdentityRegistration" | "IdentityUpdate" => json!({
            "Identity": {
                "did": rand_did(),
                "display_name": format!("Node-Operator-{}", idx),
                "public_key": hex::encode(&[rng.gen::<u8>(); 32]),
                "ownership_proof": hex::encode(&[rng.gen::<u8>(); 64]),
                "identity_type": pick(&["Individual", "Organization", "Validator", "EdgeNode"]),
                "did_document_hash": rand_hash(),
                "created_at": base_timestamp() + idx as u64 * 600,
                "registration_fee": 500 + rng.gen_range(0..500u64),
                "dao_fee": 100 + rng.gen_range(0..100u64),
                "controlled_nodes": (0..rng.gen_range(0..3)).map(|_| rand_hash()).collect::<Vec<_>>(),
                "owned_wallets": (0..rng.gen_range(1..4)).map(|_| rand_hash()).collect::<Vec<_>>()
            }
        }),
        "WalletRegistration" | "WalletUpdate" => json!({
            "Wallet": {
                "wallet_id": rand_hash(),
                "wallet_type": pick(&["Standard", "MultiSig", "DAO", "Validator"]),
                "wallet_name": format!("wallet-{}", idx),
                "alias": if rng.gen_bool(0.5) { Some(format!("w-{}", rng.gen_range(1000..9999))) } else { None },
                "public_key": hex::encode(&[rng.gen::<u8>(); 32]),
                "owner_identity_id": rand_hash(),
                "seed_commitment": rand_hash(),
                "created_at": base_timestamp() + idx as u64 * 300,
                "registration_fee": 100u64,
                "capabilities": rng.gen_range(1..255u32),
                "initial_balance": rng.gen_range(0..1_000_000u64)
            }
        }),
        "TokenTransfer" => json!({
            "TokenTransfer": {
                "token_id": rand_hash(),
                "from": rand_hash(),
                "to": rand_hash(),
                "amount": rng.gen_range(1..10_000_000u128),
                "nonce": rng.gen_range(0..100_000u64)
            }
        }),
        "TokenMint" => json!({
            "TokenMint": {
                "token_id": rand_hash(),
                "to": rand_hash(),
                "amount": rng.gen_range(1_000..100_000_000u128)
            }
        }),
        "DaoProposal" => json!({
            "DaoProposal": {
                "proposal_id": rand_hash(),
                "proposer": rand_did(),
                "title": format!("SIP-{}: {}", rng.gen_range(1..200), pick(&[
                    "Increase validator rewards",
                    "Reduce base fee to 50 SOV",
                    "Enable cross-shard atomic swaps",
                    "Deploy decentralized oracle committee",
                    "Upgrade BFT consensus threshold to 75%",
                    "Add LoRaWAN mesh routing support",
                    "Implement privacy-preserving UBI distribution",
                    "Migrate to Plonky3 proof system",
                ])),
                "description": format!("This proposal aims to improve the Sovereign Network by {}. \
                    The change will affect {} nodes and requires {} block confirmation period.",
                    pick(&["reducing latency", "improving throughput", "enhancing privacy",
                     "optimizing storage", "strengthening consensus"]),
                    rng.gen_range(100..10000),
                    rng.gen_range(1000..50000)
                ),
                "proposal_type": pick(&["ConfigUpdate", "CodeUpgrade", "TreasurySpend", "Emergency"]),
                "voting_period_blocks": rng.gen_range(10000..100000u64),
                "quorum_required": rng.gen_range(51..75u8),
                "execution_params": hex::encode(&(0..rng.gen_range(32..128)).map(|_| rng.gen::<u8>()).collect::<Vec<_>>()),
                "created_at": base_timestamp() + idx as u64 * 3600,
                "created_at_height": rng.gen_range(100000..500000u64)
            }
        }),
        "DaoVote" => json!({
            "DaoVote": {
                "vote_id": rand_hash(),
                "proposal_id": rand_hash(),
                "voter": rand_did(),
                "vote_choice": pick(&["Approve", "Reject", "Abstain"]),
                "voting_power": rng.gen_range(100..100000u64),
                "justification": if rng.gen_bool(0.4) {
                    Some(format!("This proposal {} the network's {}.",
                        pick(&["strengthens", "weakens", "improves", "maintains"]),
                        pick(&["security", "throughput", "decentralization", "incentive alignment"])
                    ))
                } else { None },
                "timestamp": base_timestamp() + idx as u64 * 1800
            }
        }),
        "UBIClaim" | "UbiDistribution" => json!({
            "UbiClaim": {
                "claim_id": rand_hash(),
                "claimant_identity": rand_did(),
                "month_index": rng.gen_range(0..36u64),
                "claim_amount": 500_000_000u64, // 500 SOV (in smallest unit)
                "recipient_wallet": rand_key_id(),
                "claimed_at": base_timestamp() + idx as u64 * 2592000,
                "claimed_at_height": rng.gen_range(100000..500000u64),
                "citizenship_proof": hex::encode(&[rng.gen::<u8>(); 64])
            }
        }),
        "ProfitDeclaration" => json!({
            "ProfitDeclaration": {
                "entity_id": rand_did(),
                "gross_revenue": rng.gen_range(10000..10_000_000u64),
                "net_profit": rng.gen_range(1000..5_000_000u64),
                "tax_period": format!("2025-Q{}", rng.gen_range(1..5)),
                "proof_of_income": hex::encode(&[rng.gen::<u8>(); 128]),
                "timestamp": base_timestamp() + idx as u64 * 7776000
            }
        }),
        "GovernanceConfigUpdate" => json!({
            "GovernanceConfigUpdate": {
                "target": rand_hash(),
                "field": rand_config_field(),
                "new_value_hash": rand_hash(),
                "activates_at": rng.gen_range(500000..1000000u64)
            }
        }),
        "ValidatorRegistration" | "ValidatorUpdate" | "ValidatorUnregister" => json!({
            "Validator": {
                "validator_id": rand_hash(),
                "stake_amount": rng.gen_range(100_000..10_000_000u64),
                "commission_rate": rng.gen_range(1..20u8),
                "operation": match tx_type {
                    "ValidatorRegistration" => "Register",
                    "ValidatorUpdate" => "Update",
                    _ => "Unregister",
                },
                "timestamp": base_timestamp() + idx as u64 * 3600,
                "endpoint": rand_addr(),
                "supported_protocols": vec!["ZHTP/1.1", "Mesh/2.0", "DHT/Kademlia"]
            }
        }),
        "BondingCurveBuy" | "BondingCurveSell" => json!({
            match tx_type {
                "BondingCurveBuy" => "BondingCurveBuy",
                _ => "BondingCurveSell",
            }: {
                "token_id": rand_hash(),
                "amount": rng.gen_range(100..1_000_000u128),
                "price_per_token": rng.gen_range(1..10000u64),
                "slippage_tolerance_bps": rng.gen_range(10..500u16),
                "sender": rand_hash()
            }
        }),
        "DaoExecution" => json!({
            "DaoExecution": {
                "proposal_id": rand_hash(),
                "executor": rand_did(),
                "execution_result": hex::encode(&[rng.gen::<u8>(); 32]),
                "block_height": rng.gen_range(100000..500000u64),
                "timestamp": base_timestamp() + idx as u64 * 7200
            }
        }),
        _ => json!("None"),
    }
}

/// 2. Blocks — 25 blocks with proper header chaining
fn generate_blocks(dir: &Path) {
    let mut rng = rand::thread_rng();
    let mut blocks = Vec::new();
    let mut prev_hash = "0".repeat(64); // Genesis previous hash

    for height in 0..25 {
        let tx_count = if height == 0 { 1 } else { rng.gen_range(5..20) };
        let timestamp = base_timestamp() + height * 15; // ~15 second blocks

        // Generate transaction summaries for each block
        let txs: Vec<Value> = (0..tx_count).map(|i| {
            let tx_type = if height == 0 && i == 0 { "Coinbase" } else { rand_tx_type() };
            json!({
                "tx_hash": hash_from(&format!("block-{}-tx-{}", height, i)),
                "transaction_type": tx_type,
                "fee": if tx_type == "Coinbase" { 0u64 } else { 100 + rng.gen_range(0..400) },
                "input_count": if tx_type == "Coinbase" { 0 } else { rng.gen_range(1..4) },
                "output_count": rng.gen_range(1..5u32),
                "size_bytes": rng.gen_range(200..2048u32)
            })
        }).collect();

        let total_fees: u64 = txs.iter()
            .map(|tx| tx["fee"].as_u64().unwrap_or(0))
            .sum();

        let block_hash = hash_from(&format!("block-{}", height));
        let merkle_root = hash_from(&format!("merkle-{}", height));
        let state_root = hash_from(&format!("state-{}", height));
        let verification_root = hash_from(&format!("verify-{}", height));
        let bft_quorum_root = hash_from(&format!("bft-{}", height));

        let block = json!({
            "header": {
                "version": 1,
                "previous_hash": prev_hash,
                "data_helix_root": merkle_root,
                "verification_helix_root": verification_root,
                "state_root": state_root,
                "bft_quorum_root": bft_quorum_root,
                "timestamp": timestamp,
                "height": height,
                "block_hash": block_hash
            },
            "transactions": txs,
            "transaction_count": tx_count,
            "total_fees": total_fees,
            "fee_distribution": {
                "ubi_pool_45pct": (total_fees as f64 * 0.45) as u64,
                "consensus_30pct": (total_fees as f64 * 0.30) as u64,
                "governance_15pct": (total_fees as f64 * 0.15) as u64,
                "treasury_10pct": (total_fees as f64 * 0.10) as u64
            },
            "block_size_bytes": rng.gen_range(4096..65536u32),
            "validator": rand_key_id()
        });

        prev_hash = block_hash;
        blocks.push(block);
    }

    let data = json!({
        "version": "sovereign-network-v1",
        "chain": "mainnet",
        "block_count": blocks.len(),
        "latest_height": blocks.len() - 1,
        "blocks": blocks
    });

    let path = dir.join("blocks.json");
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

/// 3. Governance Proposals — 30 proposals with voting and config changes
fn generate_governance_proposals(dir: &Path) {
    let mut rng = rand::thread_rng();
    let mut proposals = Vec::new();
    let mut pending_changes = Vec::new();
    let mut vote_records = Vec::new();

    let proposal_titles = [
        "Reduce base transaction fee from 100 to 50 SOV",
        "Increase maximum block size to 2MB",
        "Enable cross-shard atomic swap protocol",
        "Deploy decentralized price oracle committee",
        "Implement privacy-preserving UBI verification",
        "Upgrade consensus threshold to 75% BFT",
        "Add Bluetooth mesh routing for edge nodes",
        "Migrate ZK proofs to Plonky3 system",
        "Increase validator minimum stake to 500K SOV",
        "Enable bonding curve token launches",
        "Add LoRaWAN long-range mesh support",
        "Implement progressive tax on profit declarations",
        "Deploy automated treasury rebalancing",
        "Add multi-signature wallet support",
        "Enable encrypted memo field for privacy",
        "Reduce block time to 10 seconds",
        "Implement fee burning mechanism (50% burn)",
        "Add identity recovery via social attestation",
        "Deploy on-chain employment contract system",
        "Enable WiFi-Direct peer discovery protocol",
        "Increase UBI base amount to 750 SOV/month",
        "Add cross-chain bridge to Sovereign L2",
        "Implement reputation-weighted voting",
        "Deploy shard compression with ZK witnesses",
        "Enable quantum-resistant key rotation",
        "Add decentralized DNS resolver",
        "Implement storage pruning protocol",
        "Deploy neural mesh optimization layer",
        "Add community governance veto mechanism",
        "Enable dynamic difficulty adjustment",
    ];

    for (i, title) in proposal_titles.iter().enumerate() {
        let proposal_id = hash_from(&format!("proposal-{}", i));
        let status = pick(&["Active", "Passed", "Rejected", "Pending", "Executed"]);

        let votes_for = rng.gen_range(1000..100000u64);
        let votes_against = rng.gen_range(100..votes_for);
        let votes_abstain = rng.gen_range(0..votes_for / 10);
        let total_voting_power = votes_for + votes_against + votes_abstain;

        proposals.push(json!({
            "proposal_id": proposal_id,
            "proposer": rand_did(),
            "title": title,
            "description": format!(
                "{} This change was proposed to address concerns about {}. \
                 Implementation requires {} blocks for activation after approval. \
                 Estimated impact: {} active nodes affected.",
                title,
                pick(&["network throughput", "fee fairness", "validator incentives",
                 "cross-shard latency", "identity privacy"]),
                rng.gen_range(10000..100000),
                rng.gen_range(500..50000)
            ),
            "proposal_type": pick(&["ConfigUpdate", "ProtocolUpgrade", "TreasurySpend",
                             "Emergency", "ParameterChange"]),
            "status": status,
            "voting_period_blocks": rng.gen_range(10000..100000u64),
            "quorum_required": rng.gen_range(51..75u8),
            "voting_summary": {
                "votes_for": votes_for,
                "votes_against": votes_against,
                "votes_abstain": votes_abstain,
                "total_voting_power": total_voting_power,
                "participation_rate": format!("{:.2}%",
                    total_voting_power as f64 / rng.gen_range(200000..1000000) as f64 * 100.0),
                "quorum_met": rng.gen_bool(0.7)
            },
            "created_at_height": rng.gen_range(100000..400000u64),
            "created_at": base_timestamp() + i as u64 * 86400,
            "execution_params": if status == "Executed" {
                Some(hex::encode(&(0..rng.gen_range(32..128)).map(|_| rng.gen::<u8>()).collect::<Vec<_>>()))
            } else { None }
        }));

        // Add pending config change if status is Passed/Pending
        if status == "Passed" || status == "Pending" {
            let field = rand_config_field();
            pending_changes.push(json!({
                "target": rand_hash(), // TokenId
                "field": field,
                "new_value_hash": rand_hash(),
                "submitted_at": rng.gen_range(200000..400000u64),
                "activates_at": rng.gen_range(400000..600000u64),
                "tx_hash": hash_from(&format!("gov-tx-{}", i))
            }));
        }

        // Generate 5-15 vote records per proposal
        let num_votes = rng.gen_range(5..15);
        for v in 0..num_votes {
            vote_records.push(json!({
                "vote_id": hash_from(&format!("vote-{}-{}", i, v)),
                "proposal_id": proposal_id,
                "voter": rand_did(),
                "vote_choice": pick(&["Approve", "Reject", "Abstain"]),
                "voting_power": rng.gen_range(100..50000u64),
                "justification": if rng.gen_bool(0.3) {
                    Some(format!("This proposal {} the network's {} and should be {}.",
                        pick(&["strengthens", "threatens", "improves", "maintains"]),
                        pick(&["security posture", "economic model", "decentralization",
                         "validator incentives", "user privacy"]),
                        pick(&["approved", "rejected", "amended"])
                    ))
                } else { None },
                "timestamp": base_timestamp() + (i * 86400 + v * 3600) as u64
            }));
        }
    }

    let data = json!({
        "version": "sovereign-governance-v1",
        "proposal_count": proposals.len(),
        "proposals": proposals,
        "pending_changes": pending_changes,
        "vote_records": vote_records,
        "config_fields": [
            "TransferFeeBps", "BurnFeeBps", "FeeCap", "MinFee",
            "TransferPolicy", "FeeRecipient", "TreasuryAddress",
            "MaxSupply", "AuthorityAdd", "AuthorityRemove",
            "BlockSizeLimit", "TxCountLimit", "BaseFeePerByte"
        ]
    });

    let path = dir.join("governance_proposals.json");
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

/// 4. Shard Manifests — ZkWitness objects with Merkle proofs
fn generate_shard_manifests(dir: &Path) {
    let mut rng = rand::thread_rng();
    let mut witnesses = Vec::new();

    let mime_types = [
        "application/octet-stream", "application/json", "text/plain",
        "image/png", "application/wasm", "application/x-sovereign-block",
        "application/x-sovereign-state", "application/x-zhtp-payload",
    ];

    let file_names = [
        "block_archive_2025Q1.dat", "state_snapshot_h450000.bin",
        "contract_bytecode_dex.wasm", "identity_batch_export.json",
        "shard_replica_node42.dat", "merkle_tree_state.bin",
        "validator_attestations.json", "ubi_distribution_batch.dat",
        "token_ledger_snapshot.bin", "governance_vote_archive.json",
        "dht_routing_backup.dat", "mesh_topology_map.bin",
        "oracle_price_feed.json", "cross_shard_proofs.dat",
        "neural_mesh_model_v3.bin", "compression_dictionary.dat",
        "edge_node_cache_shard.bin", "bluetooth_mesh_state.dat",
        "lorawan_routing_table.bin", "privacy_set_accumulator.dat",
    ];

    for i in 0..40 {
        let num_shards = rng.gen_range(4..32);
        let file_size: u64 = rng.gen_range(1024..10_485_760); // 1KB - 10MB
        let avg_shard_size = file_size as usize / num_shards;

        let shard_ids: Vec<Value> = (0..num_shards).map(|s| {
            json!(rand_hash()) // ShardId is [u8; 32]
        }).collect();

        let shard_offsets: Vec<usize> = (0..num_shards)
            .map(|s| s * avg_shard_size)
            .collect();

        let zk_proof = if rng.gen_bool(0.8) {
            Some(json!({
                "proof_data": hex::encode(&(0..rng.gen_range(256..1024))
                    .map(|_| rng.gen::<u8>()).collect::<Vec<_>>()),
                "public_inputs": (0..rng.gen_range(4..12))
                    .map(|_| rng.gen_range(0..u64::MAX)).collect::<Vec<u64>>(),
                "verification_key": hex::encode(&(0..128)
                    .map(|_| rng.gen::<u8>()).collect::<Vec<_>>()),
                "circuit_digest": rand_hash()
            }))
        } else {
            None
        };

        witnesses.push(json!({
            "version": 1,
            "root_hash": rand_hash(),
            "shard_ids": shard_ids,
            "shard_count": num_shards,
            "merkle_root": rand_hash(),
            "metadata": {
                "name": file_names[i % file_names.len()],
                "size": file_size,
                "shard_count": num_shards,
                "avg_shard_size": avg_shard_size,
                "created_at": base_timestamp() + i as u64 * 7200,
                "mime_type": mime_types[rng.gen_range(0..mime_types.len())],
                "shard_offsets": shard_offsets
            },
            "zk_proof": zk_proof,
            "compression_stats": {
                "original_size": file_size,
                "compressed_size": (file_size as f64 * rng.gen_range(0.05..0.6)) as u64,
                "ratio": format!("{:.2}:1", 1.0 / rng.gen_range(0.05..0.6)),
                "strategy": pick(&["SFC0", "SFC1", "SFC4", "SFC7", "ZKC_SFC7", "PureSFC"]),
                "weissman_score": format!("{:.2}", rng.gen_range(1.5..8.0f64))
            }
        }));
    }

    let data = json!({
        "version": "sovereign-compression-v1",
        "witness_count": witnesses.len(),
        "witnesses": witnesses,
        "shard_storage_summary": {
            "total_shards": witnesses.iter()
                .map(|w| w["shard_count"].as_u64().unwrap_or(0))
                .sum::<u64>(),
            "total_original_bytes": witnesses.iter()
                .map(|w| w["compression_stats"]["original_size"].as_u64().unwrap_or(0))
                .sum::<u64>(),
            "total_compressed_bytes": witnesses.iter()
                .map(|w| w["compression_stats"]["compressed_size"].as_u64().unwrap_or(0))
                .sum::<u64>()
        }
    });

    let path = dir.join("shard_manifests.json");
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

/// 5. Network Mesh Messages — 100 MeshMessageEnvelope objects
fn generate_network_messages(dir: &Path) {
    let mut rng = rand::thread_rng();
    let mut messages = Vec::new();

    for i in 0..100 {
        let msg_type = rand_message_type();
        let hop_count: u8 = rng.gen_range(0..8);
        let route_history: Vec<String> = (0..hop_count)
            .map(|_| rand_key_id())
            .collect();

        let payload_size = match msg_type {
            "Heartbeat" | "DhtPing" => rng.gen_range(16..64),
            "BlockPropagate" => rng.gen_range(4096..65536),
            "TransactionPropagate" => rng.gen_range(256..4096),
            "ShardResponse" => rng.gen_range(1024..32768),
            _ => rng.gen_range(64..2048),
        };

        let payload_sample: Vec<u8> = (0..128.min(payload_size))
            .map(|_| rng.gen())
            .collect();

        messages.push(json!({
            "message_id": rng.gen_range(1..u64::MAX),
            "origin": rand_public_key(),
            "destination": rand_public_key(),
            "ttl": rng.gen_range(8..32u8),
            "hop_count": hop_count,
            "route_history": route_history,
            "timestamp": base_timestamp() + i as u64 * rng.gen_range(1..30),
            "message_type": msg_type,
            "payload_size": payload_size,
            "payload_preview": hex::encode(&payload_sample),
            "encryption": {
                "algorithm": "Kyber1024-AES256-GCM",
                "nonce": hex::encode(&[rng.gen::<u8>(); 12]),
                "encrypted": rng.gen_bool(0.8)
            },
            "routing": {
                "protocol": pick(&["Direct", "Mesh", "DHT", "Flood"]),
                "priority": rng.gen_range(1..5u8),
                "qos": {
                    "min_bandwidth_kbps": rng.gen_range(10..10000u32),
                    "max_latency_ms": rng.gen_range(10..5000u32),
                    "reliability_requirement": format!("{:.3}", rng.gen_range(0.9..1.0f64))
                }
            }
        }));
    }

    let data = json!({
        "version": "sovereign-mesh-v2",
        "message_count": messages.len(),
        "capture_period": {
            "start": base_timestamp(),
            "end": base_timestamp() + 3600,
            "duration_seconds": 3600
        },
        "messages": messages,
        "message_type_distribution": {
            "PeerDiscovery": rng.gen_range(10..30),
            "BlockPropagate": rng.gen_range(5..15),
            "TransactionPropagate": rng.gen_range(20..50),
            "ConsensusVote": rng.gen_range(10..25),
            "Heartbeat": rng.gen_range(30..60),
            "ShardSync": rng.gen_range(5..20),
            "DhtFindNode": rng.gen_range(10..30)
        }
    });

    let path = dir.join("network_mesh_messages.json");
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

/// 6. Identity Records — 50 DID registrations
fn generate_identity_records(dir: &Path) {
    let mut rng = rand::thread_rng();
    let mut identities = Vec::new();

    let identity_types = ["Individual", "Organization", "Validator",
                          "EdgeNode", "ServiceProvider", "GovernmentEntity"];
    let jurisdictions = ["US-CA", "DE-BY", "JP-13", "SG", "CH-ZH",
                         "GB-LND", "KR-11", "AU-NSW", "BR-SP", "IN-MH"];
    let credential_types = ["CitizenshipProof", "AgeVerification",
                           "IncomeAttestation", "ValidatorCertification",
                           "KYCBasic", "KYCAml", "OrganizationRegistry"];

    for i in 0..50 {
        let did = rand_did();
        let identity_type = identity_types[rng.gen_range(0..identity_types.len())];
        let is_validator = identity_type == "Validator";
        let num_credentials = rng.gen_range(1..5);
        let num_wallets = rng.gen_range(1..4);
        let num_attestations = rng.gen_range(0..6);

        let credentials: Vec<Value> = (0..num_credentials).map(|_| {
            let cred_type = credential_types[rng.gen_range(0..credential_types.len())];
            json!({
                "credential_type": cred_type,
                "issuer": rand_did(),
                "issued_at": base_timestamp() + rng.gen_range(0..86400 * 365) as u64,
                "expires_at": base_timestamp() + rng.gen_range(86400 * 365..86400 * 730) as u64,
                "zk_proof": hex::encode(&(0..rng.gen_range(64..256))
                    .map(|_| rng.gen::<u8>()).collect::<Vec<_>>()),
                "revoked": rng.gen_bool(0.05)
            })
        }).collect();

        let wallets: Vec<Value> = (0..num_wallets).map(|w| {
            json!({
                "wallet_id": rand_hash(),
                "wallet_type": pick(&["Standard", "MultiSig", "DAO", "Validator"]),
                "wallet_name": format!("{}-wallet-{}", did.split(':').last().unwrap_or("x")[..8].to_string(), w),
                "balance": rng.gen_range(0..50_000_000u64),
                "created_at": base_timestamp() + rng.gen_range(0..86400 * 180) as u64
            })
        }).collect();

        let attestations: Vec<Value> = (0..num_attestations).map(|_| {
            json!({
                "attester": rand_did(),
                "attestation_type": pick(&["IdentityVerification", "ReputationEndorsement",
                                     "SkillCertification", "KYCAttestation"]),
                "timestamp": base_timestamp() + rng.gen_range(0..86400 * 365) as u64,
                "signature": hex::encode(&(0..rng.gen_range(64..128))
                    .map(|_| rng.gen::<u8>()).collect::<Vec<_>>()),
                "expires_at": base_timestamp() + rng.gen_range(86400 * 365..86400 * 1095) as u64
            })
        }).collect();

        identities.push(json!({
            "did": did,
            "identity_type": identity_type,
            "public_key": rand_public_key(),
            "node_id": rand_hash(),
            "primary_device": format!("device-{}", hex::encode(&[rng.gen::<u8>(); 4])),
            "device_count": rng.gen_range(1..5u32),
            "reputation": rng.gen_range(0..10000u64),
            "age": if rng.gen_bool(0.7) { Some(rng.gen_range(18..80)) } else { None::<u32> },
            "access_level": pick(&["Basic", "Verified", "Premium", "Validator", "Admin"]),
            "credentials": credentials,
            "wallets": wallets,
            "attestations": attestations,
            "dao_member_id": format!("dao-member-{}", rng.gen_range(1000..99999)),
            "dao_voting_power": if is_validator {
                rng.gen_range(10000..100000u64)
            } else {
                rng.gen_range(100..10000u64)
            },
            "citizenship_verified": rng.gen_bool(0.6),
            "jurisdiction": if rng.gen_bool(0.8) {
                Some(jurisdictions[rng.gen_range(0..jurisdictions.len())])
            } else { None::<&str> },
            "created_at": base_timestamp() + i as u64 * 3600,
            "last_active": base_timestamp() + rng.gen_range(0..86400 * 30) as u64,
            "metadata": {
                "display_name": format!("Node-Operator-{}", i),
                "bio": if rng.gen_bool(0.5) {
                    Some(format!("Sovereign Network {} since block {}.",
                        identity_type.to_lowercase(),
                        rng.gen_range(1000..100000)
                    ))
                } else { None::<String> },
                "avatar_hash": if rng.gen_bool(0.3) { Some(rand_hash()) } else { None::<String> }
            }
        }));
    }

    let data = json!({
        "version": "sovereign-identity-v1",
        "did_prefix": "did:zhtp:",
        "identity_count": identities.len(),
        "identities": identities,
        "network_stats": {
            "total_identities": identities.len(),
            "validators": identities.iter()
                .filter(|id| id["identity_type"] == "Validator")
                .count(),
            "citizenship_verified": identities.iter()
                .filter(|id| id["citizenship_verified"] == true)
                .count(),
            "total_wallets": identities.iter()
                .map(|id| id["wallets"].as_array().map(|w| w.len()).unwrap_or(0))
                .sum::<usize>()
        }
    });

    let path = dir.join("identity_records.json");
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

/// 7. Token Economics — CBE allocations, UBI distribution, token operations
fn generate_token_economics(dir: &Path) {
    let mut rng = rand::thread_rng();

    // CBE Token Allocation Ledger (real structure from lib-economy)
    let cbe_ledger = json!({
        "cbe_token": {
            "name": "Sovereign Network CBE Token",
            "symbol": "CBE",
            "total_supply": 100_000_000_000u64,
            "initialized": true,
            "allocation_buckets": {
                "Compensation": {
                    "bucket_id": 1,
                    "allocated": 40_000_000_000u64,
                    "distributed": rng.gen_range(1_000_000_000u64..10_000_000_000),
                    "remaining": 0u64, // will be calculated
                    "description": "Employee and contributor compensation (40%)"
                },
                "Treasury": {
                    "bucket_id": 2,
                    "allocated": 30_000_000_000u64,
                    "distributed": rng.gen_range(500_000_000u64..5_000_000_000),
                    "remaining": 0u64,
                    "description": "Operational treasury for network development (30%)"
                },
                "Performance": {
                    "bucket_id": 3,
                    "allocated": 20_000_000_000u64,
                    "distributed": rng.gen_range(200_000_000u64..2_000_000_000),
                    "remaining": 0u64,
                    "description": "Performance incentives for validators and nodes (20%)"
                },
                "Reserves": {
                    "bucket_id": 4,
                    "allocated": 10_000_000_000u64,
                    "distributed": rng.gen_range(100_000_000u64..1_000_000_000),
                    "remaining": 0u64,
                    "description": "Strategic reserves for emergency and growth (10%)"
                }
            }
        }
    });

    // SOV Token info
    let sov_token = json!({
        "sov_token": {
            "name": "Sovereign",
            "symbol": "SOV",
            "decimals": 9,
            "token_id": "0".repeat(64), // TokenId::NATIVE = all zeros
            "max_supply": "18_446_744_073_709_551_615", // u64::MAX
            "fee_config": {
                "base_fee": 100,
                "bytes_per_sov": 100,
                "witness_cap": 500,
                "token_creation_fee": 1000
            }
        }
    });

    // UBI Distribution Records (monthly claims)
    let mut ubi_claims = Vec::new();
    for month in 0..12 {
        let num_claims = rng.gen_range(100..500);
        let claims: Vec<Value> = (0..num_claims.min(20)).map(|c| {
            json!({
                "claim_id": hash_from(&format!("ubi-{}-{}", month, c)),
                "claimant": rand_did(),
                "month_index": month,
                "amount": 500_000_000u64, // 500 SOV base UBI
                "recipient_wallet": rand_hash(),
                "claimed_at_height": rng.gen_range(100000..500000u64),
                "citizenship_proof_valid": rng.gen_bool(0.95)
            })
        }).collect();

        ubi_claims.push(json!({
            "month_index": month,
            "month_label": format!("2025-{:02}", month + 1),
            "total_claims": num_claims,
            "total_distributed": num_claims as u64 * 500_000_000,
            "sample_claims": claims
        }));
    }

    // Token transfer history
    let mut transfers = Vec::new();
    for i in 0..50 {
        transfers.push(json!({
            "tx_hash": hash_from(&format!("token-tx-{}", i)),
            "token_id": if rng.gen_bool(0.7) {
                "0".repeat(64) // SOV native
            } else {
                rand_hash() // Custom token
            },
            "from": rand_hash(),
            "to": rand_hash(),
            "amount": rng.gen_range(100..10_000_000u128),
            "fee": 100 + rng.gen_range(0..200u64),
            "nonce": rng.gen_range(0..10000u64),
            "block_height": rng.gen_range(100000..500000u64),
            "timestamp": base_timestamp() + i as u64 * rng.gen_range(60..3600)
        }));
    }

    // Bonding curve tokens
    let mut bonding_curves = Vec::new();
    for i in 0..5 {
        bonding_curves.push(json!({
            "token_id": rand_hash(),
            "name": format!("Community Token {}", ['A', 'B', 'C', 'D', 'E'][i]),
            "symbol": format!("CT{}", ['A', 'B', 'C', 'D', 'E'][i]),
            "curve_type": "LinearBonding",
            "initial_price": rng.gen_range(1..100u64),
            "current_price": rng.gen_range(100..10000u64),
            "total_supply": rng.gen_range(1_000_000..100_000_000u128),
            "market_cap": rng.gen_range(10_000_000..1_000_000_000u128),
            "graduated": rng.gen_bool(0.2),
            "creator": rand_did(),
            "created_at_height": rng.gen_range(50000..200000u64)
        }));
    }

    let data = json!({
        "version": "sovereign-economy-v1",
        "cbe_ledger": cbe_ledger,
        "sov_token": sov_token,
        "ubi_distribution": {
            "base_amount_per_month": 500_000_000u64,
            "monthly_records": ubi_claims
        },
        "token_transfers": transfers,
        "bonding_curves": bonding_curves
    });

    let path = dir.join("token_economics.json");
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

/// 8. Network Metrics — CSV format, 3000 rows
fn generate_network_metrics(dir: &Path) {
    let mut rng = rand::thread_rng();
    let mut csv = String::from(
        "timestamp,node_id,node_type,response_time_ms,bandwidth_kbps,\
         success_rate,corruption_rate,participation_rate,reputation,\
         peer_count,shard_count,block_height,memory_mb,cpu_pct,\
         uptime_hours,region\n"
    );

    let regions = ["us-east-1", "eu-west-1", "ap-southeast-1", "us-west-2",
                    "eu-central-1", "ap-northeast-1", "sa-east-1", "af-south-1",
                    "me-south-1", "ap-south-1"];
    let node_types = ["Validator", "FullNode", "EdgeNode", "LightClient",
                      "MeshRelay", "ArchiveNode"];

    // Generate 60 unique node IDs
    let node_ids: Vec<String> = (0..60).map(|i| {
        hash_from(&format!("node-{}", i))[..16].to_string()
    }).collect();

    for row in 0..3000 {
        let node_idx = row % 60;
        let node_id = &node_ids[node_idx];
        let node_type = node_types[node_idx % node_types.len()];
        let region = regions[node_idx % regions.len()];
        let timestamp = base_timestamp() + (row as u64 / 60) * 60; // One reading per minute

        let base_latency: f64 = match node_type {
            "Validator" => 5.0,
            "FullNode" => 15.0,
            "EdgeNode" => 50.0,
            "LightClient" => 100.0,
            "MeshRelay" => 30.0,
            "ArchiveNode" => 25.0,
            _ => 50.0,
        };

        let response_time = (base_latency + rng.gen_range(-base_latency * 0.3..base_latency * 2.0)).max(1.0);

        let bandwidth = match node_type {
            "Validator" => rng.gen_range(50000..200000u32),
            "FullNode" => rng.gen_range(10000..100000),
            "EdgeNode" => rng.gen_range(1000..20000),
            "LightClient" => rng.gen_range(500..5000),
            "MeshRelay" => rng.gen_range(5000..50000),
            "ArchiveNode" => rng.gen_range(20000..150000),
            _ => rng.gen_range(1000..50000),
        };

        let success_rate = rng.gen_range(0.95..1.0f64);
        let corruption_rate = rng.gen_range(0.0..0.005f64);
        let participation_rate = match node_type {
            "Validator" => rng.gen_range(0.90..1.0),
            _ => rng.gen_range(0.5..1.0f64),
        };
        let reputation = rng.gen_range(5000..10000u64);
        let peer_count = rng.gen_range(8..256u32);
        let shard_count = match node_type {
            "ArchiveNode" => rng.gen_range(100..1000u32),
            "Validator" => rng.gen_range(50..500),
            "FullNode" => rng.gen_range(20..200),
            _ => rng.gen_range(5..50),
        };
        let block_height = 450000 + (row as u64 / 60) * 4; // ~4 blocks per minute
        let memory_mb = rng.gen_range(256..8192u32);
        let cpu_pct = rng.gen_range(5.0..95.0f64);
        let uptime_hours = rng.gen_range(1..8760u32); // Up to 1 year

        csv.push_str(&format!(
            "{},{},{},{:.1},{},{:.4},{:.6},{:.4},{},{},{},{},{},{:.1},{},{}\n",
            timestamp, node_id, node_type, response_time, bandwidth,
            success_rate, corruption_rate, participation_rate, reputation,
            peer_count, shard_count, block_height, memory_mb, cpu_pct,
            uptime_hours, region
        ));
    }

    let path = dir.join("network_metrics.csv");
    fs::write(&path, csv).unwrap();
}

/// 9. DHT Routing — Kademlia routing table with 20-byte UIDs
fn generate_dht_routing(dir: &Path) {
    let mut rng = rand::thread_rng();

    let local_uid = rand_uid();
    let mut buckets = Vec::new();

    // Kademlia: 160 buckets (1 per bit), but most are empty
    // Typically only ~20-40 buckets have entries
    for bucket_idx in 0..160 {
        // Closer buckets are denser (more likely to have entries)
        let has_entries = if bucket_idx < 10 {
            rng.gen_bool(0.9)
        } else if bucket_idx < 40 {
            rng.gen_bool(0.6)
        } else if bucket_idx < 80 {
            rng.gen_bool(0.2)
        } else {
            rng.gen_bool(0.05)
        };

        if has_entries {
            let k = 8; // Standard Kademlia k-bucket size
            let entry_count = rng.gen_range(1..=k);
            let entries: Vec<Value> = (0..entry_count).map(|_| {
                let now_ms = base_timestamp() as u128 * 1000
                    + rng.gen_range(0..86400000u128);
                json!({
                    "uid": rand_uid(),
                    "address": {
                        "ip": rand_addr(),
                        "transport": pick(&["Udp", "Tcp", "Quic"])
                    },
                    "stale": rng.gen_range(0..5u32),
                    "last_seen": now_ms,
                    "rtt_ms": rng.gen_range(5..500u32),
                    "verified": rng.gen_bool(0.8)
                })
            }).collect();

            buckets.push(json!({
                "bucket_index": bucket_idx,
                "prefix_length": bucket_idx,
                "entries": entries,
                "entry_count": entry_count,
                "last_updated": base_timestamp() + rng.gen_range(0..3600u64)
            }));
        }
    }

    // Pending operations (find_node, find_value in progress)
    let mut pending_ops = Vec::new();
    for i in 0..rng.gen_range(3..10) {
        pending_ops.push(json!({
            "operation_id": rng.gen_range(1..10000u64),
            "operation_type": pick(&["FindNode", "FindValue", "Store", "Ping"]),
            "target": rand_uid(),
            "started_at": base_timestamp() + rng.gen_range(0..60u64),
            "timeout_ms": rng.gen_range(5000..30000u32),
            "responses_received": rng.gen_range(0..8u32),
            "closest_nodes": (0..rng.gen_range(0..5)).map(|_| rand_uid()).collect::<Vec<_>>()
        }));
    }

    let data = json!({
        "version": "sovereign-dht-v1",
        "routing_type": "Kademlia",
        "id_length_bytes": 20,
        "k_bucket_size": 8,
        "local_node": {
            "uid": local_uid,
            "address": rand_addr(),
            "uptime_seconds": rng.gen_range(3600..86400 * 30),
            "total_queries": rng.gen_range(10000..1000000u64),
            "total_stored_values": rng.gen_range(100..50000u64)
        },
        "routing_table": {
            "bucket_type": "Kademlia",
            "total_buckets": 160,
            "active_buckets": buckets.len(),
            "total_nodes": buckets.iter()
                .map(|b| b["entry_count"].as_u64().unwrap_or(0))
                .sum::<u64>(),
            "buckets": buckets
        },
        "pending_operations": pending_ops,
        "statistics": {
            "queries_per_second": rng.gen_range(10..500u32),
            "avg_lookup_hops": format!("{:.2}", rng.gen_range(2.0..6.0f64)),
            "avg_lookup_ms": rng.gen_range(50..500u32),
            "replication_factor": 3,
            "refresh_interval_ms": 3600000
        }
    });

    let path = dir.join("dht_routing.json");
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
}

/// 10. Validator Event Log — structured text log format
fn generate_validator_log(dir: &Path) {
    let mut rng = rand::thread_rng();
    let mut log = String::new();

    let log_levels = ["INFO", "INFO", "INFO", "WARN", "DEBUG", "ERROR", "INFO", "INFO"];
    let components = [
        "consensus::bft", "network::mesh", "validator::attestation",
        "blockchain::block", "dht::routing", "identity::verification",
        "compression::sfc", "governance::voting", "economy::ubi",
        "mempool::selection", "storage::sled", "protocol::zhtp",
        "neural_mesh::router", "proofs::plonky2", "tokens::bonding_curve",
    ];

    // Generate node IDs for log entries
    let node_ids: Vec<String> = (0..8).map(|i| {
        hash_from(&format!("validator-{}", i))[..16].to_string()
    }).collect();

    for i in 0..5000 {
        let timestamp = base_timestamp() + (i as u64 / 10); // ~10 events per second
        let ms = rng.gen_range(0..999);
        let level = log_levels[rng.gen_range(0..log_levels.len())];
        let component = components[rng.gen_range(0..components.len())];
        let node_id = &node_ids[rng.gen_range(0..node_ids.len())];

        // Format: 2025-01-01T00:00:00.000Z [LEVEL] component{node=...} message key=value ...
        let (message, kvs) = generate_log_entry(component, level, &mut rng, node_id);

        let log_line = format!(
            "{}T{:02}:{:02}:{:02}.{:03}Z [{}] {} node={} {}{}\n",
            "2025-01-01",
            (timestamp / 3600) % 24,
            (timestamp / 60) % 60,
            timestamp % 60,
            ms,
            level,
            component,
            node_id,
            message,
            kvs
        );
        log.push_str(&log_line);
    }

    let path = dir.join("validator_events.log");
    fs::write(&path, log).unwrap();
}

/// Generate a realistic log message for a given component
fn generate_log_entry(
    component: &str,
    level: &str,
    rng: &mut rand::rngs::ThreadRng,
    node_id: &str,
) -> (String, String) {
    match component {
        "consensus::bft" => {
            let events = [
                ("received pre-commit vote", format!(" round={} height={} from={} vote=accept", rng.gen_range(0..5), rng.gen_range(400000..500000u64), &rand_key_id()[..16])),
                ("block proposal accepted", format!(" height={} txs={} size={}KB hash={}", rng.gen_range(400000..500000u64), rng.gen_range(5..50), rng.gen_range(10..256), &rand_hash()[..16])),
                ("quorum reached", format!(" round={} validators={}/{} threshold=75%", rng.gen_range(0..3), rng.gen_range(50..100), rng.gen_range(80..120))),
                ("finalized block", format!(" height={} latency={}ms txs={}", rng.gen_range(400000..500000u64), rng.gen_range(100..5000), rng.gen_range(1..100))),
            ];
            let (msg, kvs) = &events[rng.gen_range(0..events.len())];
            (msg.to_string(), kvs.clone())
        },
        "network::mesh" => {
            let events = [
                ("peer connected", format!(" addr={} transport={} latency={}ms", rand_addr(), ["tcp", "quic", "udp"][rng.gen_range(0..3)], rng.gen_range(5..200))),
                ("peer disconnected", format!(" addr={} reason={} duration={}s", rand_addr(), ["timeout", "reset", "graceful"][rng.gen_range(0..3)], rng.gen_range(60..86400))),
                ("mesh route discovered", format!(" hops={} target={} path_latency={}ms", rng.gen_range(1..8), &rand_key_id()[..16], rng.gen_range(20..500))),
                ("message relayed", format!(" type={} size={} ttl={} hop={}", rand_message_type(), rng.gen_range(100..10000), rng.gen_range(8..32), rng.gen_range(0..8))),
            ];
            let (msg, kvs) = &events[rng.gen_range(0..events.len())];
            (msg.to_string(), kvs.clone())
        },
        "blockchain::block" => {
            let events = [
                ("appended block to chain", format!(" height={} hash={} txs={} fees={}SOV", rng.gen_range(400000..500000u64), &rand_hash()[..16], rng.gen_range(1..100), rng.gen_range(100..50000))),
                ("validated block header", format!(" height={} prev={} elapsed={}ms", rng.gen_range(400000..500000u64), &rand_hash()[..16], rng.gen_range(1..50))),
                ("processing transactions", format!(" count={} batch={} parallel=true", rng.gen_range(5..100), rng.gen_range(1..10))),
            ];
            let (msg, kvs) = &events[rng.gen_range(0..events.len())];
            (msg.to_string(), kvs.clone())
        },
        "compression::sfc" => {
            let events = [
                ("compressed shard", format!(" strategy=SFC7 ratio={:.2}:1 weissman={:.2} elapsed={}ms size_in={}KB size_out={}KB", rng.gen_range(2.0..15.0f64), rng.gen_range(1.5..8.0f64), rng.gen_range(10..2000), rng.gen_range(10..2048), rng.gen_range(1..512))),
                ("decompressed shard", format!(" elapsed={}ms verified=true hash={}", rng.gen_range(1..50), &rand_hash()[..16])),
                ("neural mesh optimization", format!(" rl_action={} confidence={:.1}% anomaly={:.4}", rng.gen_range(0..10), rng.gen_range(10.0..95.0f64), rng.gen_range(0.0..0.5f64))),
            ];
            let (msg, kvs) = &events[rng.gen_range(0..events.len())];
            (msg.to_string(), kvs.clone())
        },
        "economy::ubi" => {
            let events = [
                ("processed UBI claim", format!(" claimant={} month={} amount=500SOV wallet={}", &rand_did()[..24], rng.gen_range(0..12), &rand_hash()[..16])),
                ("UBI distribution batch", format!(" month={} claims={} total={}SOV", rng.gen_range(0..12), rng.gen_range(100..1000), rng.gen_range(50000..500000))),
            ];
            let (msg, kvs) = &events[rng.gen_range(0..events.len())];
            (msg.to_string(), kvs.clone())
        },
        "governance::voting" => {
            let events = [
                ("vote recorded", format!(" proposal={} voter={} choice={} power={}", &rand_hash()[..16], &rand_did()[..24], ["Approve", "Reject", "Abstain"][rng.gen_range(0..3)], rng.gen_range(100..50000))),
                ("proposal status changed", format!(" proposal={} status={} quorum={:.1}%", &rand_hash()[..16], ["Active", "Passed", "Rejected"][rng.gen_range(0..3)], rng.gen_range(40.0..90.0f64))),
            ];
            let (msg, kvs) = &events[rng.gen_range(0..events.len())];
            (msg.to_string(), kvs.clone())
        },
        _ => {
            let events = [
                ("operation completed", format!(" duration={}ms success=true", rng.gen_range(1..5000))),
                ("health check passed", format!(" uptime={}h peers={} memory={}MB", rng.gen_range(1..8760), rng.gen_range(8..256), rng.gen_range(256..8192))),
                ("periodic maintenance", format!(" pruned={} compacted={} elapsed={}ms", rng.gen_range(0..1000), rng.gen_range(0..100), rng.gen_range(10..10000))),
            ];
            let (msg, kvs) = &events[rng.gen_range(0..events.len())];
            (msg.to_string(), kvs.clone())
        }
    }
}
