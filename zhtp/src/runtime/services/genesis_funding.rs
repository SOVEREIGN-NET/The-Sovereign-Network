use anyhow::Result;
use lib_blockchain::{
    Blockchain,
    transaction::{
        Transaction,
        TransactionOutput,
        WalletTransactionData,
        IdentityTransactionData,
    },
    integration::crypto_integration::{Signature, SignatureAlgorithm},
};
use lib_crypto::PublicKey;
use tracing::{info, warn, error};

/// Genesis validator configuration
#[derive(Clone, Debug)]
pub struct GenesisValidator {
    pub identity_id: lib_identity::IdentityId,
    pub node_device_id: Option<lib_identity::IdentityId>,
    pub stake: u64,
    pub storage_provided: u64,
    pub commission_rate: u16, // basis points (e.g., 500 = 5%)
}

/// Service for creating genesis funding and bootstrapping the blockchain
pub struct GenesisFundingService;

impl GenesisFundingService {
    /// Create genesis funding to bootstrap the system with UTXOs for multi-node network
    pub async fn create_genesis_funding(
        blockchain: &mut Blockchain,
        genesis_validators: Vec<GenesisValidator>,
        environment: &crate::config::Environment,
        user_primary_wallet_id: Option<(lib_identity::wallets::WalletId, Vec<u8>)>, // (wallet_id, public_key)
        user_identity_id: Option<lib_identity::IdentityId>,
        genesis_private_data: Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>,
    ) -> Result<()> {
        info!("Creating genesis funding for multi-validator identity-based transaction system...");
        info!("Initializing {} genesis validators", genesis_validators.len());
        
        // Validate we have validators
        if genesis_validators.is_empty() {
            return Err(anyhow::anyhow!("No genesis validators provided - network requires at least one validator"));
        }
        
        info!("Multi-validator mode: {} validators for production network", genesis_validators.len());
        
        // Initialize outputs vector for genesis transaction
        let mut genesis_outputs = Vec::new();
        let mut total_validator_stake = 0u64;
        
        // Create UTXOs for each validator based on their stake
        for (index, validator) in genesis_validators.iter().enumerate() {
            let validator_id_hex = hex::encode(&validator.identity_id.0[..8]);
            info!("Creating validator {} UTXO: {} ZHTP stake (Identity: {})", 
                  index + 1, validator.stake, validator_id_hex);
            
            // Create validator stake UTXO
            let validator_output = TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(
                    format!("validator_stake_commitment_{}_{}", validator_id_hex, validator.stake).as_bytes()
                ),
                note: lib_blockchain::types::hash::blake3_hash(
                    format!("validator_stake_note_{}_{}", validator_id_hex, index).as_bytes()
                ),
                recipient: PublicKey::new(validator.identity_id.as_bytes().to_vec()),
            };
            
            genesis_outputs.push(validator_output);
            total_validator_stake += validator.stake;
            
            info!("   - Validator {}: {} ZHTP (ID: {})", 
                  index + 1, validator.stake, validator_id_hex);
        }
        
        info!("Total validator stake: {} ZHTP across {} validators", 
              total_validator_stake, genesis_validators.len());
        
        // Access the genesis block (first block in the blockchain)
        if blockchain.blocks.is_empty() {
            return Err(anyhow::anyhow!("No genesis block found in blockchain"));
        }
        
        let genesis_block = &mut blockchain.blocks[0];
        
        // Add system funding pools (unchanged amounts for network operation)
        genesis_outputs.extend(vec![
            // System UBI funding pool
            TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(b"ubi_pool_commitment_500000"),
                note: lib_blockchain::types::hash::blake3_hash(b"ubi_pool_note"),
                recipient: PublicKey::new(b"genesis_system_ubi".to_vec()),
            },
            // Mining rewards pool
            TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(b"mining_pool_commitment_300000"),
                note: lib_blockchain::types::hash::blake3_hash(b"mining_pool_note"),
                recipient: PublicKey::new(b"genesis_system_mining".to_vec()),
            },
            // Development fund
            TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(b"dev_pool_commitment_200000"),
                note: lib_blockchain::types::hash::blake3_hash(b"dev_pool_note"),
                recipient: PublicKey::new(b"genesis_system_dev".to_vec()),
            },
        ]);
        
        // Add user primary wallet funding (welcome bonus: 5000 ZHTP)
        if let Some((wallet_id, _wallet_public_key)) = user_primary_wallet_id.as_ref() {
            let wallet_id_hex = hex::encode(&wallet_id.0[..8]);
            info!(" Funding genesis user primary wallet: {} with 5000 ZHTP welcome bonus", wallet_id_hex);
            
            // CRITICAL: Get the FULL Dilithium2 public key from the identity's private data
            // This is required for signature verification (1312 bytes, not 32-byte hash)
            let identity_dilithium_pubkey = if let Some(user_id) = user_identity_id.as_ref() {
                // Find the matching private data for this identity
                if let Some(genesis_private) = genesis_private_data.iter()
                    .find(|(id, _)| id.0 == user_id.0)
                {
                    // Extract the full Dilithium2 public key (1312 bytes)
                    genesis_private.1.quantum_keypair.public_key.clone()
                } else {
                    error!(" CRITICAL: No private key found for user identity during genesis!");
                    return Err(anyhow::anyhow!("Genesis identity missing private key data"));
                }
            } else {
                error!(" CRITICAL: No user identity ID for genesis wallet!");
                return Err(anyhow::anyhow!("Genesis wallet missing identity"));
            };
            
            info!("   - Dilithium2 public key size: {} bytes", identity_dilithium_pubkey.len());
            
            // Create wallet funding UTXO (still uses 32-byte identity hash for recipient)
            let identity_hash = user_identity_id.as_ref().unwrap().0.to_vec();
            let wallet_output = TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(
                    format!("user_wallet_commitment_{}_{}", wallet_id_hex, 5000).as_bytes()
                ),
                note: lib_blockchain::types::hash::blake3_hash(
                    format!("user_wallet_note_{}", wallet_id_hex).as_bytes()
                ),
                recipient: PublicKey::new(identity_hash),
            };
            
            genesis_outputs.push(wallet_output);
            
            // Register wallet in blockchain's wallet_registry with initial balance
            // CRITICAL: Store the FULL Dilithium2 public key for signature verification
            let wallet_data = WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from_slice(&wallet_id.0),
                wallet_type: "Primary".to_string(),
                wallet_name: "Primary Wallet".to_string(),
                alias: None,
                public_key: identity_dilithium_pubkey.clone(), // Full 1312-byte Dilithium2 public key
                owner_identity_id: user_identity_id.as_ref().map(|id| lib_blockchain::Hash::from_slice(&id.0)),
                seed_commitment: lib_blockchain::types::hash::blake3_hash(b"genesis_wallet_seed"),
                created_at: 1730419200, // Genesis timestamp
                registration_fee: 0,
                capabilities: 0xFFFFFFFF, // Full capabilities
                initial_balance: 5000, // 5000 ZHTP welcome bonus
            };
            
            blockchain.wallet_registry.insert(hex::encode(&wallet_id.0), wallet_data);
            
            info!(" Genesis user wallet funded and registered: {} ZHTP", 5000);
            info!("   - Wallet ID: {}", hex::encode(&wallet_id.0));
            info!("   - Owner Identity ID: {}", hex::encode(&user_identity_id.as_ref().unwrap().0));
            info!("   - Dilithium2 Public Key (first 16 bytes): {}", hex::encode(&identity_dilithium_pubkey[..16]));
        }
        
        // Create genesis funding transaction signed by first validator (network bootstrap)
        let genesis_signature = if let Some(first_validator) = genesis_validators.first() {
            let validator_id_hex = hex::encode(&first_validator.identity_id.0[..8]);
            Signature {
                signature: format!("validator_{}_genesis_signature", validator_id_hex).as_bytes().to_vec(),
                public_key: PublicKey::new(first_validator.identity_id.as_bytes().to_vec()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: 1730419200, // November 1, 2025 00:00:00 UTC
            }
        } else {
            return Err(anyhow::anyhow!("No validators available for genesis signature"));
        };
        
        let genesis_tx = Transaction {
            version: 1,
            chain_id: environment.chain_id(),
            transaction_type: lib_blockchain::types::TransactionType::Transfer,
            inputs: vec![],
            outputs: genesis_outputs.clone(),
            fee: 0,
            signature: genesis_signature,
            memo: b"Genesis funding transaction for ZHTP system".to_vec(),
            wallet_data: None,
            identity_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        };

        // Add genesis transaction to the genesis block
        genesis_block.transactions.push(genesis_tx.clone());
        
        // Recalculate and update the genesis block's merkle root after adding the transaction
        let updated_merkle_root = lib_blockchain::transaction::hashing::calculate_transaction_merkle_root(&genesis_block.transactions);
        genesis_block.header.merkle_root = updated_merkle_root;
        info!("Genesis block merkle root updated: {}", hex::encode(updated_merkle_root.as_bytes()));
        
        // Create UTXOs from genesis transaction outputs and add to UTXO set
        let genesis_tx_id = lib_blockchain::types::hash::blake3_hash(b"genesis_funding_transaction");
        for (index, output) in genesis_outputs.iter().enumerate() {
            let utxo_hash = lib_blockchain::types::hash::blake3_hash(
                &format!("genesis_funding:{}:{}", hex::encode(genesis_tx_id), index).as_bytes()
            );
            blockchain.utxo_set.insert(utxo_hash, output.clone());
        }
        
        info!("Genesis funding created: {} UTXOs with validator stakes and funding pools", 
              genesis_outputs.len());
        
        for (index, validator) in genesis_validators.iter().enumerate() {
            info!("   - Validator {}: {} ZHTP (ID: {})", 
                  index + 1, validator.stake, hex::encode(&validator.identity_id.0[..8]));
        }
        
        info!("   - UBI Pool: 500,000 ZHTP");
        info!("   - Mining Pool: 300,000 ZHTP");
        info!("   - Development Pool: 200,000 ZHTP");
        info!("   - Total validator stake: {} ZHTP", total_validator_stake);
        info!("   - Total UTXO entries: {}", blockchain.utxo_set.len());
        
        // Register USER identity on blockchain (not just validators)
        Self::register_user_identity(blockchain, user_identity_id, &genesis_validators, genesis_private_data, user_primary_wallet_id).await?;
        
        // Register validators AFTER USER identity exists in blockchain
        Self::register_validators(blockchain, genesis_validators).await?;
        
        // Genesis block stays at height 0 - pending transactions will mine into block 1
        info!("   Genesis block finalized - Height: {}, UTXOs: {}, Identities: {}, Pending: {}", 
              blockchain.height, blockchain.utxo_set.len(), blockchain.identity_registry.len(),
              blockchain.pending_transactions.len());
        
        Ok(())
    }
    
    async fn register_user_identity(
        blockchain: &mut Blockchain,
        user_identity_id: Option<lib_identity::IdentityId>,
        genesis_validators: &[GenesisValidator],
        genesis_private_data: Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>,
        user_primary_wallet_id: Option<(lib_identity::wallets::WalletId, Vec<u8>)>,
    ) -> Result<()> {
        info!("  Validator registration will occur after USER identity is registered");
        
        if let Some(user_id) = user_identity_id.as_ref() {
            let user_did = format!("did:zhtp:{}", hex::encode(&user_id.0));
            info!(" Registering USER identity on blockchain: {}", user_did);
            
            // Get the full Dilithium2 public key from private data
            let user_dilithium_pubkey = if let Some(user_private) = genesis_private_data.iter()
                .find(|(id, _)| id.0 == user_id.0)
            {
                user_private.1.quantum_keypair.public_key.clone()
            } else {
                warn!("  No private key found for user identity during genesis registration!");
                vec![]
            };
            
            // Collect node device IDs from genesis validators (nodes are controlled devices, not separate identities)
            let controlled_node_ids: Vec<String> = genesis_validators.iter()
                .filter_map(|v| v.node_device_id.as_ref().map(|nid| hex::encode(&nid.0)))
                .collect();
            
            info!("   - User controls {} node device(s)", controlled_node_ids.len());
            for (idx, node_id) in controlled_node_ids.iter().enumerate() {
                info!("     Node {}: {}...", idx + 1, &node_id[..32]);
            }
            
            let user_identity_data = IdentityTransactionData {
                did: user_did.clone(),
                display_name: "Genesis User".to_string(),
                public_key: user_dilithium_pubkey,
                ownership_proof: vec![],
                identity_type: "human".to_string(),
                did_document_hash: lib_blockchain::types::hash::blake3_hash(user_did.as_bytes()),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                registration_fee: 0,
                dao_fee: 0,
                controlled_nodes: controlled_node_ids,
                owned_wallets: vec![hex::encode(&user_primary_wallet_id.as_ref().unwrap().0.0)],
            };
            
            match blockchain.register_identity(user_identity_data) {
                Ok(tx_hash) => {
                    info!(" Genesis USER identity registered with transaction: {}", 
                          hex::encode(tx_hash));
                    info!("   - DID: {}", user_did);
                    info!("   - Identity ID: {}", hex::encode(&user_id.0));
                    info!("   - Identity type: Human");
                }
                Err(e) => {
                    warn!("  User identity registration failed (may already exist): {}", e);
                }
            }
        }
        
        Ok(())
    }
    
    async fn register_validators(
        blockchain: &mut Blockchain,
        genesis_validators: Vec<GenesisValidator>,
    ) -> Result<()> {
        info!(" Registering validators in validator_registry (USER identity already registered)...");
        let mut registered_validators = 0;
        
        for (index, validator) in genesis_validators.iter().enumerate() {
            let validator_did = format!("did:zhtp:{}", hex::encode(&validator.identity_id.0));
            
            info!(" Registering validator {}: {}", index + 1, validator_did);
            if let Some(node_id) = &validator.node_device_id {
                info!("   - Node device: {}", hex::encode(&node_id.0[..16]));
            }
            
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let validator_info = lib_blockchain::blockchain::ValidatorInfo {
                identity_id: validator_did.clone(),
                stake: validator.stake,
                storage_provided: validator.storage_provided,
                consensus_key: validator.identity_id.as_bytes().to_vec(),
                network_address: "127.0.0.1:9333".to_string(),
                commission_rate: (validator.commission_rate.min(10000) / 100) as u8,
                status: "active".to_string(),
                registered_at: now,
                last_activity: now,
                blocks_validated: 0,
                slash_count: 0,
            };
            
            match blockchain.register_validator(validator_info) {
                Ok(validator_tx_hash) => {
                    registered_validators += 1;
                    info!(" Genesis validator {} registered in validator_registry", index + 1);
                    info!("   - Validator TX: {}", hex::encode(validator_tx_hash));
                    info!("   - Stake: {} ZHTP", validator.stake);
                    info!("   - Storage: {} GB", validator.storage_provided);
                    info!("   - Commission: {}.{}%", 
                          validator.commission_rate / 100, validator.commission_rate % 100);
                }
                Err(e) => {
                    warn!("  Failed to register validator {} in validator_registry: {}", 
                          index + 1, e);
                }
            }
        }
        
        info!(" Validator registration complete: {}/{} validators registered", 
              registered_validators, genesis_validators.len());
        info!("   - Pending transactions: {}", blockchain.pending_transactions.len());
        info!("   - Identities in registry: {}", blockchain.identity_registry.len());
        
        Ok(())
    }
}
