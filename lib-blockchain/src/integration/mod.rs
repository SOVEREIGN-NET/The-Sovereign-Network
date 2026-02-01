//! Blockchain integration modules

pub mod enhanced_zk_crypto;
pub mod crypto_integration;
pub mod zk_integration;
pub mod network_integration;
pub mod economic_integration;
pub mod storage_integration;
pub mod identity_integration;
pub mod consensus_integration;

// Re-export for convenience
pub use enhanced_zk_crypto::{
    ConsensusProofData, EnhancedConsensusValidator, EnhancedTransactionCreator, 
    EnhancedTransactionValidator, ProofMetadata, TransactionSpec
};
pub use crypto_integration::{encrypt_data_hybrid, public_key_bytes};
pub use zk_integration::{
    batch_verify_transaction_proofs, generate_identity_proof_for_transaction, 
    generate_proofs_transaction_proof, generate_simple_transaction_proof, 
    is_valid_proof_structure, verify_transaction_proof, verify_transaction_proof_detailed
};
pub use network_integration::{
    deserialize_block_from_network, deserialize_transaction_from_network,
    serialize_block_for_network, serialize_transaction_for_network,
    NetworkMessage, NetworkNode
};
pub use economic_integration::{
    calculate_minimum_blockchain_fee, convert_blockchain_amount_to_economy,
    convert_economy_amount_to_blockchain, create_economic_processor,
    create_welfare_funding_transactions, validate_dao_fee_calculation,
    EconomicTransactionProcessor, TreasuryStats
};
pub use storage_integration::{
    block_storage_key, contract_storage_key, deserialize_blockchain_state,
    identity_storage_key, serialize_blockchain_state, transaction_storage_key,
    utxo_storage_key, BackupData, BlockchainState, BlockchainStorageConfig,
    BlockchainStorageManager, StorageCache, StorageOperationMetadata,
    StorageOperationResult, StorageOperationType
};
pub use identity_integration::{
    create_blockchain_did, create_identity_commitment, determine_access_level,
    identity_type_to_string, parse_identity_type, process_identity_registration,
    process_identity_revocation, process_identity_update, validate_identity_data,
    verify_identity_for_operation, Did, IdentityAttributes
};
pub use consensus_integration::{
    create_dao_proposal_transaction, create_dao_vote_transaction,
    initialize_consensus_integration, initialize_consensus_integration_with_difficulty_config,
    BlockchainConsensusCoordinator, ConsensusStatus, FeeValidationReport,
    ValidatorInfo, ValidatorKeypair
};
