//! Read-only query interface for blockchain state.
//!
//! The `BlockchainQuery` trait defines the boundary between the blockchain engine
//! and the services layer. Services (API handlers, ZDNS, rewards) access chain
//! state through this trait rather than through direct field access on `Blockchain`.
//!
//! This enables:
//! - Clear separation of concerns (services never hold the blockchain write lock)
//! - Future IPC backend (Phase 4) without changing service code
//! - Testability (mock implementations for unit tests)

use crate::block::Block;
use crate::transaction::{
    DaoExecutionData, DaoProposalData, DaoVoteData, IdentityTransactionData, Transaction,
    WalletTransactionData,
};
use crate::types::Hash;

/// Read-only query interface to blockchain state.
///
/// All methods take `&self` — no mutation allowed through this trait.
/// Implementations may read from in-memory state, sled, or an IPC channel.
pub trait BlockchainQuery {
    /// Current chain height (0 = genesis only).
    fn query_height(&self) -> u64;

    /// Total number of blocks in the chain.
    fn query_block_count(&self) -> usize;

    /// Get a block by height.
    fn query_block(&self, height: u64) -> Option<&Block>;

    /// Get the most recent block.
    fn query_latest_block(&self) -> Option<&Block>;

    /// Get all blocks as a slice (for iteration/search).
    fn query_blocks(&self) -> &[Block];

    /// Get pending (unconfirmed) transactions.
    fn query_pending_transactions(&self) -> Vec<Transaction>;

    /// Number of pending transactions.
    fn query_pending_count(&self) -> usize;

    /// Check if a DID is in the identity registry.
    fn query_identity_exists(&self, did: &str) -> bool;

    /// Get identity data by DID.
    fn query_identity(&self, did: &str) -> Option<&IdentityTransactionData>;

    /// Get all registered identities.
    fn query_all_identities(&self) -> Vec<(&String, &IdentityTransactionData)>;

    /// Number of registered identities.
    fn query_identity_count(&self) -> usize;

    /// Check if a wallet ID exists.
    fn query_wallet_exists(&self, wallet_id: &str) -> bool;

    /// Get wallet data by ID.
    fn query_wallet(&self, wallet_id: &str) -> Option<&WalletTransactionData>;

    /// Number of registered wallets.
    fn query_wallet_count(&self) -> usize;

    /// Number of active validators.
    fn query_validator_count(&self) -> usize;

    /// Get validator info by DID.
    fn query_validator(&self, did: &str) -> Option<&crate::blockchain::ValidatorInfo>;

    /// Check if a DID is a council member.
    fn query_is_council_member(&self, did: &str) -> bool;

    /// Get all DAO proposals.
    fn query_dao_proposals(&self) -> Vec<DaoProposalData>;

    /// Get a specific DAO proposal by ID.
    fn query_dao_proposal(&self, proposal_id: &Hash) -> Option<DaoProposalData>;

    /// Get votes for a proposal.
    fn query_dao_votes(&self, proposal_id: &Hash) -> Vec<DaoVoteData>;

    /// Get all DAO executions.
    fn query_dao_executions(&self) -> Vec<DaoExecutionData>;

    /// Get DAO treasury balance.
    fn query_dao_treasury_balance(&self) -> Option<u128>;

    /// Get token balance for an address. Reads from sled (authoritative) with
    /// in-memory fallback. Returns 0 if token or address not found.
    fn query_token_balance(&self, token_id: &[u8; 32], key_id: &[u8; 32]) -> u128;

    /// Get a token contract by ID (from sled or in-memory).
    fn query_token_contract(
        &self,
        token_id: &[u8; 32],
    ) -> Option<crate::contracts::TokenContract>;

    /// Get transaction fee config.
    fn query_tx_fee_config(&self) -> &crate::transaction::TxFeeConfig;
}
