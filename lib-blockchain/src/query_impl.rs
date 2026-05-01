//! BlockchainQuery implementation for Blockchain.

use crate::block::Block;
use crate::blockchain::{Blockchain, ValidatorInfo};
use crate::query::BlockchainQuery;
use crate::transaction::{
    DaoExecutionData, DaoProposalData, DaoVoteData, IdentityTransactionData, Transaction,
    WalletTransactionData,
};
use crate::types::Hash;

impl BlockchainQuery for Blockchain {
    fn query_height(&self) -> u64 {
        self.height
    }

    fn query_block_count(&self) -> usize {
        self.blocks.len()
    }

    fn query_block(&self, height: u64) -> Option<&Block> {
        self.get_block(height)
    }

    fn query_latest_block(&self) -> Option<&Block> {
        self.latest_block()
    }

    fn query_blocks(&self) -> &[Block] {
        &self.blocks
    }

    fn query_pending_transactions(&self) -> Vec<Transaction> {
        self.pending_transactions.clone()
    }

    fn query_pending_count(&self) -> usize {
        self.pending_transactions.len()
    }

    fn query_identity_exists(&self, did: &str) -> bool {
        self.identity_registry.contains_key(did)
    }

    fn query_identity(&self, did: &str) -> Option<&IdentityTransactionData> {
        self.identity_registry.get(did)
    }

    fn query_all_identities(&self) -> Vec<(&String, &IdentityTransactionData)> {
        self.identity_registry.iter().collect()
    }

    fn query_identity_count(&self) -> usize {
        self.identity_registry.len()
    }

    fn query_wallet_exists(&self, wallet_id: &str) -> bool {
        self.wallet_registry.contains_key(wallet_id)
    }

    fn query_wallet(&self, wallet_id: &str) -> Option<&WalletTransactionData> {
        self.wallet_registry.get(wallet_id)
    }

    fn query_wallet_count(&self) -> usize {
        self.wallet_registry.len()
    }

    fn query_validator_count(&self) -> usize {
        self.validator_registry.len()
    }

    fn query_validator(&self, did: &str) -> Option<&ValidatorInfo> {
        self.validator_registry.get(did)
    }

    fn query_is_council_member(&self, did: &str) -> bool {
        self.is_council_member(did)
    }

    fn query_dao_proposals(&self) -> Vec<DaoProposalData> {
        self.get_dao_proposals()
    }

    fn query_dao_proposal(&self, proposal_id: &Hash) -> Option<DaoProposalData> {
        self.get_dao_proposal(proposal_id)
    }

    fn query_dao_votes(&self, proposal_id: &Hash) -> Vec<DaoVoteData> {
        self.get_dao_votes_for_proposal(proposal_id)
    }

    fn query_dao_executions(&self) -> Vec<DaoExecutionData> {
        self.get_dao_executions()
    }

    fn query_dao_treasury_balance(&self) -> Option<u128> {
        self.get_dao_treasury_balance().ok()
    }

    fn query_token_balance(&self, token_id: &[u8; 32], key_id: &[u8; 32]) -> u128 {
        // Authoritative source: sled store
        if let Some(store) = self.get_store() {
            let storage_token_id = crate::storage::TokenId(*token_id);
            let addr = crate::storage::Address::new(*key_id);
            if let Ok(balance) = store.get_token_balance(&storage_token_id, &addr) {
                return balance as u128;
            }
        }
        // Fallback: in-memory token contract
        if let Some(token) = self.token_contracts.get(token_id) {
            let key = crate::integration::crypto_integration::PublicKey {
                dilithium_pk: [0u8; 2592],
                kyber_pk: [0u8; 1568],
                key_id: *key_id,
            };
            return token.balance_of(&key);
        }
        0
    }

    fn query_token_contract(
        &self,
        token_id: &[u8; 32],
    ) -> Option<crate::contracts::TokenContract> {
        self.get_token_contract(token_id)
    }

    fn query_tx_fee_config(&self) -> &crate::transaction::TxFeeConfig {
        self.get_tx_fee_config()
    }
}
