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
        // #2636: full chain length, not the hot-window size (`self.blocks.len()`
        // under-counts once the window slides on a store-backed node).
        self.block_count() as usize
    }

    fn query_block(&self, height: u64) -> Option<Block> {
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
        // #2639: sled-first — the in-memory registry can be empty/partial on a
        // store-backed node after restart or window prune.
        self.identity_exists(did)
    }

    fn query_identity(&self, did: &str) -> Option<&IdentityTransactionData> {
        // In-memory ref only — sled-backed identities use identity_transaction_data().
        self.identity_registry.get(did)
    }

    fn query_all_identities(&self) -> Vec<(&String, &IdentityTransactionData)> {
        // Legacy ref iterator — IPC uses identity_registry_snapshot() instead (#2639).
        self.identity_registry.iter().collect()
    }

    fn query_identity_count(&self) -> usize {
        // #2639: authoritative sled count (in-memory shadow is non-durable).
        self.identity_count()
    }

    fn query_wallet_exists(&self, wallet_id: &str) -> bool {
        // #2639: sled-first union — in-memory shadow can be empty after restart.
        self.wallet_exists(wallet_id)
    }

    fn query_wallet(&self, wallet_id: &str) -> Option<&WalletTransactionData> {
        // In-memory ref only — sled-backed wallets use wallet_transaction_data().
        self.wallet_registry.get(wallet_id)
    }

    fn query_wallet_count(&self) -> usize {
        // #2639: authoritative sled count (in-memory shadow is non-durable).
        self.wallet_count()
    }

    fn query_validator(&self, did: &str) -> Option<&ValidatorInfo> {
        // In-memory ref only — sled-backed validators use validator_info_by_did().
        self.validator_registry.get(did)
    }

    fn query_validator_count(&self) -> usize {
        // #2639: authoritative sled count (in-memory shadow is non-durable).
        self.validator_count()
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
        // Trait API returns u128 — sled errors surface as 0 (parity with pre-#2637).
        self.token_balance(token_id, key_id).unwrap_or(0)
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

    fn query_all_wallets(&self) -> Vec<(&String, &WalletTransactionData)> {
        // Legacy ref iterator — handlers use wallet_registry_snapshot() instead (#2639).
        self.wallet_registry.iter().collect()
    }

    fn query_all_validators(&self) -> Vec<(&String, &crate::blockchain::ValidatorInfo)> {
        // Legacy ref iterator — handlers use validator_registry_snapshot() instead (#2639).
        self.validator_registry.iter().collect()
    }

    fn query_token_count(&self) -> usize {
        self.token_contracts.len()
    }

    fn query_all_token_contracts(&self) -> Vec<(&[u8; 32], &crate::contracts::TokenContract)> {
        self.token_contracts.iter().collect()
    }

    fn query_governance_phase(&self) -> crate::dao::GovernancePhase {
        self.governance_phase.clone()
    }

    fn query_council_members(&self) -> &[crate::dao::CouncilMember] {
        &self.council_members
    }

    fn query_block_range(&self, start: u64, end: u64) -> Vec<Block> {
        // #2636: `start`/`end` are ABSOLUTE heights. `self.blocks` is only the
        // hot window, so `self.blocks[start..=end]` indexed it by absolute
        // height — returning the wrong blocks (or empty) once the window slid
        // past genesis on a store-backed node. get_block(h) resolves each height
        // across the window AND sled.
        let end = end.min(self.height);
        if start > end {
            return Vec::new();
        }
        (start..=end).filter_map(|h| self.get_block(h)).collect()
    }
}

impl crate::query::BlockchainMutate for Blockchain {
    fn submit_transaction(&mut self, tx: Transaction) -> anyhow::Result<()> {
        self.add_pending_transaction(tx)
    }

    fn submit_system_transaction(
        &mut self,
        tx: Transaction,
        originator: &'static str,
    ) -> anyhow::Result<()> {
        self.add_system_transaction(tx, originator)
    }
}
