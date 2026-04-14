use super::*;

#[doc(hidden)]
impl Blockchain {
    /// Push a minimal DAO proposal into `self.blocks` for test use.
    /// Bypasses block validation — do NOT call outside of unit tests.
    pub fn push_test_dao_proposal(&mut self, proposal_id: Hash, quorum: u8) {
        self.push_test_dao_proposal_with_category(
            proposal_id,
            quorum,
            crate::dao::TreasurySpendingCategory::GrantsFunding,
        );
    }

    /// Push a DAO proposal with an explicit spending category for test use.
    pub fn push_test_dao_proposal_with_category(
        &mut self,
        proposal_id: Hash,
        quorum: u8,
        category: crate::dao::TreasurySpendingCategory,
    ) {
        use crate::transaction::DaoProposalData;
        // Serialize a minimal TreasuryExecutionParams — recipient/amount are overridden at
        // execution time, but the category is validated before the transfer happens.
        let params = crate::dao::TreasuryExecutionParams {
            category,
            recipient_wallet_id: String::new(),
            amount: 0,
        };
        let params_bytes =
            serde_json::to_vec(&params).expect("TreasuryExecutionParams must serialize");
        let tx = Transaction::new_dao_proposal(
            DaoProposalData {
                proposal_id,
                proposer: "did:zhtp:test".to_string(),
                title: "Test Proposal".to_string(),
                description: "Test".to_string(),
                proposal_type: "treasury_allocation".to_string(),
                voting_period_blocks: 1000,
                quorum_required: quorum,
                execution_params: Some(params_bytes),
                created_at: 0,
                created_at_height: 0,
            },
            vec![],
            vec![],
            0,
            Signature::default(),
            vec![],
        );
        self.blocks.push(Self::make_minimal_test_block(vec![tx]));
    }

    /// Push a governance-parameter-update DAO proposal into `self.blocks` for test use.
    /// Bypasses block validation — do NOT call outside of unit tests.
    pub fn push_test_governance_parameter_proposal(
        &mut self,
        proposal_id: Hash,
        quorum: u8,
        updates: Vec<lib_consensus::dao::dao_types::GovernanceParameterValue>,
    ) {
        use crate::transaction::DaoProposalData;
        use lib_consensus::dao::dao_types::{
            DaoExecutionAction, DaoExecutionParams, GovernanceParameterUpdate,
        };

        let params = DaoExecutionParams {
            action: DaoExecutionAction::GovernanceParameterUpdate(GovernanceParameterUpdate {
                updates,
            }),
        };
        let params_bytes = bincode::serialize(&params).expect("DaoExecutionParams must serialize");
        let tx = Transaction::new_dao_proposal(
            DaoProposalData {
                proposal_id,
                proposer: "did:zhtp:test".to_string(),
                title: "Governance Update".to_string(),
                description: "Test governance update".to_string(),
                proposal_type: "governance_parameter_update".to_string(),
                voting_period_blocks: 1000,
                quorum_required: quorum,
                execution_params: Some(params_bytes),
                created_at: 0,
                created_at_height: 0,
            },
            vec![],
            vec![],
            0,
            Signature::default(),
            vec![],
        );
        self.blocks.push(Self::make_minimal_test_block(vec![tx]));
    }

    /// Push a minimal DAO vote into `self.blocks` for test use.
    /// Bypasses block validation — do NOT call outside of unit tests.
    pub fn push_test_dao_vote(&mut self, proposal_id: Hash, voter: &str, choice: &str) {
        use crate::transaction::DaoVoteData;
        let tx = Transaction::new_dao_vote(
            DaoVoteData {
                vote_id: Hash::default(),
                proposal_id,
                voter: voter.to_string(),
                vote_choice: choice.to_string(),
                voting_power: 1,
                justification: None,
                timestamp: 0,
            },
            vec![],
            vec![],
            0,
            Signature::default(),
            vec![],
        );
        self.blocks.push(Self::make_minimal_test_block(vec![tx]));
    }

    /// Credit SOV directly to the DAO treasury wallet.
    /// Bypasses normal minting rules — for unit tests only.
    pub fn credit_dao_treasury_sov_for_test(&mut self, amount: u64) -> Result<()> {
        // Ensure the SOV token contract exists (Blockchain::new() skips this).
        self.ensure_sov_token_contract();
        let treasury_wallet_id = self
            .dao_treasury_wallet_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("DAO treasury wallet not set"))?;
        let id_bytes: [u8; 32] = hex::decode(&treasury_wallet_id)
            .map_err(|e| anyhow::anyhow!("Bad treasury wallet hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Treasury wallet ID must be 32 bytes"))?;
        let pk = Self::wallet_key_for_sov(&id_bytes);
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let token = self
            .token_contracts
            .get_mut(&sov_id)
            .ok_or_else(|| anyhow::anyhow!("SOV token contract not found"))?;
        token
            .credit_balance(&pk, amount as u128)
            .map_err(|e| anyhow::anyhow!("Treasury credit failed: {}", e))?;
        Ok(())
    }

    /// Query the raw SOV balance for an arbitrary 64-char hex wallet ID.
    /// For unit tests only.
    pub fn get_wallet_sov_for_test(&self, wallet_id_hex: &str) -> Result<u128> {
        let id_bytes: [u8; 32] = hex::decode(wallet_id_hex)
            .map_err(|e| anyhow::anyhow!("Bad wallet hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Wallet ID must be 32 bytes"))?;
        let pk = Self::wallet_key_for_sov(&id_bytes);
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let token = self
            .token_contracts
            .get(&sov_id)
            .ok_or_else(|| anyhow::anyhow!("SOV token contract not found"))?;
        Ok(token.balance_of(&pk))
    }

    /// Register a minimal wallet owned by `identity_bytes` and credit it with `amount` SOV.
    /// This allows `calculate_user_voting_power` to return a non-zero value in unit tests.
    /// For unit tests only — bypasses normal registration pipeline.
    pub fn credit_identity_sov_for_test(
        &mut self,
        identity_bytes: &[u8; 32],
        amount: u64,
    ) -> Result<()> {
        self.ensure_sov_token_contract();

        // Wallet ID is derived from the identity bytes so it is unique per identity.
        let wallet_id_bytes: [u8; 32] = {
            let mut w = *identity_bytes;
            w[0] ^= 0xee; // differentiate wallet_id from identity_id
            w
        };

        // Insert a minimal WalletTransactionData owned by this identity.
        let owner_hash = crate::types::hash::Hash::new(*identity_bytes);
        let wallet_id_hash = crate::types::hash::Hash::new(wallet_id_bytes);
        let wallet_id_hex = hex::encode(wallet_id_bytes);
        let wallet_data = crate::transaction::WalletTransactionData {
            wallet_id: wallet_id_hash,
            public_key: vec![],
            wallet_type: "standard".to_string(),
            wallet_name: "test".to_string(),
            alias: None,
            owner_identity_id: Some(owner_hash),
            seed_commitment: Hash::default(),
            created_at: 0,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        };
        self.wallet_registry.insert(wallet_id_hex, wallet_data);

        // Credit SOV to the wallet's synthetic key.
        let pk = Self::wallet_key_for_sov(&wallet_id_bytes);
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let token = self
            .token_contracts
            .get_mut(&sov_id)
            .ok_or_else(|| anyhow::anyhow!("SOV token contract not found"))?;
        token
            .credit_balance(&pk, amount as u128)
            .map_err(|e| anyhow::anyhow!("Identity SOV credit failed: {}", e))?;
        Ok(())
    }

    fn make_minimal_test_block(transactions: Vec<Transaction>) -> Block {
        use crate::block::BlockHeader;
        Block {
            header: BlockHeader {
                version: 1,
                previous_hash: Hash::default().into(),
                data_helix_root: Hash::default().into(),
                timestamp: 0,
                height: 1,
                verification_helix_root: [0u8; 32],
                state_root: [0u8; 32],
                bft_quorum_root: [0u8; 32],
                block_hash: Hash::default(),
            },
            transactions,
        }
    }

}
