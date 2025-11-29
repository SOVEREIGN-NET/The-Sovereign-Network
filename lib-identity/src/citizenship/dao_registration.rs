//! DAO governance registration from the original identity.rs

use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::types::IdentityId;
use crate::economics::{EconomicModel, Transaction, TransactionType, Priority};

/// DAO governance registration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoRegistration {
    /// Citizen's identity ID
    pub identity_id: IdentityId,
    /// DAO registration transaction
    pub registration_tx: Transaction,
    /// Voting power (1 vote per citizen)
    pub voting_power: u64,
    /// DAO membership proof
    pub membership_proof: [u8; 32],
    /// Registration timestamp
    pub registered_at: u64,
    /// Can vote on proposals
    pub voting_eligibility: bool,
    /// Can create proposals
    pub proposal_eligibility: bool,
}

impl DaoRegistration {
    /// Create a new DAO registration
    pub fn new(
        identity_id: IdentityId,
        registration_tx: Transaction,
        voting_power: u64,
        membership_proof: [u8; 32],
        registered_at: u64,
        voting_eligibility: bool,
        proposal_eligibility: bool,
    ) -> Self {
        Self {
            identity_id,
            registration_tx,
            voting_power,
            membership_proof,
            registered_at,
            voting_eligibility,
            proposal_eligibility,
        }
    }
    
    /// Register identity for DAO governance participation - IMPLEMENTATION FROM ORIGINAL
    pub async fn register_for_dao_governance(
        identity_id: &IdentityId,
        economic_model: &mut EconomicModel,
    ) -> Result<Self> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Create DAO membership transaction
        let dao_tx = Transaction::new(
            [0u8; 32], // DAO treasury
            identity_id.0,
            0, // No cost to join DAO
            TransactionType::DaoFee, // Actually a DAO registration
            economic_model,
            64, // Transaction size
            Priority::Normal,
        )?;

        // Generate voting power (starts at 1 vote per citizen)
        let voting_power = 1u64;
        
        // Generate DAO membership proof
        let membership_proof = lib_crypto::hash_blake3(
            &[identity_id.0.as_slice(), &current_time.to_le_bytes()].concat()
        );

        tracing::info!(
            " DAO REGISTERED: Citizen {} granted voting rights with {} voting power",
            hex::encode(&identity_id.0[..8]),
            voting_power
        );

        Ok(Self::new(
            identity_id.clone(),
            dao_tx,
            voting_power,
            membership_proof,
            current_time,
            true, // voting_eligibility
            true, // proposal_eligibility
        ))
    }
    
    /// Check if citizen can vote
    pub fn can_vote(&self) -> bool {
        self.voting_eligibility && self.voting_power > 0
    }
    
    /// Check if citizen can create proposals
    pub fn can_create_proposals(&self) -> bool {
        self.proposal_eligibility && self.voting_power > 0
    }
    
    /// Get voting weight (currently 1 vote per citizen)
    pub fn get_voting_weight(&self) -> u64 {
        if self.voting_eligibility {
            self.voting_power
        } else {
            0
        }
    }
    
    /// Get registration age in seconds
    pub fn registration_age_seconds(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.registered_at)
    }
    
    /// Check if membership proof is valid (simplified validation)
    pub fn is_membership_proof_valid(&self) -> bool {
        // Verify membership proof contains expected elements
        self.membership_proof != [0u8; 32] && 
        self.voting_power > 0 &&
        self.registered_at > 0
    }
}
