//! DAO transaction helpers — vestigial slice of the deleted
//! `BlockchainConsensusCoordinator`.
//!
//! The 2,142-LOC `BlockchainConsensusCoordinator` and its parallel
//! orchestration loops (`block_production_loop`, `consensus_event_loop`,
//! `dao_governance_loop`, `reward_distribution_loop`) were deleted in
//! CONS-505. The single consensus driver now lives in
//! `lib-consensus-runtime::ConsensusRuntime` (CONS-502); the loops
//! migrated to:
//!
//! - block production → `ConsensusEngine`'s proposer-selection path
//!   (CONS-305).
//! - DAO governance → `lib_governance::dao::ConsensusGovernanceAdapter`
//!   (CONS-106 / AD-005, wired via the runtime's
//!   `GovernanceCallback`).
//! - reward distribution → `lib_economy::rewards::ConsensusRewardAdapter`
//!   (CONS-103 / AD-005, wired via `RewardCallback`).
//! - finalization → `lib_consensus_core::ports::BlockFinalizationSink`
//!   (CONS-402, impl in zhtp's `ConsensusBlockFinalizationSink`,
//!   CONS-504).
//!
//! What remains here:
//!
//! - `create_dao_proposal_transaction` / `create_dao_vote_transaction`
//!   — system-transaction builders used by
//!   `lib-blockchain/src/blockchain/dao.rs` to record DAO actions
//!   on-chain. The actual DAO state lives in `lib-governance`; these
//!   helpers just produce the audit-trail transactions.
//! - `ValidatorKeypair`, `ValidatorInfo`, `FeeValidationReport`,
//!   `ConsensusStatus` — pure data types still consumed by callers.
//! - `get_current_unix_timestamp` / `validate_consensus_timestamp` —
//!   timestamp utilities used by the helpers.

use anyhow::{anyhow, Result};
use std::time::{SystemTime, UNIX_EPOCH};

use lib_consensus::{ConsensusType, DaoProposalType, DaoVoteChoice, ValidatorStatus};
use lib_crypto::{Hash, KeyPair};
use lib_identity::IdentityId;

use crate::{utils::time::current_timestamp, Transaction};

// ---------------------------------------------------------------------------
// Pure data types (still consumed by callers)
// ---------------------------------------------------------------------------

/// Validator keypair for cryptographic operations.
#[derive(Debug, Clone)]
pub struct ValidatorKeypair {
    pub public_key: lib_crypto::PublicKey,
    pub private_key: lib_crypto::PrivateKey,
}

/// Detailed information about a validator.
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    pub identity: IdentityId,
    pub status: ValidatorStatus,
    pub stake_amount: u64,
    pub reputation_score: u8,
    pub last_active_height: u64,
    pub total_blocks_produced: u64,
    pub slashing_count: u32,
}

/// Fee distribution validation report for end-to-end pipeline
/// verification.
///
/// Week 11 Phase 5c: validates that fees calculated from blocks match
/// expected distributions across UBI / consensus / governance / treasury
/// pools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeValidationReport {
    pub block_height: u64,
    pub total_fees: u64,
    pub ubi_allocation: u64,
    pub consensus_allocation: u64,
    pub governance_allocation: u64,
    pub treasury_allocation: u64,
    pub validation_passed: bool,
    pub timestamp: u64,
}

impl FeeValidationReport {
    /// Check if all allocation percentages are correct (within 1 wei
    /// tolerance).
    pub fn allocations_correct(&self) -> bool {
        if self.total_fees == 0 {
            return true;
        }

        let expected_ubi = self.total_fees.saturating_mul(45).saturating_div(100);
        let expected_consensus = self.total_fees.saturating_mul(30).saturating_div(100);
        let expected_gov = self.total_fees.saturating_mul(15).saturating_div(100);
        let expected_treasury = self.total_fees.saturating_mul(10).saturating_div(100);

        let check_tolerance = |actual: u64, expected: u64| -> bool {
            let diff = if actual > expected {
                actual - expected
            } else {
                expected - actual
            };
            diff <= 1
        };

        check_tolerance(self.ubi_allocation, expected_ubi)
            && check_tolerance(self.consensus_allocation, expected_consensus)
            && check_tolerance(self.governance_allocation, expected_gov)
            && check_tolerance(self.treasury_allocation, expected_treasury)
    }

    /// Verify all fees are accounted for (no loss or duplication).
    pub fn all_fees_accounted_for(&self) -> bool {
        self.ubi_allocation
            .saturating_add(self.consensus_allocation)
            .saturating_add(self.governance_allocation)
            .saturating_add(self.treasury_allocation)
            == self.total_fees
    }
}

/// Lightweight rollup of consensus state surfaced by `Blockchain` to
/// callers that previously polled the deleted
/// `BlockchainConsensusCoordinator`. Kept as a placeholder data shape
/// so any external consumer compiles; meaningful values now come from
/// `lib_consensus_runtime::ConsensusRuntime`.
#[derive(Debug, Clone, Default)]
pub struct ConsensusStatus {
    pub is_running: bool,
    pub current_height: u64,
    pub current_round: u32,
    pub validator_count: u32,
    pub consensus_type: Option<ConsensusType>,
}

// ---------------------------------------------------------------------------
// DAO system-transaction helpers
// ---------------------------------------------------------------------------

/// Create a DAO proposal transaction (audit-trail record only).
///
/// In the post-CONS-106 design, DAO proposals are handled by
/// `lib-governance`. This helper produces a minimal blockchain
/// transaction so the proposal is visible in chain history; the
/// authoritative DAO state lives in the governance engine.
pub fn create_dao_proposal_transaction(
    proposer_keypair: &KeyPair,
    title: String,
    description: String,
    proposal_type: DaoProposalType,
) -> Result<Transaction> {
    let memo = format!(
        "dao:proposal:title:{}|description:{}|type:{:?}",
        title, description, proposal_type
    );

    let mut transaction = Transaction::new(
        vec![],
        vec![],
        100, // DAO proposal fee
        crate::integration::crypto_integration::Signature {
            signature: vec![],
            public_key: proposer_keypair.public_key.clone(),
            algorithm: crate::integration::crypto_integration::SignatureAlgorithm::DEFAULT,
            timestamp: current_timestamp(),
        },
        memo.into_bytes(),
    );

    let tx_hash = transaction.hash();
    let signature = proposer_keypair.sign(&tx_hash.as_bytes())?;
    transaction.signature = signature;

    Ok(transaction)
}

/// Create a DAO vote transaction (audit-trail record only).
///
/// Same pattern as [`create_dao_proposal_transaction`] — the vote is
/// recorded on-chain for transparency; the tally lives in
/// `lib-governance`.
pub fn create_dao_vote_transaction(
    voter_keypair: &KeyPair,
    proposal_id: Hash,
    vote_choice: DaoVoteChoice,
) -> Result<Transaction> {
    let memo = format!(
        "dao:vote:proposal:{}|vote:{}",
        hex::encode(proposal_id.as_bytes()),
        match vote_choice {
            DaoVoteChoice::Yes => "yes",
            DaoVoteChoice::No => "no",
            DaoVoteChoice::Abstain => "abstain",
            DaoVoteChoice::Delegate(_) => "delegate",
        }
    );

    let mut transaction = Transaction::new(
        vec![],
        vec![],
        10, // DAO vote fee
        crate::integration::crypto_integration::Signature {
            signature: vec![],
            public_key: voter_keypair.public_key.clone(),
            algorithm: crate::integration::crypto_integration::SignatureAlgorithm::DEFAULT,
            timestamp: current_timestamp(),
        },
        memo.into_bytes(),
    );

    let tx_hash = transaction.hash();
    let signature = voter_keypair.sign(&tx_hash.as_bytes())?;
    transaction.signature = signature;

    Ok(transaction)
}

// ---------------------------------------------------------------------------
// Timestamp utilities
// ---------------------------------------------------------------------------

/// Current UNIX timestamp via `SystemTime`. Returns an error when the
/// host clock is set before the epoch.
pub fn get_current_unix_timestamp() -> Result<u64> {
    let now = SystemTime::now();
    let duration = now
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("System time before UNIX epoch: {}", e))?;
    Ok(duration.as_secs())
}

/// Validate a consensus-message timestamp against the host clock with
/// a 5-minute drift tolerance.
pub fn validate_consensus_timestamp(timestamp: u64) -> Result<()> {
    let current_time = get_current_unix_timestamp()?;
    let max_time_drift = 300;

    if timestamp > current_time + max_time_drift {
        return Err(anyhow!(
            "Timestamp too far in future: {} vs {}",
            timestamp,
            current_time
        ));
    }

    if timestamp < current_time.saturating_sub(max_time_drift) {
        return Err(anyhow!(
            "Timestamp too far in past: {} vs {}",
            timestamp,
            current_time
        ));
    }

    Ok(())
}
