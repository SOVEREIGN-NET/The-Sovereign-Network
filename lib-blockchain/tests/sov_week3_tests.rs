//! Week 3 Comprehensive Unit Tests
//!
//! Tests for DAO Treasury and Sunset contracts.
//!
//! Tests validate:
//! - DAO Treasury: Proposal creation, voting, spending workflow, audit trail
//! - Sunset: State transitions, spending policies, timelock enforcement
//!
//! Critical Constants Validated:
//! - DAO_ALLOCATION_PERCENTAGE = 6%
//! - DAO_TIMELOCK_SECONDS = 604,800 (7 days)
//! - RESTRICTED_MIN_DURATION = 7,776,000 (90 days)
//! - WIND_DOWN_MIN_DURATION = 15,552,000 (180 days)

use lib_blockchain::contracts::dao::{
    DaoTreasury, SpendingCategory, DaoTreasuryError,
    DAO_ALLOCATION_PERCENTAGE, NUM_SECTOR_DAOS, PER_DAO_ALLOCATION_PERCENTAGE, DAO_TIMELOCK_SECONDS,
    MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
};
use lib_blockchain::contracts::dao::ProposalStatus as DaoProposalStatus;
use lib_blockchain::contracts::governance::{
    Sunset, SunsetState, SpendingPolicy, SunsetError,
    RESTRICTED_MIN_DURATION, WIND_DOWN_MIN_DURATION, FINAL_PAYOUT_TO_NONPROFIT_PERCENTAGE,
    SUNSET_STATE_TRANSITION_TIMELOCK,
};

// ============================================================================
// TEST CONSTANTS
// ============================================================================

const ADMIN: [u8; 32] = [1u8; 32];
const GOVERNANCE: [u8; 32] = [2u8; 32];
const NONPROFIT_TREASURY: [u8; 32] = [3u8; 32];
const PROPOSER: [u8; 32] = [4u8; 32];
const VOTER1: [u8; 32] = [5u8; 32];
const VOTER2: [u8; 32] = [6u8; 32];
const RECIPIENT: [u8; 32] = [7u8; 32];

const DAO_VOTING_POWER: u64 = 100_000 * 10_u64.pow(8); // 100k CBE

// ============================================================================
// DAO TREASURY TESTS
// ============================================================================

#[test]
fn test_dao_treasury_initialization() {
    let mut treasury = DaoTreasury::new();
    assert!(!treasury.is_initialized());

    let result = treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE);
    assert!(result.is_ok());
    assert!(treasury.is_initialized());
    assert_eq!(treasury.get_name(), "HealthcareDAO Treasury");
}

#[test]
fn test_dao_treasury_cannot_init_twice() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();

    let result = treasury.init("EducationDAO Treasury".to_string(), ADMIN, GOVERNANCE);
    assert_eq!(result, Err(DaoTreasuryError::AlreadyInitialized));
}

#[test]
fn test_dao_treasury_receive_allocation() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();

    let result = treasury.receive_allocation(1_000_000, GOVERNANCE);
    assert!(result.is_ok());
    assert_eq!(treasury.balance(), 1_000_000);
    assert_eq!(treasury.total_received(), 1_000_000);
}

#[test]
fn test_dao_treasury_multiple_allocations() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();

    treasury.receive_allocation(500_000, GOVERNANCE).unwrap();
    treasury.receive_allocation(300_000, GOVERNANCE).unwrap();
    treasury.receive_allocation(200_000, GOVERNANCE).unwrap();

    assert_eq!(treasury.balance(), 1_000_000);
    assert_eq!(treasury.total_received(), 1_000_000);
}

#[test]
fn test_dao_treasury_create_proposal() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();
    treasury.receive_allocation(1_000_000, GOVERNANCE).unwrap();
    treasury.update_total_voting_power(DAO_VOTING_POWER * 10);
    treasury.set_current_timestamp(0);

    let result = treasury.create_proposal(
        PROPOSER,
        "Research Grant".to_string(),
        "Fund healthcare research".to_string(),
        SpendingCategory::Research,
        100_000,
        RECIPIENT,
        MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
    );

    assert!(result.is_ok());
    let proposal_id = result.unwrap();
    let proposal = treasury.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.amount, 100_000);
    assert_eq!(proposal.category, SpendingCategory::Research);
}

#[test]
fn test_dao_treasury_cannot_create_proposal_without_voting_power() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();
    treasury.receive_allocation(1_000_000, GOVERNANCE).unwrap();

    let result = treasury.create_proposal(
        PROPOSER,
        "Research Grant".to_string(),
        "Fund healthcare research".to_string(),
        SpendingCategory::Research,
        100_000,
        RECIPIENT,
        MIN_DAO_VOTING_POWER_FOR_PROPOSAL - 1,
    );

    assert_eq!(result, Err(DaoTreasuryError::InsufficientVotingPower));
}

#[test]
fn test_dao_treasury_cannot_spend_more_than_balance() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();
    treasury.receive_allocation(500_000, GOVERNANCE).unwrap();
    treasury.update_total_voting_power(DAO_VOTING_POWER * 10);

    let result = treasury.create_proposal(
        PROPOSER,
        "Research Grant".to_string(),
        "Fund healthcare research".to_string(),
        SpendingCategory::Research,
        600_000,
        RECIPIENT,
        MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
    );

    assert_eq!(result, Err(DaoTreasuryError::InsufficientBalance));
}

#[test]
fn test_dao_treasury_voting_workflow() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();
    treasury.receive_allocation(1_000_000, GOVERNANCE).unwrap();
    treasury.update_total_voting_power(DAO_VOTING_POWER * 10);
    treasury.set_current_timestamp(0);

    let proposal_id = treasury.create_proposal(
        PROPOSER,
        "Research Grant".to_string(),
        "Fund healthcare research".to_string(),
        SpendingCategory::Research,
        100_000,
        RECIPIENT,
        MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Vote for
    treasury.vote(proposal_id, VOTER1, true, DAO_VOTING_POWER).unwrap();

    // Vote against
    treasury.vote(proposal_id, VOTER2, false, DAO_VOTING_POWER / 2).unwrap();

    let proposal = treasury.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.votes_for, DAO_VOTING_POWER);
    assert_eq!(proposal.votes_against, DAO_VOTING_POWER / 2);
}

#[test]
fn test_dao_treasury_finalize_voting_passes() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();
    treasury.receive_allocation(1_000_000, GOVERNANCE).unwrap();
    treasury.update_total_voting_power(DAO_VOTING_POWER * 10);
    treasury.set_current_timestamp(0);

    let proposal_id = treasury.create_proposal(
        PROPOSER,
        "Research Grant".to_string(),
        "Fund healthcare research".to_string(),
        SpendingCategory::Research,
        100_000,
        RECIPIENT,
        MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Vote: 60% for, 40% against (should pass)
    treasury.vote(proposal_id, VOTER1, true, 600_000).unwrap();
    treasury.vote(proposal_id, VOTER2, false, 400_000).unwrap();

    // Finalize after 7 days
    treasury.set_current_timestamp(7 * 24 * 60 * 60 + 1);
    treasury.finalize_voting(proposal_id).unwrap();

    let proposal = treasury.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.status, DaoProposalStatus::Approved);
}

#[test]
fn test_dao_treasury_spending_categories() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();
    treasury.receive_allocation(1_000_000, GOVERNANCE).unwrap();
    treasury.update_total_voting_power(DAO_VOTING_POWER * 10);

    // Test all spending categories
    let categories = vec![
        SpendingCategory::Research,
        SpendingCategory::Operations,
        SpendingCategory::Community,
        SpendingCategory::Emergency,
    ];

    for (i, category) in categories.iter().enumerate() {
        let result = treasury.create_proposal(
            PROPOSER,
            format!("Proposal {}", i),
            "Test proposal".to_string(),
            *category,
            100_000,
            RECIPIENT,
            MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
        );

        assert!(result.is_ok());
        let proposal = treasury.get_proposal(result.unwrap()).unwrap();
        assert_eq!(proposal.category, *category);
    }
}

#[test]
fn test_dao_treasury_execute_proposal() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();
    treasury.receive_allocation(1_000_000, GOVERNANCE).unwrap();
    treasury.update_total_voting_power(DAO_VOTING_POWER * 10);
    treasury.set_current_timestamp(0);

    let proposal_id = treasury.create_proposal(
        PROPOSER,
        "Research Grant".to_string(),
        "Fund healthcare research".to_string(),
        SpendingCategory::Research,
        100_000,
        RECIPIENT,
        MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Vote and finalize
    treasury.vote(proposal_id, VOTER1, true, DAO_VOTING_POWER).unwrap();
    treasury.set_current_timestamp(7 * 24 * 60 * 60 + 1);
    treasury.finalize_voting(proposal_id).unwrap();

    // Wait for 7-day timelock
    treasury.set_current_timestamp(7 * 24 * 60 * 60 + DAO_TIMELOCK_SECONDS + 1);
    let result = treasury.execute_proposal(proposal_id, ADMIN);
    assert!(result.is_ok());

    assert_eq!(treasury.balance(), 900_000);
    assert_eq!(treasury.total_spent(), 100_000);
}

#[test]
fn test_dao_treasury_timelock_enforcement() {
    let mut treasury = DaoTreasury::new();
    treasury.init("HealthcareDAO Treasury".to_string(), ADMIN, GOVERNANCE).unwrap();
    treasury.receive_allocation(1_000_000, GOVERNANCE).unwrap();
    treasury.update_total_voting_power(DAO_VOTING_POWER * 10);
    treasury.set_current_timestamp(0);

    let proposal_id = treasury.create_proposal(
        PROPOSER,
        "Research Grant".to_string(),
        "Fund healthcare research".to_string(),
        SpendingCategory::Research,
        100_000,
        RECIPIENT,
        MIN_DAO_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    treasury.vote(proposal_id, VOTER1, true, DAO_VOTING_POWER).unwrap();
    treasury.set_current_timestamp(7 * 24 * 60 * 60 + 1);
    treasury.finalize_voting(proposal_id).unwrap();

    // Try to execute before timelock
    let result = treasury.execute_proposal(proposal_id, ADMIN);
    assert_eq!(result, Err(DaoTreasuryError::TimelockNotExpired));

    // Execute after timelock
    treasury.set_current_timestamp(7 * 24 * 60 * 60 + DAO_TIMELOCK_SECONDS + 1);
    let result = treasury.execute_proposal(proposal_id, ADMIN);
    assert!(result.is_ok());
}

// ============================================================================
// SUNSET CONTRACT TESTS
// ============================================================================

#[test]
fn test_sunset_initialization() {
    let mut sunset = Sunset::new();
    assert!(!sunset.is_initialized());

    let result = sunset.init(ADMIN, NONPROFIT_TREASURY);
    assert!(result.is_ok());
    assert!(sunset.is_initialized());
    assert_eq!(sunset.get_state(), SunsetState::Normal);
}

#[test]
fn test_sunset_cannot_init_twice() {
    let mut sunset = Sunset::new();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let result = sunset.init(ADMIN, NONPROFIT_TREASURY);
    assert_eq!(result, Err(SunsetError::AlreadyInitialized));
}

#[test]
fn test_sunset_spending_policies() {
    let mut sunset = Sunset::new();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    assert_eq!(sunset.get_spending_policy(), SpendingPolicy::Unrestricted);
    assert_eq!(sunset.get_current_spending_policy(), SpendingPolicy::Unrestricted);
}

#[test]
fn test_sunset_propose_valid_transitions() {
    let mut sunset = Sunset::new();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();
    sunset.set_current_timestamp(0);

    // Valid: NORMAL → RESTRICTED
    let result = sunset.propose_state_transition(
        SunsetState::Normal,
        SunsetState::Restricted,
        ADMIN,
    );
    assert!(result.is_ok());

    sunset.set_current_timestamp(0);
    // Valid: RESTRICTED → WIND_DOWN
    let result = sunset.propose_state_transition(
        SunsetState::Restricted,
        SunsetState::WindDown,
        ADMIN,
    );
    assert!(result.is_ok());

    sunset.set_current_timestamp(0);
    // Valid: WIND_DOWN → DISSOLVED
    let result = sunset.propose_state_transition(
        SunsetState::WindDown,
        SunsetState::Dissolved,
        ADMIN,
    );
    assert!(result.is_ok());
}

#[test]
fn test_sunset_reject_invalid_transitions() {
    let mut sunset = Sunset::new();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    // Invalid: NORMAL → DISSOLVED
    let result = sunset.propose_state_transition(
        SunsetState::Normal,
        SunsetState::Dissolved,
        ADMIN,
    );
    assert_eq!(result, Err(SunsetError::InvalidStateTransition));

    // Invalid: RESTRICTED → NORMAL
    let result = sunset.propose_state_transition(
        SunsetState::Restricted,
        SunsetState::Normal,
        ADMIN,
    );
    assert_eq!(result, Err(SunsetError::InvalidStateTransition));
}

#[test]
fn test_sunset_state_transition_with_timelock() {
    let mut sunset = Sunset::new();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();
    sunset.set_current_timestamp(0);

    let proposal_id = sunset.propose_state_transition(
        SunsetState::Normal,
        SunsetState::Restricted,
        ADMIN,
    ).unwrap();

    // Vote on proposal
    sunset.vote_on_transition(proposal_id, VOTER1, true, 100_000).unwrap();
    sunset.vote_on_transition(proposal_id, VOTER2, true, 100_000).unwrap();

    // Try to execute before timelock (14 days)
    let result = sunset.execute_state_transition(proposal_id);
    assert_eq!(result, Err(SunsetError::TimelockNotExpired));

    // Execute after timelock
    sunset.set_current_timestamp(SUNSET_STATE_TRANSITION_TIMELOCK + 1);
    let result = sunset.execute_state_transition(proposal_id);
    assert!(result.is_ok());

    assert_eq!(sunset.get_state(), SunsetState::Restricted);
}

#[test]
fn test_sunset_minimum_duration_restricted() {
    let mut sunset = Sunset::new();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();
    sunset.set_current_timestamp(0);

    // Transition to RESTRICTED
    let proposal1 = sunset.propose_state_transition(
        SunsetState::Normal,
        SunsetState::Restricted,
        ADMIN,
    ).unwrap();

    sunset.set_current_timestamp(SUNSET_STATE_TRANSITION_TIMELOCK + 1);
    sunset.execute_state_transition(proposal1).unwrap();
    assert_eq!(sunset.get_state(), SunsetState::Restricted);

    // Try to transition to WIND_DOWN before 90 days
    let proposal2 = sunset.propose_state_transition(
        SunsetState::Restricted,
        SunsetState::WindDown,
        ADMIN,
    ).unwrap();

    sunset.set_current_timestamp(SUNSET_STATE_TRANSITION_TIMELOCK + RESTRICTED_MIN_DURATION - 1);
    let result = sunset.execute_state_transition(proposal2);
    assert_eq!(result, Err(SunsetError::MinimumDurationNotMet));

    // Execute after 90 days
    sunset.set_current_timestamp(SUNSET_STATE_TRANSITION_TIMELOCK + RESTRICTED_MIN_DURATION + 1);
    let result = sunset.execute_state_transition(proposal2);
    assert!(result.is_ok());
    assert_eq!(sunset.get_state(), SunsetState::WindDown);
}

#[test]
fn test_sunset_state_transition_audit_trail() {
    let mut sunset = Sunset::new();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();
    sunset.set_current_timestamp(0);

    let proposal_id = sunset.propose_state_transition(
        SunsetState::Normal,
        SunsetState::Restricted,
        ADMIN,
    ).unwrap();

    sunset.set_current_timestamp(SUNSET_STATE_TRANSITION_TIMELOCK + 1);
    sunset.execute_state_transition(proposal_id).unwrap();

    let transitions = sunset.get_state_transitions();
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].1, SunsetState::Normal);
    assert_eq!(transitions[0].2, SunsetState::Restricted);
}

#[test]
fn test_sunset_complete_lifecycle() {
    let mut sunset = Sunset::new();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();
    sunset.set_current_timestamp(0);

    // NORMAL → RESTRICTED
    let p1 = sunset.propose_state_transition(SunsetState::Normal, SunsetState::Restricted, ADMIN).unwrap();
    sunset.set_current_timestamp(SUNSET_STATE_TRANSITION_TIMELOCK + 1);
    sunset.execute_state_transition(p1).unwrap();
    assert_eq!(sunset.get_state(), SunsetState::Restricted);

    // RESTRICTED → WIND_DOWN
    let p2 = sunset.propose_state_transition(SunsetState::Restricted, SunsetState::WindDown, ADMIN).unwrap();
    sunset.set_current_timestamp(SUNSET_STATE_TRANSITION_TIMELOCK + RESTRICTED_MIN_DURATION + 1);
    sunset.execute_state_transition(p2).unwrap();
    assert_eq!(sunset.get_state(), SunsetState::WindDown);

    // WIND_DOWN → DISSOLVED
    let p3 = sunset.propose_state_transition(SunsetState::WindDown, SunsetState::Dissolved, ADMIN).unwrap();
    sunset.set_current_timestamp(SUNSET_STATE_TRANSITION_TIMELOCK + RESTRICTED_MIN_DURATION + WIND_DOWN_MIN_DURATION + 1);
    sunset.execute_state_transition(p3).unwrap();
    assert_eq!(sunset.get_state(), SunsetState::Dissolved);
}

#[test]
fn test_week3_phase_gate_constants() {
    // DAO Treasury constants
    assert_eq!(DAO_ALLOCATION_PERCENTAGE, 6);
    assert_eq!(NUM_SECTOR_DAOS, 5);
    assert_eq!(PER_DAO_ALLOCATION_PERCENTAGE, 120); // 1.2%
    assert_eq!(DAO_TIMELOCK_SECONDS, 604_800); // 7 days

    // Sunset constants
    assert_eq!(RESTRICTED_MIN_DURATION, 7_776_000); // 90 days
    assert_eq!(WIND_DOWN_MIN_DURATION, 15_552_000); // 180 days
    assert_eq!(FINAL_PAYOUT_TO_NONPROFIT_PERCENTAGE, 100);
    assert_eq!(SUNSET_STATE_TRANSITION_TIMELOCK, 1_209_600); // 14 days
}

#[test]
fn test_week3_all_contracts_initialized() {
    let mut dao_treasury = DaoTreasury::new();
    let mut sunset = Sunset::new();

    assert!(!dao_treasury.is_initialized());
    assert!(!sunset.is_initialized());

    dao_treasury.init("TestDAO".to_string(), ADMIN, GOVERNANCE).unwrap();
    sunset.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    assert!(dao_treasury.is_initialized());
    assert!(sunset.is_initialized());
}
