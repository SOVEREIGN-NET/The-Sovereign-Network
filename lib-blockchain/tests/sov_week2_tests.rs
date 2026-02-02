//! Week 2 Comprehensive Unit Tests
//!
//! Tests for Governance, NonprofitTreasury, ForProfitTreasury, and TributeRouter contracts.
//!
//! Tests validate:
//! - Governance: Proposal creation, voting, timelock enforcement
//! - NonprofitTreasury: Deposit receipt, withdrawal requests, fund isolation
//! - ForProfitTreasury: Profit tracking, tribute enforcement, spending guards
//! - TributeRouter: 20% tribute enforcement, anti-circumvention rules
//!
//! Critical Constants Validated:
//! - VOTING_PERIOD_SECONDS = 604,800 (7 days)
//! - TIMELOCK_DELAY_SECONDS = 172,800 (2 days)
//! - MAJORITY_THRESHOLD = 5,001 basis points (50.01%)
//! - SUPERMAJORITY_THRESHOLD = 6,667 basis points (66.67%)
//! - MANDATORY_TRIBUTE_PERCENTAGE = 20%

// Include contract modules
use lib_blockchain::contracts::governance::*;
use lib_blockchain::contracts::treasuries::*;
use lib_blockchain::contracts::economics::*;

// ============================================================================
// TEST CONSTANTS
// ============================================================================

const ADMIN: [u8; 32] = [1u8; 32];
const NONPROFIT_TREASURY: [u8; 32] = [2u8; 32];
const FOR_PROFIT_TREASURY: [u8; 32] = [3u8; 32];
const PROPOSER: [u8; 32] = [4u8; 32];
const VOTER1: [u8; 32] = [5u8; 32];
const VOTER2: [u8; 32] = [6u8; 32];
const VOTER3: [u8; 32] = [7u8; 32];

const VOTING_POWER_BASE: u64 = 100_000 * 10_u64.pow(8); // 100k with 8 decimals
const TEST_TOTAL_VOTING_POWER: u64 = 1_000_000; // Smaller value for easier test math

// ============================================================================
// GOVERNANCE TESTS
// ============================================================================

#[test]
fn test_governance_initialization() {
    let mut governance = Governance::new();
    assert!(!governance.is_initialized());

    let result = governance.init(ADMIN);
    assert!(result.is_ok());
    assert!(governance.is_initialized());
    assert_eq!(governance.get_admin(), Some(ADMIN));
}

#[test]
fn test_governance_cannot_init_twice() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();

    let result = governance.init(ADMIN);
    assert_eq!(result, Err(GovernanceError::AlreadyInitialized));
}

#[test]
fn test_governance_voting_period_constant() {
    assert_eq!(VOTING_PERIOD_SECONDS, 604_800, "Voting period must be exactly 7 days");
    assert_eq!(TIMELOCK_DELAY_SECONDS, 172_800, "Timelock must be exactly 2 days");
}

#[test]
fn test_governance_create_proposal_requires_voting_power() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(VOTING_POWER_BASE * 10);

    // Insufficient voting power
    let result = governance.create_proposal(
        PROPOSER,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL - 1,
    );
    assert_eq!(result, Err(GovernanceError::InsufficientVotingPower));
}

#[test]
fn test_governance_create_proposal_success() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(VOTING_POWER_BASE * 10);

    let result = governance.create_proposal(
        PROPOSER,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    );

    assert!(result.is_ok());
    let proposal_id = result.unwrap();
    assert_eq!(proposal_id, 1);

    let proposal = governance.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.title, "Test Proposal");
    assert_eq!(proposal.status, ProposalStatus::Active);
}

#[test]
fn test_governance_cannot_create_proposal_with_empty_title() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(VOTING_POWER_BASE * 10);

    let result = governance.create_proposal(
        PROPOSER,
        "".to_string(),
        "Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    );
    assert_eq!(result, Err(GovernanceError::EmptyTitle));
}

#[test]
fn test_governance_cannot_create_proposal_with_empty_description() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(VOTING_POWER_BASE * 10);

    let result = governance.create_proposal(
        PROPOSER,
        "Title".to_string(),
        "".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    );
    assert_eq!(result, Err(GovernanceError::EmptyDescription));
}

#[test]
fn test_governance_voting_flow() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(VOTING_POWER_BASE * 10);
    governance.set_current_timestamp(0);

    let proposal_id = governance.create_proposal(
        PROPOSER,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Vote during voting period
    let vote_result = governance.vote(
        proposal_id,
        VOTER1,
        VoteType::For,
        VOTING_POWER_BASE,
    );
    assert!(vote_result.is_ok());

    let proposal = governance.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.votes_for, VOTING_POWER_BASE);
}

#[test]
fn test_governance_cannot_vote_twice() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(VOTING_POWER_BASE * 10);
    governance.set_current_timestamp(0);

    let proposal_id = governance.create_proposal(
        PROPOSER,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    governance.vote(proposal_id, VOTER1, VoteType::For, VOTING_POWER_BASE).unwrap();

    let result = governance.vote(proposal_id, VOTER1, VoteType::For, VOTING_POWER_BASE);
    assert_eq!(result, Err(GovernanceError::AlreadyVoted));
}

#[test]
fn test_governance_voting_period_check() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(VOTING_POWER_BASE * 10);
    governance.set_current_timestamp(0);

    let proposal_id = governance.create_proposal(
        PROPOSER,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Try to vote before voting starts
    governance.set_current_timestamp(0);
    let result = governance.vote(proposal_id, VOTER1, VoteType::For, VOTING_POWER_BASE);
    assert!(result.is_ok());

    // Try to vote after voting period ends
    governance.set_current_timestamp(VOTING_PERIOD_SECONDS + 1);
    let result = governance.vote(proposal_id, VOTER2, VoteType::For, VOTING_POWER_BASE);
    assert_eq!(result, Err(GovernanceError::VotingPeriodEnded));
}

#[test]
fn test_governance_finalize_voting_majority_passes() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(TEST_TOTAL_VOTING_POWER);
    governance.set_current_timestamp(0);

    let proposal_id = governance.create_proposal(
        PROPOSER,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Vote: 60% for, 40% against (total = 100% meets quorum)
    governance.vote(proposal_id, VOTER1, VoteType::For, 600_000).unwrap();
    governance.vote(proposal_id, VOTER2, VoteType::Against, 400_000).unwrap();

    // Finalize after voting period
    governance.set_current_timestamp(VOTING_PERIOD_SECONDS + 1);
    governance.finalize_voting(proposal_id).unwrap();

    let proposal = governance.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Approved);
}

#[test]
fn test_governance_finalize_voting_majority_fails() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(TEST_TOTAL_VOTING_POWER);
    governance.set_current_timestamp(0);

    let proposal_id = governance.create_proposal(
        PROPOSER,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Vote: 40% for, 60% against (fails majority, total = 100% meets quorum)
    governance.vote(proposal_id, VOTER1, VoteType::For, 400_000).unwrap();
    governance.vote(proposal_id, VOTER2, VoteType::Against, 600_000).unwrap();

    governance.set_current_timestamp(VOTING_PERIOD_SECONDS + 1);
    governance.finalize_voting(proposal_id).unwrap();

    let proposal = governance.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Rejected);
}

#[test]
fn test_governance_timelock_enforcement() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(TEST_TOTAL_VOTING_POWER);
    governance.set_current_timestamp(0);

    let proposal_id = governance.create_proposal(
        PROPOSER,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Vote with enough power to meet quorum (>50% of 1M = >500K)
    governance.vote(proposal_id, VOTER1, VoteType::For, 600_000).unwrap();
    governance.set_current_timestamp(VOTING_PERIOD_SECONDS + 1);
    governance.finalize_voting(proposal_id).unwrap();

    // Try to execute before timelock
    let result = governance.execute_proposal(proposal_id);
    assert_eq!(result, Err(GovernanceError::TimelockNotExpired));

    // Execute after timelock
    governance.set_current_timestamp(VOTING_PERIOD_SECONDS + TIMELOCK_DELAY_SECONDS + 1);
    let result = governance.execute_proposal(proposal_id);
    assert!(result.is_ok());

    let proposal = governance.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Executed);
}

#[test]
fn test_governance_supermajority_threshold() {
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(TEST_TOTAL_VOTING_POWER);
    governance.set_current_timestamp(0);

    let proposal_id = governance.create_proposal(
        PROPOSER,
        "Constitutional Amendment".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Constitutional,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // Vote: 65% for (below 66.67% supermajority), total = 100% meets quorum
    governance.vote(proposal_id, VOTER1, VoteType::For, 650_000).unwrap();
    governance.vote(proposal_id, VOTER2, VoteType::Against, 350_000).unwrap();

    governance.set_current_timestamp(VOTING_PERIOD_SECONDS + 1);
    governance.finalize_voting(proposal_id).unwrap();

    let proposal = governance.get_proposal(proposal_id).unwrap();
    assert_eq!(proposal.status, ProposalStatus::Rejected);

    // Vote: 67% for (meets supermajority)
    governance.set_current_timestamp(0);
    let proposal_id2 = governance.create_proposal(
        PROPOSER,
        "Constitutional Amendment 2".to_string(),
        "Test Description".to_string(),
        ProposalCategory::Constitutional,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    governance.vote(proposal_id2, VOTER1, VoteType::For, 670_000).unwrap();
    governance.vote(proposal_id2, VOTER2, VoteType::Against, 330_000).unwrap();

    governance.set_current_timestamp(VOTING_PERIOD_SECONDS + 1);
    governance.finalize_voting(proposal_id2).unwrap();

    let proposal2 = governance.get_proposal(proposal_id2).unwrap();
    assert_eq!(proposal2.status, ProposalStatus::Approved);
}

// ============================================================================
// NONPROFIT TREASURY TESTS
// ============================================================================

#[test]
fn test_nonprofit_treasury_initialization() {
    let mut treasury = NonprofitTreasury::new();
    assert!(!treasury.is_initialized());

    let result = treasury.init(ADMIN, FOR_PROFIT_TREASURY);
    assert!(result.is_ok());
    assert!(treasury.is_initialized());
}

#[test]
fn test_nonprofit_treasury_cannot_init_twice() {
    let mut treasury = NonprofitTreasury::new();
    treasury.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();

    let result = treasury.init(ADMIN, FOR_PROFIT_TREASURY);
    assert_eq!(result, Err(NonprofitTreasuryError::AlreadyInitialized));
}

#[test]
fn test_nonprofit_treasury_receive_funds() {
    let mut treasury = NonprofitTreasury::new();
    treasury.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();

    let result = treasury.receive(FOR_PROFIT_TREASURY, 1_000_000);
    assert!(result.is_ok());
    assert_eq!(treasury.balance(), 1_000_000);
    assert_eq!(treasury.total_received(), 1_000_000);
}

#[test]
fn test_nonprofit_treasury_rejects_unauthorized_source() {
    let mut treasury = NonprofitTreasury::new();
    treasury.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();

    let result = treasury.receive(ADMIN, 1_000_000);
    assert_eq!(result, Err(NonprofitTreasuryError::UnauthorizedSource));
    assert_eq!(treasury.balance(), 0);
}

#[test]
fn test_nonprofit_treasury_multiple_deposits() {
    let mut treasury = NonprofitTreasury::new();
    treasury.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();

    treasury.receive(FOR_PROFIT_TREASURY, 500_000).unwrap();
    treasury.receive(FOR_PROFIT_TREASURY, 300_000).unwrap();
    treasury.receive(FOR_PROFIT_TREASURY, 200_000).unwrap();

    assert_eq!(treasury.balance(), 1_000_000);
    assert_eq!(treasury.total_received(), 1_000_000);
}

#[test]
fn test_nonprofit_treasury_withdrawal_request() {
    let mut treasury = NonprofitTreasury::new();
    treasury.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();
    treasury.receive(FOR_PROFIT_TREASURY, 1_000_000).unwrap();

    let result = treasury.request_withdrawal(ADMIN, 500_000, 1);
    assert!(result.is_ok());

    let request_id = result.unwrap();
    let request = treasury.get_withdrawal_request(request_id).unwrap();
    assert_eq!(request.status, WithdrawalStatus::Pending);
    assert_eq!(request.amount, 500_000);
}

#[test]
fn test_nonprofit_treasury_cannot_withdraw_more_than_balance() {
    let mut treasury = NonprofitTreasury::new();
    treasury.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();
    treasury.receive(FOR_PROFIT_TREASURY, 500_000).unwrap();

    let result = treasury.request_withdrawal(ADMIN, 600_000, 1);
    assert_eq!(result, Err(NonprofitTreasuryError::InsufficientBalance));
}

#[test]
fn test_nonprofit_treasury_withdrawal_approval_and_execution() {
    let mut treasury = NonprofitTreasury::new();
    treasury.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();
    treasury.receive(FOR_PROFIT_TREASURY, 1_000_000).unwrap();

    let request_id = treasury.request_withdrawal(ADMIN, 500_000, 1).unwrap();

    // Approve
    let result = treasury.approve_withdrawal(request_id, ADMIN);
    assert!(result.is_ok());

    // Execute
    let result = treasury.execute_withdrawal(request_id, ADMIN);
    assert!(result.is_ok());

    let request = treasury.get_withdrawal_request(request_id).unwrap();
    assert_eq!(request.status, WithdrawalStatus::Executed);
    assert_eq!(treasury.balance(), 500_000);
    assert_eq!(treasury.total_withdrawn(), 500_000);
}

#[test]
fn test_nonprofit_treasury_audit_trail() {
    let mut treasury = NonprofitTreasury::new();
    treasury.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();
    treasury.receive(FOR_PROFIT_TREASURY, 1_000_000).unwrap();

    let transactions = treasury.get_transactions();
    assert_eq!(transactions.len(), 1);

    let tx = transactions.get(&1).unwrap();
    assert_eq!(tx.transaction_type, TransactionType::Deposit);
    assert_eq!(tx.amount, 1_000_000);
}

// ============================================================================
// FORPROFIT TREASURY TESTS
// ============================================================================

#[test]
fn test_forprofit_treasury_initialization() {
    let mut treasury = ForProfitTreasury::new();
    assert!(!treasury.is_initialized());

    let result = treasury.init(ADMIN, NONPROFIT_TREASURY);
    assert!(result.is_ok());
    assert!(treasury.is_initialized());
}

#[test]
fn test_forprofit_treasury_profit_declaration() {
    let mut treasury = ForProfitTreasury::new();
    treasury.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let result = treasury.declare_profit(1_000_000, ADMIN, None);
    assert!(result.is_ok());

    let declaration_id = result.unwrap();
    let declaration = treasury.get_profit_declaration(declaration_id).unwrap();

    // Verify tribute calculation (20%)
    assert_eq!(declaration.profit_amount, 1_000_000);
    assert_eq!(declaration.tribute_amount, 200_000);
}

#[test]
fn test_forprofit_treasury_tribute_enforcement() {
    let mut treasury = ForProfitTreasury::new();
    treasury.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let declaration_id = treasury.declare_profit(1_000_000, ADMIN, None).unwrap();

    // Verify tribute cannot be paid twice
    let result = treasury.settle_tribute(declaration_id, ADMIN);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 200_000);

    let result = treasury.settle_tribute(declaration_id, ADMIN);
    assert_eq!(result, Err(ForProfitTreasuryError::TributePending));
}

#[test]
fn test_forprofit_treasury_no_dividend_before_tribute() {
    let mut treasury = ForProfitTreasury::new();
    treasury.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let _declaration_id = treasury.declare_profit(1_000_000, ADMIN, None).unwrap();

    // Try to pay dividend before tribute
    let result = treasury.spend(
        SpendingCategory::Dividend,
         100_000,
        ADMIN,
        "Dividend".to_string(),
        ADMIN,
    );
    assert_eq!(result, Err(ForProfitTreasuryError::DividendBeforeTribute));
}

#[test]
fn test_forprofit_treasury_spending_after_tribute() {
    let mut treasury = ForProfitTreasury::new();
    treasury.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let declaration_id = treasury.declare_profit(1_000_000, ADMIN, None).unwrap();
    treasury.settle_tribute(declaration_id, ADMIN).unwrap();

    // Now dividend should work
    let result = treasury.spend(
        SpendingCategory::Dividend,
        100_000,
        ADMIN,
        "Dividend".to_string(),
        ADMIN,
    );
    assert!(result.is_ok());
}

#[test]
fn test_forprofit_treasury_operations_spending() {
    let mut treasury = ForProfitTreasury::new();
    treasury.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let _declaration_id = treasury.declare_profit(1_000_000, ADMIN, None).unwrap();

    // Operations spending should work anytime
    let result = treasury.spend(
        SpendingCategory::Operations,
        100_000,
        ADMIN,
        "Salaries".to_string(),
        ADMIN,
    );
    assert!(result.is_ok());
}

#[test]
fn test_forprofit_treasury_spending_guards() {
    let mut treasury = ForProfitTreasury::new();
    treasury.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let _declaration_id = treasury.declare_profit(1_000_000, ADMIN, None).unwrap();

    // Large dividend without tribute should fail
    let result = treasury.spend(
        SpendingCategory::Dividend,
        600_000, // 60% of profit
        ADMIN,
        "Large Dividend".to_string(),
        ADMIN,
    );
    assert_eq!(result, Err(ForProfitTreasuryError::DividendBeforeTribute));
}

#[test]
fn test_forprofit_treasury_accurate_balance() {
    let mut treasury = ForProfitTreasury::new();
    treasury.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    treasury.declare_profit(1_000_000, ADMIN, None).unwrap();
    assert_eq!(treasury.balance(), 1_000_000);

    let declaration_id = treasury.declare_profit(500_000, ADMIN, None).unwrap();
    assert_eq!(treasury.balance(), 1_500_000);

    treasury.settle_tribute(declaration_id, ADMIN).unwrap();
    assert_eq!(treasury.balance(), 1_500_000 - 100_000); // 500k * 20%
    assert_eq!(treasury.total_tribute_paid(), 100_000);
}

// ============================================================================
// TRIBUTE ROUTER TESTS
// ============================================================================

#[test]
fn test_tribute_router_initialization() {
    let mut router = TributeRouter::new();
    assert!(!router.is_initialized());

    let result = router.init(ADMIN, NONPROFIT_TREASURY);
    assert!(result.is_ok());
    assert!(router.is_initialized());
}

#[test]
fn test_tribute_router_profit_declaration() {
    let mut router = TributeRouter::new();
    router.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let result = router.declare_profit(
        ADMIN,
        1_000_000,
        None,
        "Q1 Profit".to_string(),
    );

    assert!(result.is_ok());
    let settlement = router.get_settlement(result.unwrap()).unwrap();
    assert_eq!(settlement.tribute_amount, 200_000);
}

#[test]
fn test_tribute_router_tribute_routing() {
    let mut router = TributeRouter::new();
    router.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let settlement_id = router.declare_profit(
        ADMIN,
        1_000_000,
        None,
        "Profit".to_string(),
    ).unwrap();

    let result = router.settle_tribute(settlement_id);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 200_000);

    assert!(router.is_tribute_settled(settlement_id));
    assert_eq!(router.total_tribute_collected(), 200_000);
}

#[test]
fn test_tribute_router_multiple_profits() {
    let mut router = TributeRouter::new();
    router.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    // Declare multiple profits
    router.set_current_timestamp(0);
    let id1 = router.declare_profit(ADMIN, 1_000_000, None, "Q1".to_string()).unwrap();

    // Advance time to avoid anti-circumvention rule
    router.set_current_timestamp(86400 + 1);
    let id2 = router.declare_profit(ADMIN, 500_000, None, "Q2".to_string()).unwrap();

    router.settle_tribute(id1).unwrap();
    router.settle_tribute(id2).unwrap();

    assert_eq!(router.total_profit_declared(), 1_500_000);
    assert_eq!(router.total_tribute_collected(), 300_000); // 20% of 1.5M
}

#[test]
fn test_tribute_router_zero_profit_rejected() {
    let mut router = TributeRouter::new();
    router.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let result = router.declare_profit(ADMIN, 0, None, "No Profit".to_string());
    assert_eq!(result, Err(TributeRouterError::ZeroProfit));
}

#[test]
fn test_tribute_router_anti_circumvention_min_interval() {
    let mut router = TributeRouter::new();
    router.init(ADMIN, NONPROFIT_TREASURY).unwrap();
    router.set_current_timestamp(0);

    // First declaration at timestamp 0
    let _id1 = router.declare_profit(ADMIN, 1_000_000, None, "Profit 1".to_string()).unwrap();

    // Try declaration before minimum interval (1 day)
    router.set_current_timestamp(43200); // 12 hours later
    let result = router.declare_profit(ADMIN, 1_000_000, None, "Profit 2".to_string());
    assert_eq!(result, Err(TributeRouterError::CircumventionAttempt));

    // After minimum interval, should work
    router.set_current_timestamp(86400 + 1);
    let result = router.declare_profit(ADMIN, 1_000_000, None, "Profit 2".to_string());
    assert!(result.is_ok());
}

#[test]
fn test_tribute_router_consistent_20_percent_calculation() {
    let mut router = TributeRouter::new();
    router.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    // Test various profit amounts
    let test_cases = vec![
        (100_000, 20_000),
        (1_000_000, 200_000),
        (5_000_000, 1_000_000),
        (10_000_000, 2_000_000),
    ];

    for (i, (profit, expected_tribute)) in test_cases.iter().enumerate() {
        // Advance time between declarations to avoid anti-circumvention rule
        router.set_current_timestamp(86400 * (i as u64 + 1));

        let settlement_id = router.declare_profit(
            ADMIN,
            *profit,
            None,
            format!("Test {}", i),
        ).unwrap();

        let settlement = router.get_settlement(settlement_id).unwrap();
        assert_eq!(settlement.tribute_amount, *expected_tribute, "Tribute calculation failed for profit {}", profit);
    }
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_week2_complete_flow() {
    // Initialize all contracts
    let mut governance = Governance::new();
    governance.init(ADMIN).unwrap();
    governance.update_total_voting_power(TEST_TOTAL_VOTING_POWER);
    governance.set_current_timestamp(0);

    let mut nonprofit = NonprofitTreasury::new();
    nonprofit.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();

    let mut forprofit = ForProfitTreasury::new();
    forprofit.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    let mut router = TributeRouter::new();
    router.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    // 1. For-profit declares profit
    let forprofit_declaration = forprofit.declare_profit(1_000_000, ADMIN, None).unwrap();

    // 2. Tribute is settled
    forprofit.settle_tribute(forprofit_declaration, ADMIN).unwrap();

    // 3. Simulate transfer of tribute to nonprofit (in real system, this is enforced by contract calls)
    nonprofit.receive(FOR_PROFIT_TREASURY, 200_000).unwrap();

    // 4. Create governance proposal to spend nonprofit funds
    let proposal_id = governance.create_proposal(
        PROPOSER,
        "Community Grant".to_string(),
        "Allocate nonprofit funds for community good".to_string(),
        ProposalCategory::Regular,
        MIN_VOTING_POWER_FOR_PROPOSAL,
    ).unwrap();

    // 5. Vote on proposal (>50% of TEST_TOTAL_VOTING_POWER to meet quorum)
    governance.vote(proposal_id, VOTER1, VoteType::For, 600_000).unwrap();

    // 6. Finalize voting
    governance.set_current_timestamp(VOTING_PERIOD_SECONDS + 1);
    governance.finalize_voting(proposal_id).unwrap();

    // 7. Request withdrawal from nonprofit (after proposal approval)
    let withdrawal = nonprofit.request_withdrawal(ADMIN, 100_000, proposal_id).unwrap();
    nonprofit.approve_withdrawal(withdrawal, ADMIN).unwrap();
    nonprofit.execute_withdrawal(withdrawal, ADMIN).unwrap();

    // Verify final state
    assert_eq!(nonprofit.balance(), 100_000); // 200k received - 100k withdrawn
    assert_eq!(nonprofit.total_withdrawn(), 100_000);
    assert_eq!(forprofit.total_tribute_paid(), 200_000);
    assert_eq!(router.total_tribute_collected(), 0); // Router is separate layer
    assert_eq!(governance.get_proposal(proposal_id).unwrap().status, ProposalStatus::Approved);
}

#[test]
fn test_week2_phase_gate_constants() {
    // Verify all critical constants
    assert_eq!(VOTING_PERIOD_SECONDS, 604_800);
    assert_eq!(TIMELOCK_DELAY_SECONDS, 172_800);
    assert_eq!(MAJORITY_THRESHOLD_BASIS_POINTS, 5_001);
    assert_eq!(SUPERMAJORITY_THRESHOLD_BASIS_POINTS, 6_667);
    assert_eq!(MANDATORY_TRIBUTE_PERCENTAGE, 20);
    assert_eq!(NONPROFIT_ALLOCATION_PERCENTAGE, 20);
    assert_eq!(TRIBUTE_RATE_PERCENTAGE, 20);
}

#[test]
fn test_week2_all_contracts_initialized() {
    let mut governance = Governance::new();
    let mut nonprofit = NonprofitTreasury::new();
    let mut forprofit = ForProfitTreasury::new();
    let mut router = TributeRouter::new();

    assert!(!governance.is_initialized());
    assert!(!nonprofit.is_initialized());
    assert!(!forprofit.is_initialized());
    assert!(!router.is_initialized());

    governance.init(ADMIN).unwrap();
    nonprofit.init(ADMIN, FOR_PROFIT_TREASURY).unwrap();
    forprofit.init(ADMIN, NONPROFIT_TREASURY).unwrap();
    router.init(ADMIN, NONPROFIT_TREASURY).unwrap();

    assert!(governance.is_initialized());
    assert!(nonprofit.is_initialized());
    assert!(forprofit.is_initialized());
    assert!(router.is_initialized());
}
