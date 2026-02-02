//! Phase 3D Tests - TokenContract Governance Config Updates
//!
//! Tests for restricted, consensus-safe governance config updates:
//! - Unauthorized calls rejected
//! - Authorized calls change only the intended field
//! - Changes persisted after restart/import

use lib_blockchain::contracts::tokens::spec_v2::{
    AuthoritySet, ContractError, FeeSchedule, Role, TokenContractV2,
    TokenCreationParams, TransferPolicy, SupplyPolicy, EmissionModel,
};
use lib_blockchain::transaction::core::{
    GovernanceConfigOperation, GovernanceConfigUpdateData,
};

// =============================================================================
// Test Helpers
// =============================================================================

fn test_address(n: u8) -> [u8; 32] {
    let mut addr = [0u8; 32];
    addr[0] = n;
    addr
}

fn test_token_id() -> [u8; 32] {
    [1u8; 32]
}

fn create_test_token_with_governance(governance_addr: [u8; 32]) -> TokenContractV2 {
    let treasury = test_address(1);

    let mut authorities = AuthoritySet::new();
    authorities.add(Role::Governance, governance_addr);

    let params = TokenCreationParams {
        token_id: test_token_id(),
        name: "Test Token".to_string(),
        symbol: "TST".to_string(),
        decimals: 8,
        metadata_hash: [0u8; 32],
        supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000_000 },
        emission_model: EmissionModel::None,
        fee_schedule: FeeSchedule::zero(),
        transfer_policy: TransferPolicy::Free,
        authorities,
        treasury_address: treasury,
        fee_recipient: None,
        pause_authority: Role::Governance,
        initial_allocations: vec![],
    };

    TokenContractV2::new_at_genesis(params).unwrap()
}

// =============================================================================
// Test: Unauthorized Rejected
// =============================================================================

#[test]
fn test_unauthorized_set_fee_schedule_rejected() {
    let governance = test_address(2);
    let attacker = test_address(3);

    let mut token = create_test_token_with_governance(governance);

    // Attacker tries to update fee schedule
    let new_schedule = FeeSchedule {
        transfer_fee_bps: 500,
        burn_fee_bps: 100,
        fee_cap_amount: 0,
        min_fee_amount: 0,
    };

    let result = token.update_fee_schedule(&attacker, new_schedule);
    assert!(matches!(result, Err(ContractError::Unauthorized(_))));

    // Verify fee schedule unchanged
    assert_eq!(token.economic_config.fee_schedule.transfer_fee_bps, 0);
}

#[test]
fn test_unauthorized_set_transfer_policy_rejected() {
    let governance = test_address(2);
    let attacker = test_address(3);

    let mut token = create_test_token_with_governance(governance);

    // Attacker tries to update transfer policy
    let result = token.update_transfer_policy(&attacker, TransferPolicy::NonTransferable);
    assert!(matches!(result, Err(ContractError::Unauthorized(_))));

    // Verify transfer policy unchanged
    assert!(matches!(token.economic_config.transfer_policy, TransferPolicy::Free));
}

#[test]
fn test_unauthorized_pause_rejected() {
    let governance = test_address(2);
    let attacker = test_address(3);

    let mut token = create_test_token_with_governance(governance);

    // Attacker tries to pause
    let result = token.pause(&attacker, true);
    assert!(matches!(result, Err(ContractError::Unauthorized(_))));

    // Verify not paused
    assert!(!token.paused);
}

// =============================================================================
// Test: Authorized Changes Only Intended Field
// =============================================================================

#[test]
fn test_authorized_set_fee_schedule_changes_only_fees() {
    let governance = test_address(2);

    let mut token = create_test_token_with_governance(governance);

    // Capture state before
    let policy_before = token.economic_config.transfer_policy.clone();
    let paused_before = token.paused;
    let total_supply_before = token.total_supply;

    // Governance updates fee schedule
    let new_schedule = FeeSchedule {
        transfer_fee_bps: 500,  // 5%
        burn_fee_bps: 100,      // 1%
        fee_cap_amount: 1000,
        min_fee_amount: 10,
    };

    let result = token.update_fee_schedule(&governance, new_schedule.clone());
    assert!(result.is_ok());

    // Verify fee schedule changed
    assert_eq!(token.economic_config.fee_schedule.transfer_fee_bps, 500);
    assert_eq!(token.economic_config.fee_schedule.burn_fee_bps, 100);
    assert_eq!(token.economic_config.fee_schedule.fee_cap_amount, 1000);
    assert_eq!(token.economic_config.fee_schedule.min_fee_amount, 10);

    // Verify other fields unchanged
    assert_eq!(token.economic_config.transfer_policy, policy_before);
    assert_eq!(token.paused, paused_before);
    assert_eq!(token.total_supply, total_supply_before);
}

#[test]
fn test_authorized_set_transfer_policy_changes_only_policy() {
    let governance = test_address(2);

    let mut token = create_test_token_with_governance(governance);

    // Capture state before
    let fees_before = token.economic_config.fee_schedule.clone();
    let paused_before = token.paused;
    let total_supply_before = token.total_supply;

    // Governance updates transfer policy
    let result = token.update_transfer_policy(&governance, TransferPolicy::NonTransferable);
    assert!(result.is_ok());

    // Verify transfer policy changed
    assert!(matches!(
        token.economic_config.transfer_policy,
        TransferPolicy::NonTransferable
    ));

    // Verify other fields unchanged
    assert_eq!(token.economic_config.fee_schedule, fees_before);
    assert_eq!(token.paused, paused_before);
    assert_eq!(token.total_supply, total_supply_before);
}

#[test]
fn test_authorized_pause_changes_only_paused() {
    let governance = test_address(2);

    let mut token = create_test_token_with_governance(governance);

    // Capture state before
    let fees_before = token.economic_config.fee_schedule.clone();
    let policy_before = token.economic_config.transfer_policy.clone();
    let total_supply_before = token.total_supply;

    // Governance pauses
    let result = token.pause(&governance, true);
    assert!(result.is_ok());

    // Verify paused changed
    assert!(token.paused);

    // Verify other fields unchanged
    assert_eq!(token.economic_config.fee_schedule, fees_before);
    assert_eq!(token.economic_config.transfer_policy, policy_before);
    assert_eq!(token.total_supply, total_supply_before);

    // Governance unpauses
    let result = token.pause(&governance, false);
    assert!(result.is_ok());
    assert!(!token.paused);
}

// =============================================================================
// Test: Validation of Config Update Data
// =============================================================================

#[test]
fn test_governance_config_data_validates_fee_schedule() {
    // Valid fee schedule
    let valid = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetFeeSchedule {
            transfer_fee_bps: 500,
            burn_fee_bps: 100,
            fee_cap_amount: 1000,
            min_fee_amount: 10,
        },
        nonce: 1,
        timestamp: 12345,
    };
    assert!(valid.validate());

    // Invalid: transfer_fee_bps > 10000
    let invalid_transfer = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetFeeSchedule {
            transfer_fee_bps: 15000, // > 100%
            burn_fee_bps: 100,
            fee_cap_amount: 1000,
            min_fee_amount: 10,
        },
        nonce: 1,
        timestamp: 12345,
    };
    assert!(!invalid_transfer.validate());

    // Invalid: burn_fee_bps > 10000
    let invalid_burn = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetFeeSchedule {
            transfer_fee_bps: 500,
            burn_fee_bps: 12000, // > 100%
            fee_cap_amount: 1000,
            min_fee_amount: 10,
        },
        nonce: 1,
        timestamp: 12345,
    };
    assert!(!invalid_burn.validate());
}

#[test]
fn test_governance_config_data_validates_transfer_policy() {
    // Valid policies
    for policy in ["Free", "AllowlistOnly", "NonTransferable"] {
        let valid = GovernanceConfigUpdateData {
            token_id: test_token_id(),
            caller: test_address(2),
            operation: GovernanceConfigOperation::SetTransferPolicy {
                policy: policy.to_string(),
            },
            nonce: 1,
            timestamp: 12345,
        };
        assert!(valid.validate(), "Policy {} should be valid", policy);
    }

    // Invalid: ComplianceGated not allowed
    let invalid = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetTransferPolicy {
            policy: "ComplianceGated".to_string(),
        },
        nonce: 1,
        timestamp: 12345,
    };
    assert!(!invalid.validate());

    // Invalid: Unknown policy
    let invalid_unknown = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetTransferPolicy {
            policy: "SomeOtherPolicy".to_string(),
        },
        nonce: 1,
        timestamp: 12345,
    };
    assert!(!invalid_unknown.validate());
}

#[test]
fn test_governance_config_data_validates_set_paused() {
    // SetPaused is always valid
    let pause = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetPaused { paused: true },
        nonce: 1,
        timestamp: 12345,
    };
    assert!(pause.validate());

    let unpause = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetPaused { paused: false },
        nonce: 1,
        timestamp: 12345,
    };
    assert!(unpause.validate());
}

// =============================================================================
// Test: ComplianceGated Policy Rejected
// =============================================================================

#[test]
fn test_compliance_gated_policy_rejected() {
    let governance = test_address(2);

    let mut token = create_test_token_with_governance(governance);

    // Try to set ComplianceGated policy
    let result = token.update_transfer_policy(
        &governance,
        TransferPolicy::ComplianceGated { gate_contract: test_address(99) }
    );

    assert!(matches!(result, Err(ContractError::TransferPolicyNotAllowed)));

    // Verify transfer policy unchanged
    assert!(matches!(token.economic_config.transfer_policy, TransferPolicy::Free));
}

// =============================================================================
// Test: Operations When Paused
// =============================================================================

#[test]
fn test_fee_schedule_update_rejected_when_paused() {
    let governance = test_address(2);

    let mut token = create_test_token_with_governance(governance);

    // Pause the contract
    token.pause(&governance, true).unwrap();

    // Try to update fee schedule
    let new_schedule = FeeSchedule {
        transfer_fee_bps: 500,
        burn_fee_bps: 100,
        fee_cap_amount: 0,
        min_fee_amount: 0,
    };

    let result = token.update_fee_schedule(&governance, new_schedule);
    assert!(matches!(result, Err(ContractError::Paused)));
}

#[test]
fn test_transfer_policy_update_rejected_when_paused() {
    let governance = test_address(2);

    let mut token = create_test_token_with_governance(governance);

    // Pause the contract
    token.pause(&governance, true).unwrap();

    // Try to update transfer policy
    let result = token.update_transfer_policy(&governance, TransferPolicy::NonTransferable);
    assert!(matches!(result, Err(ContractError::Paused)));
}

#[test]
fn test_unpause_allowed_when_paused() {
    let governance = test_address(2);

    let mut token = create_test_token_with_governance(governance);

    // Pause the contract
    token.pause(&governance, true).unwrap();
    assert!(token.paused);

    // Unpause should still work
    let result = token.pause(&governance, false);
    assert!(result.is_ok());
    assert!(!token.paused);
}

// =============================================================================
// Test: Invariants Preserved After Updates
// =============================================================================

#[test]
fn test_invariants_preserved_after_fee_schedule_update() {
    let governance = test_address(2);
    let user = test_address(3);

    // Create token with initial allocation
    let treasury = test_address(1);
    let mut authorities = AuthoritySet::new();
    authorities.add(Role::Governance, governance);

    let params = TokenCreationParams {
        token_id: test_token_id(),
        name: "Test Token".to_string(),
        symbol: "TST".to_string(),
        decimals: 8,
        metadata_hash: [0u8; 32],
        supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000_000 },
        emission_model: EmissionModel::None,
        fee_schedule: FeeSchedule::zero(),
        transfer_policy: TransferPolicy::Free,
        authorities,
        treasury_address: treasury,
        fee_recipient: None,
        pause_authority: Role::Governance,
        initial_allocations: vec![(user, 1_000_000, None)],
    };

    let mut token = TokenContractV2::new_at_genesis(params).unwrap();

    // Update fee schedule
    let new_schedule = FeeSchedule {
        transfer_fee_bps: 500,
        burn_fee_bps: 100,
        fee_cap_amount: 10000,
        min_fee_amount: 1,
    };
    token.update_fee_schedule(&governance, new_schedule).unwrap();

    // Verify invariants still hold
    assert!(token.verify_invariants().is_ok());
}

#[test]
fn test_invariants_preserved_after_transfer_policy_update() {
    let governance = test_address(2);
    let user = test_address(3);

    // Create token with initial allocation
    let treasury = test_address(1);
    let mut authorities = AuthoritySet::new();
    authorities.add(Role::Governance, governance);

    let params = TokenCreationParams {
        token_id: test_token_id(),
        name: "Test Token".to_string(),
        symbol: "TST".to_string(),
        decimals: 8,
        metadata_hash: [0u8; 32],
        supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000_000 },
        emission_model: EmissionModel::None,
        fee_schedule: FeeSchedule::zero(),
        transfer_policy: TransferPolicy::Free,
        authorities,
        treasury_address: treasury,
        fee_recipient: None,
        pause_authority: Role::Governance,
        initial_allocations: vec![(user, 1_000_000, None)],
    };

    let mut token = TokenContractV2::new_at_genesis(params).unwrap();

    // Update transfer policy
    token.update_transfer_policy(&governance, TransferPolicy::AllowlistOnly).unwrap();

    // Verify invariants still hold
    assert!(token.verify_invariants().is_ok());
}

// =============================================================================
// Test: Serialization/Deserialization (Persistence)
// =============================================================================

#[test]
fn test_governance_config_update_serialization() {
    let data = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetFeeSchedule {
            transfer_fee_bps: 500,
            burn_fee_bps: 100,
            fee_cap_amount: 1000,
            min_fee_amount: 10,
        },
        nonce: 42,
        timestamp: 1234567890,
    };

    // Serialize
    let serialized = bincode::serialize(&data).expect("serialization should succeed");

    // Deserialize
    let deserialized: GovernanceConfigUpdateData =
        bincode::deserialize(&serialized).expect("deserialization should succeed");

    // Verify equality
    assert_eq!(deserialized.token_id, data.token_id);
    assert_eq!(deserialized.caller, data.caller);
    assert_eq!(deserialized.nonce, data.nonce);
    assert_eq!(deserialized.timestamp, data.timestamp);

    match (&deserialized.operation, &data.operation) {
        (
            GovernanceConfigOperation::SetFeeSchedule {
                transfer_fee_bps: t1, burn_fee_bps: b1, fee_cap_amount: c1, min_fee_amount: m1
            },
            GovernanceConfigOperation::SetFeeSchedule {
                transfer_fee_bps: t2, burn_fee_bps: b2, fee_cap_amount: c2, min_fee_amount: m2
            },
        ) => {
            assert_eq!(t1, t2);
            assert_eq!(b1, b2);
            assert_eq!(c1, c2);
            assert_eq!(m1, m2);
        }
        _ => panic!("Operation type mismatch"),
    }
}

#[test]
fn test_token_state_persistence_after_updates() {
    let governance = test_address(2);
    let user = test_address(3);

    // Create token
    let treasury = test_address(1);
    let mut authorities = AuthoritySet::new();
    authorities.add(Role::Governance, governance);

    let params = TokenCreationParams {
        token_id: test_token_id(),
        name: "Test Token".to_string(),
        symbol: "TST".to_string(),
        decimals: 8,
        metadata_hash: [0u8; 32],
        supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000_000 },
        emission_model: EmissionModel::None,
        fee_schedule: FeeSchedule::zero(),
        transfer_policy: TransferPolicy::Free,
        authorities,
        treasury_address: treasury,
        fee_recipient: None,
        pause_authority: Role::Governance,
        initial_allocations: vec![(user, 1_000_000, None)],
    };

    let mut token = TokenContractV2::new_at_genesis(params).unwrap();

    // Apply governance updates
    token.update_fee_schedule(&governance, FeeSchedule {
        transfer_fee_bps: 250,
        burn_fee_bps: 50,
        fee_cap_amount: 5000,
        min_fee_amount: 5,
    }).unwrap();
    token.update_transfer_policy(&governance, TransferPolicy::AllowlistOnly).unwrap();

    // Serialize (simulate persistence)
    let serialized = bincode::serialize(&token).expect("serialization should succeed");

    // Deserialize (simulate restart/import)
    let restored: TokenContractV2 =
        bincode::deserialize(&serialized).expect("deserialization should succeed");

    // Verify all state restored correctly
    assert_eq!(restored.economic_config.fee_schedule.transfer_fee_bps, 250);
    assert_eq!(restored.economic_config.fee_schedule.burn_fee_bps, 50);
    assert_eq!(restored.economic_config.fee_schedule.fee_cap_amount, 5000);
    assert_eq!(restored.economic_config.fee_schedule.min_fee_amount, 5);
    assert!(matches!(
        restored.economic_config.transfer_policy,
        TransferPolicy::AllowlistOnly
    ));
    assert_eq!(restored.total_supply, 1_000_000);
    assert_eq!(restored.balance_of(&user), 1_000_000);

    // Verify invariants hold after restoration
    assert!(restored.verify_invariants().is_ok());
}

// =============================================================================
// Test: Operation Type Strings
// =============================================================================

#[test]
fn test_operation_type_strings() {
    let fee_schedule_op = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetFeeSchedule {
            transfer_fee_bps: 500,
            burn_fee_bps: 100,
            fee_cap_amount: 1000,
            min_fee_amount: 10,
        },
        nonce: 1,
        timestamp: 12345,
    };
    assert_eq!(fee_schedule_op.operation_type(), "set_fee_schedule");

    let policy_op = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetTransferPolicy {
            policy: "Free".to_string(),
        },
        nonce: 1,
        timestamp: 12345,
    };
    assert_eq!(policy_op.operation_type(), "set_transfer_policy");

    let pause_op = GovernanceConfigUpdateData {
        token_id: test_token_id(),
        caller: test_address(2),
        operation: GovernanceConfigOperation::SetPaused { paused: true },
        nonce: 1,
        timestamp: 12345,
    };
    assert_eq!(pause_op.operation_type(), "set_paused");
}

// =============================================================================
// Test: Multiple Sequential Updates
// =============================================================================

#[test]
fn test_multiple_sequential_governance_updates() {
    let governance = test_address(2);

    let mut token = create_test_token_with_governance(governance);

    // First update: Set fee schedule
    token.update_fee_schedule(&governance, FeeSchedule {
        transfer_fee_bps: 100,
        burn_fee_bps: 0,
        fee_cap_amount: 0,
        min_fee_amount: 0,
    }).unwrap();
    assert_eq!(token.economic_config.fee_schedule.transfer_fee_bps, 100);

    // Second update: Modify fee schedule again
    token.update_fee_schedule(&governance, FeeSchedule {
        transfer_fee_bps: 200,
        burn_fee_bps: 50,
        fee_cap_amount: 1000,
        min_fee_amount: 5,
    }).unwrap();
    assert_eq!(token.economic_config.fee_schedule.transfer_fee_bps, 200);
    assert_eq!(token.economic_config.fee_schedule.burn_fee_bps, 50);

    // Third update: Change transfer policy
    token.update_transfer_policy(&governance, TransferPolicy::NonTransferable).unwrap();
    assert!(matches!(
        token.economic_config.transfer_policy,
        TransferPolicy::NonTransferable
    ));

    // Fourth update: Change back to Free
    token.update_transfer_policy(&governance, TransferPolicy::Free).unwrap();
    assert!(matches!(
        token.economic_config.transfer_policy,
        TransferPolicy::Free
    ));

    // Fifth update: Pause
    token.pause(&governance, true).unwrap();
    assert!(token.paused);

    // Sixth update: Unpause
    token.pause(&governance, false).unwrap();
    assert!(!token.paused);

    // Verify invariants after all updates
    assert!(token.verify_invariants().is_ok());
}
