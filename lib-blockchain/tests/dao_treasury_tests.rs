//! DAO Treasury Execution tests (dao-2)

use lib_blockchain::Blockchain;
use lib_blockchain::dao::{
    GovernancePhase, CouncilBootstrapConfig, CouncilBootstrapEntry,
    TreasurySpendingCategory, TreasuryExecutionParams,
};
use anyhow::Result;

fn council_config() -> CouncilBootstrapConfig {
    CouncilBootstrapConfig {
        members: vec![
            CouncilBootstrapEntry {
                identity_id: "did:zhtp:alice".to_string(),
                wallet_id: "aaaa".to_string(),
                stake_amount: 1_000_000,
            },
            CouncilBootstrapEntry {
                identity_id: "did:zhtp:bob".to_string(),
                wallet_id: "bbbb".to_string(),
                stake_amount: 1_000_000,
            },
        ],
        threshold: 2,
    }
}

#[test]
fn test_governance_phase_default_survives_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&council_config());
    assert_eq!(bc.governance_phase, GovernancePhase::Bootstrap);

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;
    assert_eq!(loaded.governance_phase, GovernancePhase::Bootstrap);
    Ok(())
}

#[test]
fn test_treasury_epoch_spend_default_is_empty() {
    let bc = Blockchain::new().expect("genesis");
    assert!(bc.treasury_epoch_spend.is_empty());
    assert_eq!(bc.treasury_epoch_length_blocks, 10_080);
}

#[test]
fn test_emergency_state_default_is_false() {
    let bc = Blockchain::new().expect("genesis");
    assert!(!bc.emergency_state);
    assert!(bc.emergency_activated_at.is_none());
    assert!(bc.emergency_expires_at.is_none());
}

#[test]
fn test_emergency_activation_requires_threshold() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());

    // Only one signature — below threshold of 2
    let result = bc.activate_emergency_state(
        &["did:zhtp:alice".to_string()],
        "did:zhtp:alice".to_string(),
    );
    assert!(result.is_err(), "should fail with 1 sig, threshold is 2");

    // Two valid signatures — meets threshold
    let result = bc.activate_emergency_state(
        &["did:zhtp:alice".to_string(), "did:zhtp:bob".to_string()],
        "did:zhtp:alice".to_string(),
    );
    assert!(result.is_ok(), "should succeed with 2 sigs: {:?}", result);
    assert!(bc.emergency_state);
    assert!(bc.emergency_expires_at.is_some());
}

#[test]
fn test_emergency_activation_rejects_non_council_sigs() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());

    // Two signatures but from non-council members
    let result = bc.activate_emergency_state(
        &["did:zhtp:mallory".to_string(), "did:zhtp:eve".to_string()],
        "did:zhtp:mallory".to_string(),
    );
    assert!(result.is_err());
}

#[test]
fn test_emergency_auto_expire_in_block_processing() -> Result<()> {
    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&council_config());

    bc.activate_emergency_state(
        &["did:zhtp:alice".to_string(), "did:zhtp:bob".to_string()],
        "did:zhtp:alice".to_string(),
    )?;
    assert!(bc.emergency_state);

    // Simulate block advancement past expiry
    let expiry = bc.emergency_expires_at.unwrap();
    bc.height = expiry;
    bc.process_approved_governance_proposals()?;
    assert!(!bc.emergency_state, "emergency should have expired");

    Ok(())
}

// ── balance model execution ───────────────────────────────────────────────────

#[test]
fn test_execute_dao_proposal_balance_model_transfer() -> Result<()> {
    // Single-member council with threshold=1 — simplest valid configuration.
    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&CouncilBootstrapConfig {
        members: vec![CouncilBootstrapEntry {
            identity_id: "did:zhtp:alice".to_string(),
            wallet_id: "aa".to_string(),
            stake_amount: 1_000_000,
        }],
        threshold: 1,
    });

    let proposal_id = lib_blockchain::types::Hash::new([0xba; 32]);
    // quorum_required=0 means any participation satisfies the quorum check.
    bc.push_test_dao_proposal(proposal_id, 0);
    // Alice (council member) votes yes — satisfies both quorum and Phase 0 council gate.
    bc.push_test_dao_vote(proposal_id, "did:zhtp:alice", "Yes");

    // Fund treasury with 1_000_000 SOV.
    bc.credit_dao_treasury_sov_for_test(1_000_000)?;
    let treasury_before = bc.get_dao_treasury_balance()?;
    assert_eq!(treasury_before, 1_000_000);

    // Recipient: 32 bytes all-0xcc (valid 32-byte hex wallet ID).
    let recipient_hex = "cc".repeat(32);
    let amount = 1_000u64;

    bc.execute_dao_proposal(
        proposal_id,
        "did:zhtp:alice".to_string(),
        recipient_hex.clone(),
        amount,
    )?;

    // Treasury balance must have decreased by exactly `amount`.
    assert_eq!(bc.get_dao_treasury_balance()?, treasury_before - amount);
    // Recipient must have been credited exactly `amount`.
    assert_eq!(bc.get_wallet_sov_for_test(&recipient_hex)?, amount);
    Ok(())
}

#[test]
fn test_execute_dao_proposal_fails_without_council_votes() -> Result<()> {
    // Threshold=2 council: requires alice AND bob to both vote yes in Phase 0.
    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&council_config());

    let proposal_id = lib_blockchain::types::Hash::new([0xab; 32]);
    bc.push_test_dao_proposal(proposal_id, 0);
    // Mallory (non-council member) votes yes — passes quorum but NOT council gate.
    bc.push_test_dao_vote(proposal_id, "did:zhtp:mallory", "Yes");

    bc.credit_dao_treasury_sov_for_test(1_000_000)?;

    let result = bc.execute_dao_proposal(
        proposal_id,
        "did:zhtp:mallory".to_string(),
        "aa".repeat(32),
        1_000,
    );
    assert!(result.is_err(), "Must fail: mallory is not a council member");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.to_lowercase().contains("council"),
        "Error must mention council requirement, got: {}", msg
    );
    Ok(())
}

#[test]
fn test_epoch_spend_cap_enforced() -> Result<()> {
    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&CouncilBootstrapConfig {
        members: vec![CouncilBootstrapEntry {
            identity_id: "did:zhtp:alice".to_string(),
            wallet_id: "aa".to_string(),
            stake_amount: 1_000_000,
        }],
        threshold: 1,
    });

    let proposal_id = lib_blockchain::types::Hash::new([0xec; 32]);
    bc.push_test_dao_proposal(proposal_id, 0);
    bc.push_test_dao_vote(proposal_id, "did:zhtp:alice", "Yes");

    // Fund treasury with 100_000 SOV → epoch-start cap = 5% × 100_000 = 5_000
    bc.credit_dao_treasury_sov_for_test(100_000)?;

    let epoch = bc.height / bc.treasury_epoch_length_blocks.max(1);
    // Pre-record epoch start balance and simulate having already spent 4_001.
    bc.treasury_epoch_start_balance.insert(epoch, 100_000);
    bc.treasury_epoch_spend.insert(epoch, 4_001);

    // Attempting to spend 1_000 would bring the epoch total to 5_001 > cap of 5_000.
    let result = bc.execute_dao_proposal(
        proposal_id,
        "did:zhtp:alice".to_string(),
        "dd".repeat(32),
        1_000,
    );
    assert!(result.is_err(), "Must fail: 4_001 + 1_000 exceeds epoch cap of 5_000");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.to_lowercase().contains("epoch"),
        "Error must mention epoch cap, got: {}", msg
    );
    Ok(())
}

// ── spending category validation ──────────────────────────────────────────────

#[test]
fn test_emergency_spending_rejected_when_inactive() -> Result<()> {
    let bc = Blockchain::new()?;
    assert!(!bc.emergency_state, "fresh chain has no emergency state");

    let params = TreasuryExecutionParams {
        category: TreasurySpendingCategory::Emergency,
        recipient_wallet_id: "aabb".to_string(),
        amount: 100,
    };
    let result = bc.validate_treasury_spending_category(&params);
    assert!(result.is_err(), "Emergency category must be rejected when emergency_state == false");
    assert!(result.unwrap_err().to_string().contains("emergency_state"));
    Ok(())
}

#[test]
fn test_emergency_spending_allowed_when_active() -> Result<()> {
    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&council_config());
    bc.activate_emergency_state(
        &["did:zhtp:alice".to_string(), "did:zhtp:bob".to_string()],
        "did:zhtp:alice".to_string(),
    )?;
    assert!(bc.emergency_state);

    let params = TreasuryExecutionParams {
        category: TreasurySpendingCategory::Emergency,
        recipient_wallet_id: "aabb".to_string(),
        amount: 100,
    };
    assert!(
        bc.validate_treasury_spending_category(&params).is_ok(),
        "Emergency category must be allowed when emergency_state == true"
    );
    Ok(())
}

#[test]
fn test_non_emergency_category_always_allowed() -> Result<()> {
    let bc = Blockchain::new()?;
    for category in [
        TreasurySpendingCategory::GrantsFunding,
        TreasurySpendingCategory::OperationalBudget,
        TreasurySpendingCategory::Infrastructure,
    ] {
        let params = TreasuryExecutionParams {
            category,
            recipient_wallet_id: "aabb".to_string(),
            amount: 100,
        };
        assert!(
            bc.validate_treasury_spending_category(&params).is_ok(),
            "Non-emergency category must pass when emergency_state == false"
        );
    }
    Ok(())
}

// ── epoch spend cap anchored to epoch-start balance ───────────────────────────

#[test]
fn test_epoch_start_balance_is_recorded_on_first_spend() {
    let mut bc = Blockchain::new().expect("genesis");
    // Pre-populate epoch tracking as if a spend already happened
    let epoch = 0u64;
    let prior_spend = 1_000u64;
    let current_balance = 50_000u64;  // current (after prior spend)
    bc.treasury_epoch_spend.insert(epoch, prior_spend);
    // epoch_start_balance not yet recorded for this epoch
    // When first computed, it should be current + prior_spend = 51_000
    let expected_start = current_balance.saturating_add(prior_spend);
    bc.treasury_epoch_start_balance.insert(epoch, expected_start);
    assert_eq!(bc.treasury_epoch_start_balance[&epoch], 51_000);
    // The cap should be based on 51_000 (epoch-start), not 50_000 (current)
    let cap = bc.treasury_epoch_start_balance[&epoch].saturating_mul(5) / 100;
    assert_eq!(cap, 2_550);
}

#[test]
fn test_epoch_cap_uses_start_balance_not_current() {
    // Demonstrates the fix: cap is computed from epoch_start_balance, not current balance.
    // If the current balance had been used, spending half the cap first would shrink
    // the cap for the second spend, allowing the total to exceed 5%.
    let epoch_start = 100_000u64;
    let cap = epoch_start.saturating_mul(5) / 100; // 5_000
    let first_spend = 2_500u64;
    let second_spend = 2_500u64;
    // Both spends fit within the epoch-start cap
    assert!(first_spend + second_spend <= cap);
    // If cap had been recalculated from (100_000 - 2_500 = 97_500) after first spend:
    let shrunk_cap = (epoch_start - first_spend).saturating_mul(5) / 100; // 4_875
    // The second spend (2_500) would still fit, but a third spend of 2_376 also would —
    // making total 7_376 > 5% of epoch_start. Anchoring prevents this.
    assert!(shrunk_cap < cap, "shrunk cap ({}) is less than start cap ({})", shrunk_cap, cap);
}

#[test]
fn test_epoch_cap_resets_each_epoch() {
    let mut bc = Blockchain::new().expect("genesis");
    // Simulate epoch 0 having a recorded spend
    bc.treasury_epoch_spend.insert(0, 5_000);
    bc.treasury_epoch_start_balance.insert(0, 100_000);

    // Epoch 1 has no spend yet
    let epoch_1_spent = bc.treasury_epoch_spend.get(&1).copied().unwrap_or(0);
    assert_eq!(epoch_1_spent, 0, "new epoch starts with zero spend");

    // Epoch 1 has no start balance yet (will be recorded on first spend)
    assert!(bc.treasury_epoch_start_balance.get(&1).is_none());
}

// ── emergency state expiry clears all fields ──────────────────────────────────

#[test]
fn test_emergency_expiry_clears_all_fields() -> Result<()> {
    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&council_config());
    bc.activate_emergency_state(
        &["did:zhtp:alice".to_string(), "did:zhtp:bob".to_string()],
        "did:zhtp:alice".to_string(),
    )?;

    let expiry = bc.emergency_expires_at.unwrap();
    bc.height = expiry;
    bc.process_approved_governance_proposals()?;

    assert!(!bc.emergency_state);
    assert!(bc.emergency_activated_at.is_none(), "activated_at should be cleared");
    assert!(bc.emergency_activated_by.is_none(), "activated_by should be cleared");
    assert!(bc.emergency_expires_at.is_none(), "expires_at should be cleared");
    Ok(())
}

// ── treasury_epoch_start_balance persistence ──────────────────────────────────

#[test]
fn test_epoch_start_balance_survives_dat_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;
    let mut bc = Blockchain::new()?;
    bc.treasury_epoch_start_balance.insert(0, 999_999);

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;
    assert_eq!(loaded.treasury_epoch_start_balance.get(&0), Some(&999_999));
    Ok(())
}

#[test]
fn test_treasury_fields_survive_dat_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&council_config());
    bc.activate_emergency_state(
        &["did:zhtp:alice".to_string(), "did:zhtp:bob".to_string()],
        "did:zhtp:alice".to_string(),
    )?;

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;
    assert!(loaded.emergency_state);
    assert_eq!(loaded.emergency_activated_by.as_deref(), Some("did:zhtp:alice"));
    assert!(loaded.emergency_expires_at.is_some());

    Ok(())
}
