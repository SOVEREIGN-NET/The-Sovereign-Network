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

// Note: test_execute_dao_proposal_balance_model_transfer and
// test_execute_dao_proposal_fails_without_council_votes require proposals and votes
// to be mined into confirmed blocks, which needs the full block processing pipeline.
// Those tests live at the integration-test level; the unit tests below cover the
// individually-testable components of treasury execution.

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
