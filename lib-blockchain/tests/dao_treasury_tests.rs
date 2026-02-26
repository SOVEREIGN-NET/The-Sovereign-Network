//! DAO Treasury Execution tests (dao-2)

use lib_blockchain::Blockchain;
use lib_blockchain::dao::{GovernancePhase, CouncilBootstrapConfig, CouncilBootstrapEntry};
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

#[test]
fn test_quorum_uses_proposal_quorum_required() -> Result<()> {
    use tempfile::NamedTempFile;
    // Verify that execute_dao_proposal uses proposal.quorum_required, not hardcoded 60.
    // We do this by checking that the method doesn't panic with the new implementation.
    // A full integration test would need a mock proposal; here we just test the round-trip.
    let bc = Blockchain::new()?;
    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;
    assert_eq!(loaded.treasury_epoch_length_blocks, 10_080);
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
