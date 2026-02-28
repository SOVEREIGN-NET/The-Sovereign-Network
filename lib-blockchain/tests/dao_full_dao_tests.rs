//! DAO Full DAO tests (dao-6)

use lib_blockchain::Blockchain;
use lib_blockchain::dao::{GovernancePhase, CouncilBootstrapConfig, CouncilBootstrapEntry, PhaseTransitionConfig};
use anyhow::Result;

fn council_config() -> CouncilBootstrapConfig {
    CouncilBootstrapConfig {
        members: vec![
            CouncilBootstrapEntry {
                identity_id: "did:zhtp:alice".to_string(),
                wallet_id: "aaaa".to_string(),
                stake_amount: 1_000_000,
            },
        ],
        threshold: 1,
    }
}

// ── phase2 default field values ───────────────────────────────────────────────

#[test]
fn test_phase2_execution_delay_default() {
    let bc = Blockchain::new().expect("genesis");
    assert_eq!(bc.phase2_execution_delay_blocks, 8_640);
}

#[test]
fn test_council_dissolved_at_default_is_none() {
    let bc = Blockchain::new().expect("genesis");
    assert!(bc.council_dissolved_at.is_none());
}

// ── council dissolution on phase transition ───────────────────────────────────

#[test]
fn test_council_dissolves_on_phase2_entry() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());
    assert_eq!(bc.council_members.len(), 1, "council should be non-empty");

    // Set permissive thresholds to force Phase 1 → Phase 2 immediately
    bc.phase_transition_config = PhaseTransitionConfig {
        min_citizens_for_phase1: 0,
        max_wallet_pct_bps_for_phase1: u16::MAX,
        phase0_max_duration_blocks: Some(0), // trigger Bootstrap → Hybrid immediately
        min_citizens_for_phase2: 0,
        max_wallet_pct_bps_for_phase2: u16::MAX,
        phase2_quorum_consecutive_cycles: 0,
    };

    // Bootstrap → Hybrid
    bc.try_advance_governance_phase();
    assert_eq!(bc.governance_phase, GovernancePhase::Hybrid);
    assert_eq!(bc.council_members.len(), 1, "council still active in Hybrid");

    // Hybrid → FullDao
    bc.try_advance_governance_phase();
    assert_eq!(bc.governance_phase, GovernancePhase::FullDao);
    assert!(bc.council_members.is_empty(), "council should be dissolved");
    assert_eq!(bc.council_threshold, 0);
    assert_eq!(bc.council_dissolved_at, Some(bc.height));
}

// ── persistence round-trip ────────────────────────────────────────────────────

#[test]
fn test_phase2_fields_survive_dat_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    bc.phase2_execution_delay_blocks = 1_234;
    bc.council_dissolved_at = Some(9_999);

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;

    assert_eq!(loaded.phase2_execution_delay_blocks, 1_234);
    assert_eq!(loaded.council_dissolved_at, Some(9_999));
    Ok(())
}

// ── is_council_member after dissolution ──────────────────────────────────────

#[test]
fn test_is_council_member_returns_false_after_dissolution() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());
    assert!(bc.is_council_member("did:zhtp:alice"));

    // Dissolve via phase transition
    bc.phase_transition_config = PhaseTransitionConfig {
        min_citizens_for_phase1: 0,
        max_wallet_pct_bps_for_phase1: u16::MAX,
        phase0_max_duration_blocks: Some(0),
        min_citizens_for_phase2: 0,
        max_wallet_pct_bps_for_phase2: u16::MAX,
        phase2_quorum_consecutive_cycles: 0,
    };
    bc.try_advance_governance_phase(); // → Hybrid
    bc.try_advance_governance_phase(); // → FullDao + dissolve
    assert!(!bc.is_council_member("did:zhtp:alice"), "alice is no longer a council member");
}

// ── auto-execution only fires in FullDao phase ────────────────────────────────

#[test]
fn test_process_governance_in_bootstrap_does_not_auto_execute() -> Result<()> {
    let mut bc = Blockchain::new()?;
    // Should not panic or auto-execute in Bootstrap phase
    bc.process_approved_governance_proposals()?;
    assert_eq!(bc.governance_phase, GovernancePhase::Bootstrap);
    Ok(())
}
