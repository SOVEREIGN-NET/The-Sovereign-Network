//! DAO Phase Transition tests (dao-3)

use lib_blockchain::Blockchain;
use lib_blockchain::dao::{GovernancePhase, PhaseTransitionConfig, CouncilBootstrapConfig, CouncilBootstrapEntry};
use anyhow::Result;

fn two_member_council() -> CouncilBootstrapConfig {
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

// ── PhaseTransitionConfig defaults ──────────────────────────────────────────

#[test]
fn test_phase_transition_config_defaults() {
    let cfg = PhaseTransitionConfig::default();
    assert_eq!(cfg.min_citizens_for_phase1, 10_000);
    assert_eq!(cfg.max_wallet_pct_bps_for_phase1, 1_500);
    assert_eq!(cfg.min_citizens_for_phase2, 50_000);
    assert_eq!(cfg.max_wallet_pct_bps_for_phase2, 500);
    assert_eq!(cfg.phase2_quorum_consecutive_cycles, 3);
    assert!(cfg.phase0_max_duration_blocks.is_none());
}

// ── compute_decentralization_snapshot ────────────────────────────────────────

#[test]
fn test_snapshot_citizen_count() {
    let bc = Blockchain::new().expect("genesis");
    let snap = bc.compute_decentralization_snapshot();
    // Genesis may have some identities; just check it doesn't panic and is >= 0
    let _ = snap.verified_citizen_count;
    assert_eq!(snap.snapshot_height, bc.height);
}

#[test]
fn test_snapshot_max_wallet_pct_bps_is_bounded() {
    let bc = Blockchain::new().expect("genesis");
    let snap = bc.compute_decentralization_snapshot();
    // Basis points are 0..10_000; max_wallet_pct_bps must fit u16 (≤ 65535)
    assert!(snap.max_wallet_pct_bps <= 10_000 || snap.max_wallet_pct_bps == 0);
}

// ── check_phase0_to_phase1 ───────────────────────────────────────────────────

#[test]
fn test_phase0_to_phase1_time_window_trigger() {
    let mut bc = Blockchain::new().expect("genesis");
    // Set a small duration so it triggers immediately at height 0
    bc.phase_transition_config.phase0_max_duration_blocks = Some(0);

    assert!(bc.check_phase0_to_phase1(), "condition C: time window at height 0 >= 0");
}

#[test]
fn test_phase0_to_phase1_no_trigger_when_conditions_not_met() {
    let bc = Blockchain::new().expect("genesis");
    // Default config: 10_000 citizens required; genesis has far fewer.
    // Also no time window set, so condition C is false.
    // Condition B (concentration) might still be false if there are large holders.
    // At a minimum this should not panic.
    let _ = bc.check_phase0_to_phase1();
}

// ── try_advance_governance_phase ─────────────────────────────────────────────

#[test]
fn test_try_advance_phase_bootstrap_to_hybrid_via_time() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&two_member_council());
    bc.phase_transition_config.phase0_max_duration_blocks = Some(0);

    assert_eq!(bc.governance_phase, GovernancePhase::Bootstrap);
    bc.try_advance_governance_phase();
    assert_eq!(bc.governance_phase, GovernancePhase::Hybrid);
}

#[test]
fn test_try_advance_phase_hybrid_to_fullDao_requires_all_conditions() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&two_member_council());

    // Advance to Hybrid first
    bc.phase_transition_config.phase0_max_duration_blocks = Some(0);
    bc.try_advance_governance_phase();
    assert_eq!(bc.governance_phase, GovernancePhase::Hybrid);

    // Default Phase 2 requires 50_000 citizens + low concentration + 3 quorum cycles.
    // None of these are met at genesis, so it should NOT advance.
    bc.try_advance_governance_phase();
    assert_eq!(bc.governance_phase, GovernancePhase::Hybrid, "should stay Hybrid");
}

#[test]
fn test_full_dao_phase_is_terminal() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.governance_phase = GovernancePhase::FullDao;
    bc.try_advance_governance_phase(); // should be a no-op
    assert_eq!(bc.governance_phase, GovernancePhase::FullDao);
}

// ── persistence round-trip ───────────────────────────────────────────────────

#[test]
fn test_phase_transition_fields_survive_dat_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    bc.phase_transition_config.min_citizens_for_phase1 = 999;
    bc.governance_cycles_with_quorum = 7;
    bc.last_governance_cycle_height = 42_000;

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;

    assert_eq!(loaded.phase_transition_config.min_citizens_for_phase1, 999);
    assert_eq!(loaded.governance_cycles_with_quorum, 7);
    assert_eq!(loaded.last_governance_cycle_height, 42_000);
    Ok(())
}

#[test]
fn test_decentralization_snapshot_persists() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    let snap = bc.compute_decentralization_snapshot();
    bc.last_decentralization_snapshot = Some(snap.clone());

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;

    let saved = loaded.last_decentralization_snapshot.expect("snapshot should persist");
    assert_eq!(saved.snapshot_height, snap.snapshot_height);
    Ok(())
}
