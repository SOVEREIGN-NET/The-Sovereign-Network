//! DAO Hybrid Governance tests (dao-4)

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

// ── default values ────────────────────────────────────────────────────────────

#[test]
fn test_hybrid_fields_default() {
    let bc = Blockchain::new().expect("genesis");
    assert!(bc.pending_cosigns.is_empty());
    assert!(bc.pending_vetoes.is_empty());
    assert_eq!(bc.veto_window_blocks, 576);
    assert!(bc.treasury_epoch_execution_count.is_empty());
    assert_eq!(bc.max_executions_per_epoch, 3);
}

// ── council_cosign_proposal ───────────────────────────────────────────────────

#[test]
fn test_cosign_requires_council_member() {
    use lib_blockchain::types::Hash;
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());

    let proposal_id = Hash::new([1u8; 32]);
    let err = bc.council_cosign_proposal(&proposal_id, "did:zhtp:mallory".to_string(), vec![]);
    assert!(err.is_err(), "non-council member should be rejected");
}

#[test]
fn test_cosign_accepted_for_council_member() {
    use lib_blockchain::types::Hash;
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());

    let proposal_id = Hash::new([2u8; 32]);
    bc.council_cosign_proposal(&proposal_id, "did:zhtp:alice".to_string(), vec![0xAB])
        .expect("alice is a council member");

    let count = bc.pending_cosigns.get(&proposal_id.as_array()).map(|v| v.len()).unwrap_or(0);
    assert_eq!(count, 1);
}

#[test]
fn test_cosign_deduplicates_same_did() {
    use lib_blockchain::types::Hash;
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());

    let proposal_id = Hash::new([3u8; 32]);
    bc.council_cosign_proposal(&proposal_id, "did:zhtp:alice".to_string(), vec![]).unwrap();
    bc.council_cosign_proposal(&proposal_id, "did:zhtp:alice".to_string(), vec![]).unwrap();

    let count = bc.pending_cosigns.get(&proposal_id.as_array()).map(|v| v.len()).unwrap_or(0);
    assert_eq!(count, 1, "duplicate cosign should be ignored");
}

// ── council_veto_proposal ─────────────────────────────────────────────────────

#[test]
fn test_veto_requires_council_member() {
    use lib_blockchain::types::Hash;
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());

    let proposal_id = Hash::new([4u8; 32]);
    let err = bc.council_veto_proposal(&proposal_id, "did:zhtp:eve".to_string(), "bad".to_string());
    assert!(err.is_err());
}

#[test]
fn test_veto_accepted_for_council_member() {
    use lib_blockchain::types::Hash;
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());

    let proposal_id = Hash::new([5u8; 32]);
    bc.council_veto_proposal(&proposal_id, "did:zhtp:bob".to_string(), "risky".to_string())
        .expect("bob is a council member");

    let count = bc.pending_vetoes.get(&proposal_id.as_array()).map(|v| v.len()).unwrap_or(0);
    assert_eq!(count, 1);
}

#[test]
fn test_veto_deduplicates_same_did() {
    use lib_blockchain::types::Hash;
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());

    let proposal_id = Hash::new([6u8; 32]);
    bc.council_veto_proposal(&proposal_id, "did:zhtp:alice".to_string(), "r1".to_string()).unwrap();
    bc.council_veto_proposal(&proposal_id, "did:zhtp:alice".to_string(), "r2".to_string()).unwrap();

    let count = bc.pending_vetoes.get(&proposal_id.as_array()).map(|v| v.len()).unwrap_or(0);
    assert_eq!(count, 1, "duplicate veto should be ignored");
}

// ── hybrid field persistence ───────────────────────────────────────────────────

#[test]
fn test_hybrid_fields_survive_dat_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;
    use lib_blockchain::types::Hash;

    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&council_config());

    let proposal_id = Hash::new([7u8; 32]);
    bc.council_cosign_proposal(&proposal_id, "did:zhtp:alice".to_string(), vec![1, 2, 3]).unwrap();
    bc.council_veto_proposal(&proposal_id, "did:zhtp:bob".to_string(), "security".to_string()).unwrap();
    bc.treasury_epoch_execution_count.insert(1, 2);
    bc.max_executions_per_epoch = 5;
    bc.veto_window_blocks = 288;

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;

    assert_eq!(loaded.max_executions_per_epoch, 5);
    assert_eq!(loaded.veto_window_blocks, 288);
    assert_eq!(loaded.treasury_epoch_execution_count.get(&1), Some(&2));

    let cosigns = loaded.pending_cosigns.get(&proposal_id.as_array()).map(|v| v.len()).unwrap_or(0);
    assert_eq!(cosigns, 1);

    let vetoes = loaded.pending_vetoes.get(&proposal_id.as_array()).map(|v| v.len()).unwrap_or(0);
    assert_eq!(vetoes, 1);

    Ok(())
}

// ── phase gating in Hybrid mode ────────────────────────────────────────────────

#[test]
fn test_hybrid_phase_blocks_bootstrap_council_check() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&council_config());
    // Advance to Hybrid phase via time condition
    bc.phase_transition_config.phase0_max_duration_blocks = Some(0);
    bc.try_advance_governance_phase();
    assert_eq!(bc.governance_phase, GovernancePhase::Hybrid,
        "should be in Hybrid phase now");
}
