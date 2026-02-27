//! DAO Bootstrap Council tests (dao-1)

use lib_blockchain::Blockchain;
use lib_blockchain::dao::{GovernancePhase, CouncilBootstrapConfig, CouncilBootstrapEntry};
use anyhow::Result;

fn make_entry(did: &str, wallet: &str) -> CouncilBootstrapEntry {
    CouncilBootstrapEntry {
        identity_id: did.to_string(),
        wallet_id: wallet.to_string(),
        stake_amount: 1_000_000,
    }
}

fn three_member_config() -> CouncilBootstrapConfig {
    CouncilBootstrapConfig {
        members: vec![
            make_entry("did:zhtp:alice", "aaaa"),
            make_entry("did:zhtp:bob", "bbbb"),
            make_entry("did:zhtp:carol", "cccc"),
        ],
        threshold: 2,
    }
}

#[test]
fn test_governance_phase_default_is_bootstrap() {
    let bc = Blockchain::new().expect("genesis");
    assert_eq!(bc.governance_phase, GovernancePhase::Bootstrap);
}

#[test]
fn test_ensure_council_bootstrap_populates_members() {
    let mut bc = Blockchain::new().expect("genesis");
    let cfg = three_member_config();
    bc.ensure_council_bootstrap(&cfg);

    assert_eq!(bc.council_members.len(), 3);
    assert_eq!(bc.council_threshold, 2);
    assert!(bc.is_council_member("did:zhtp:alice"));
    assert!(bc.is_council_member("did:zhtp:bob"));
    assert!(bc.is_council_member("did:zhtp:carol"));
    assert!(!bc.is_council_member("did:zhtp:mallory"));
}

#[test]
fn test_ensure_council_bootstrap_idempotent() {
    let mut bc = Blockchain::new().expect("genesis");
    let cfg = three_member_config();
    bc.ensure_council_bootstrap(&cfg);
    let first_count = bc.council_members.len();

    // Call again — must be no-op
    bc.ensure_council_bootstrap(&cfg);
    assert_eq!(bc.council_members.len(), first_count);
}

#[test]
fn test_is_council_member() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&three_member_config());

    assert!(bc.is_council_member("did:zhtp:alice"));
    assert!(!bc.is_council_member("did:zhtp:unknown"));
}

#[test]
fn test_get_council_members_returns_slice() {
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&three_member_config());
    let members = bc.get_council_members();
    assert_eq!(members.len(), 3);
    assert_eq!(members[0].identity_id, "did:zhtp:alice");
}

#[test]
fn test_council_bootstrap_survives_dat_round_trip() -> Result<()> {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    bc.ensure_council_bootstrap(&three_member_config());

    // Save to a temp file
    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;

    // Reload and verify
    let loaded = Blockchain::load_from_file(tmp.path())?;
    assert_eq!(loaded.council_members.len(), 3);
    assert_eq!(loaded.council_threshold, 2);
    assert!(loaded.is_council_member("did:zhtp:alice"));
    assert_eq!(loaded.governance_phase, GovernancePhase::Bootstrap);

    Ok(())
}

#[test]
fn test_empty_config_leaves_council_empty() {
    let mut bc = Blockchain::new().expect("genesis");
    let empty_cfg = CouncilBootstrapConfig::default();
    bc.ensure_council_bootstrap(&empty_cfg);
    assert!(bc.council_members.is_empty());
}

#[test]
fn test_council_threshold_defaults_to_four_in_config() {
    let cfg = CouncilBootstrapConfig {
        members: vec![make_entry("did:zhtp:a", "aa")],
        threshold: 0, // zero triggers the default-to-4 path
    };
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&cfg);
    assert_eq!(bc.council_threshold, 4);
}

#[test]
fn test_council_bootstrap_config_default_threshold_is_four() {
    // CouncilBootstrapConfig::default() must produce threshold=4, not 0.
    // #[serde(default = "...")] only fires during TOML deserialization;
    // the custom Default impl must set the same value.
    let cfg = CouncilBootstrapConfig::default();
    assert_eq!(cfg.threshold, 4, "Default threshold should be 4");
}

// ── vote gating tests ─────────────────────────────────────────────────────────
// These tests verify the conditions that `handle_cast_vote` evaluates:
// governance_phase == Bootstrap AND !is_council_member(did).

#[test]
fn test_vote_gating_rejects_non_council_in_phase0() {
    use lib_blockchain::dao::GovernancePhase;
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&three_member_config());

    // Sanity: we are in Bootstrap phase
    assert_eq!(bc.governance_phase, GovernancePhase::Bootstrap);
    // A DID that is NOT a council member should be rejected
    assert!(
        !bc.is_council_member("did:zhtp:mallory"),
        "Mallory must not be a council member"
    );
    // The gating condition mirrors handle_cast_vote logic:
    // phase == Bootstrap && !is_council_member → reject
    let would_be_rejected = bc.governance_phase == GovernancePhase::Bootstrap
        && !bc.is_council_member("did:zhtp:mallory");
    assert!(would_be_rejected, "Non-council member should be rejected in Phase 0");
}

#[test]
fn test_vote_gating_passes_council_member() {
    use lib_blockchain::dao::GovernancePhase;
    let mut bc = Blockchain::new().expect("genesis");
    bc.ensure_council_bootstrap(&three_member_config());

    assert_eq!(bc.governance_phase, GovernancePhase::Bootstrap);
    assert!(bc.is_council_member("did:zhtp:alice"));
    // A council member must NOT satisfy the rejection condition
    let would_be_rejected = bc.governance_phase == GovernancePhase::Bootstrap
        && !bc.is_council_member("did:zhtp:alice");
    assert!(!would_be_rejected, "Council member must pass Phase 0 vote gating");
}
