//! DAO Emergency Treasury Freeze tests (dao-7)

use lib_blockchain::Blockchain;
use anyhow::Result;

/// Register a validator on the blockchain so freeze threshold can be met.
fn add_validator(bc: &mut Blockchain, did: &str) {
    let vinfo = lib_blockchain::ValidatorInfo {
        identity_id: did.to_string(),
        stake: 1_000_000,
        storage_provided: 0,
        consensus_key: vec![1u8; 32],
        networking_key: vec![2u8; 32],
        rewards_key: vec![3u8; 32],
        network_address: "127.0.0.1:9334".to_string(),
        commission_rate: 10,
        status: "active".to_string(),
        registered_at: 0,
        last_activity: 0,
        blocks_validated: 0,
        slash_count: 0,
        admission_source: String::new(),
        governance_proposal_id: None,
    };
    bc.validator_registry.insert(did.to_string(), vinfo);
}

// ── default values ────────────────────────────────────────────────────────────

#[test]
fn test_freeze_defaults() {
    let bc = Blockchain::new().expect("genesis");
    assert!(!bc.treasury_frozen);
    assert!(bc.treasury_frozen_at.is_none());
    assert!(bc.treasury_freeze_expiry.is_none());
    assert!(bc.treasury_freeze_signatures.is_empty());
}

// ── activate_treasury_freeze ──────────────────────────────────────────────────

#[test]
fn test_freeze_requires_80pct_validators() {
    let mut bc = Blockchain::new().expect("genesis");
    add_validator(&mut bc, "did:zhtp:val1");
    add_validator(&mut bc, "did:zhtp:val2");
    add_validator(&mut bc, "did:zhtp:val3");
    add_validator(&mut bc, "did:zhtp:val4");
    add_validator(&mut bc, "did:zhtp:val5");
    // 5 validators; 80% = 4. Supply only 3 signatures → should fail.
    let err = bc.activate_treasury_freeze(
        vec!["did:zhtp:val1".to_string(), "did:zhtp:val2".to_string(), "did:zhtp:val3".to_string()],
        "test".to_string(),
    );
    assert!(err.is_err(), "3/5 < 80%");
}

#[test]
fn test_freeze_succeeds_with_80pct_validators() {
    let mut bc = Blockchain::new().expect("genesis");
    add_validator(&mut bc, "did:zhtp:val1");
    add_validator(&mut bc, "did:zhtp:val2");
    add_validator(&mut bc, "did:zhtp:val3");
    add_validator(&mut bc, "did:zhtp:val4");
    add_validator(&mut bc, "did:zhtp:val5");
    // 4 out of 5 = 80%
    let result = bc.activate_treasury_freeze(
        vec![
            "did:zhtp:val1".to_string(),
            "did:zhtp:val2".to_string(),
            "did:zhtp:val3".to_string(),
            "did:zhtp:val4".to_string(),
        ],
        "suspicious activity".to_string(),
    );
    assert!(result.is_ok(), "{:?}", result);
    assert!(bc.treasury_frozen);
    assert!(bc.treasury_freeze_expiry.is_some());
}

#[test]
fn test_freeze_fails_with_no_validators() {
    let mut bc = Blockchain::new().expect("genesis");
    let err = bc.activate_treasury_freeze(vec![], "test".to_string());
    assert!(err.is_err(), "no validators registered → should fail");
}

// ── freeze blocks spending ────────────────────────────────────────────────────

#[test]
fn test_freeze_blocks_treasury_spending() {
    use lib_blockchain::types::Hash;
    let mut bc = Blockchain::new().expect("genesis");
    add_validator(&mut bc, "did:zhtp:val1");
    bc.activate_treasury_freeze(
        vec!["did:zhtp:val1".to_string()],
        "block all spending".to_string(),
    ).expect("single validator should suffice for 100% >= 80%");
    assert!(bc.treasury_frozen);

    let fake_id = Hash::new([1u8; 32]);
    let result = bc.execute_dao_proposal(
        fake_id,
        "did:zhtp:alice".to_string(),
        "recipient".to_string(),
        1000,
    );
    assert!(result.is_err(), "execute_dao_proposal should fail when treasury is frozen");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("frozen"), "error message should mention freeze");
}

// ── auto-unfreeze ─────────────────────────────────────────────────────────────

#[test]
fn test_freeze_auto_expires_at_height() -> Result<()> {
    let mut bc = Blockchain::new()?;
    add_validator(&mut bc, "did:zhtp:val1");
    bc.activate_treasury_freeze(
        vec!["did:zhtp:val1".to_string()],
        "test expire".to_string(),
    )?;
    assert!(bc.treasury_frozen);

    let expiry = bc.treasury_freeze_expiry.unwrap();
    bc.height = expiry;
    bc.process_approved_governance_proposals()?;
    assert!(!bc.treasury_frozen, "freeze should have auto-expired");
    assert!(bc.treasury_freeze_signatures.is_empty(), "signatures should be cleared");

    Ok(())
}

// ── persistence round-trip ────────────────────────────────────────────────────

#[test]
fn test_freeze_fields_survive_dat_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    add_validator(&mut bc, "did:zhtp:val1");
    bc.activate_treasury_freeze(
        vec!["did:zhtp:val1".to_string()],
        "persist test".to_string(),
    )?;

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;

    assert!(loaded.treasury_frozen);
    assert!(loaded.treasury_frozen_at.is_some());
    assert!(loaded.treasury_freeze_expiry.is_some());
    assert_eq!(loaded.treasury_freeze_signatures, vec!["did:zhtp:val1"]);

    Ok(())
}
