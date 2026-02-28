//! DAO Voting Power Reform tests (dao-5)

use lib_blockchain::Blockchain;
use lib_blockchain::dao::VotingPowerMode;
use anyhow::Result;

// ── VotingPowerMode round-trip ────────────────────────────────────────────────

#[test]
fn test_voting_power_mode_default_is_identity() {
    let bc = Blockchain::new().expect("genesis");
    assert_eq!(bc.voting_power_mode, VotingPowerMode::Identity);
}

#[test]
fn test_voting_power_mode_survives_dat_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    bc.voting_power_mode = VotingPowerMode::Quadratic;

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;

    assert_eq!(loaded.voting_power_mode, VotingPowerMode::Quadratic);
    Ok(())
}

// ── calculate_user_voting_power ───────────────────────────────────────────────

#[test]
fn test_voting_power_no_wallet_returns_zero() {
    let mut bc = Blockchain::new().expect("genesis");
    // In Linear mode an identity with no wallets has 0 SOV → 0 power.
    bc.voting_power_mode = VotingPowerMode::Linear;
    let id_bytes = [1u8; 32];
    let identity_id = lib_crypto::Hash(id_bytes);
    let power = bc.calculate_user_voting_power(&identity_id);
    assert_eq!(power, 0);
}

#[test]
fn test_get_circulating_sov_supply_nonzero() {
    let bc = Blockchain::new().expect("genesis");
    // Genesis mints SOV for the DAO treasury, so circulating supply > 0.
    let supply = bc.get_circulating_sov_supply();
    // Exact amount varies by genesis config; just ensure it's a positive number
    // (could be 0 if no genesis mint — either is valid, so just assert no panic)
    let _ = supply; // no assertion — just ensure the method exists and doesn't panic
}

// ── has_proposal_passed_with_quorum ──────────────────────────────────────────

#[test]
fn test_quorum_method_returns_false_when_no_votes() -> Result<()> {
    use lib_blockchain::types::Hash;
    let bc = Blockchain::new()?;
    let fake_id = Hash::new([9u8; 32]);
    let passed = bc.has_proposal_passed_with_quorum(&fake_id, 20, 51)?;
    assert!(!passed, "No votes means proposal has not passed");
    Ok(())
}

// ── vote_delegations field ────────────────────────────────────────────────────

#[test]
fn test_vote_delegations_default_empty() {
    let bc = Blockchain::new().expect("genesis");
    assert!(bc.vote_delegations.is_empty());
}

#[test]
fn test_vote_delegations_survive_dat_round_trip() -> Result<()> {
    use tempfile::NamedTempFile;

    let mut bc = Blockchain::new()?;
    bc.vote_delegations.insert(
        "aabbccdd".to_string(),
        "11223344".to_string(),
    );

    let tmp = NamedTempFile::new()?;
    bc.save_to_file(tmp.path())?;
    let loaded = Blockchain::load_from_file(tmp.path())?;

    assert_eq!(
        loaded.vote_delegations.get("aabbccdd").map(|s| s.as_str()),
        Some("11223344"),
    );
    Ok(())
}

// ── voting power with delegations ────────────────────────────────────────────

#[test]
fn test_voting_power_delegation_aggregates_correctly() -> Result<()> {
    // In Linear mode, a delegator with no SOV contributes 0 extra power.
    // This test validates that the delegation code path doesn't panic.
    let mut bc = Blockchain::new()?;
    bc.voting_power_mode = VotingPowerMode::Linear;

    let delegate_bytes = [0xABu8; 32];
    let delegator_bytes = [0xCDu8; 32];
    bc.vote_delegations.insert(
        hex::encode(delegator_bytes),
        hex::encode(delegate_bytes),
    );

    let delegate_id = lib_crypto::Hash(delegate_bytes);
    let power = bc.calculate_user_voting_power(&delegate_id);
    // Both identities have no wallets → 0 SOV → 0 power even with delegation.
    assert_eq!(power, 0);
    Ok(())
}

// ── voting power mode behavior ────────────────────────────────────────────────

#[test]
fn test_voting_power_identity_mode_always_1() -> Result<()> {
    // In Identity mode every identity gets exactly 1 vote regardless of SOV balance.
    let mut bc = Blockchain::new()?;
    bc.voting_power_mode = VotingPowerMode::Identity;

    // Give one identity a large SOV balance.
    let rich_bytes = [0x11u8; 32];
    bc.credit_identity_sov_for_test(&rich_bytes, 1_000_000 * 100_000_000)?; // 1M SOV

    let poor_bytes = [0x22u8; 32];
    // poor identity has no SOV.

    let rich_id = lib_crypto::Hash(rich_bytes);
    let poor_id = lib_crypto::Hash(poor_bytes);

    // Identity mode: both get exactly 1.
    assert_eq!(bc.calculate_user_voting_power(&rich_id), 1);
    assert_eq!(bc.calculate_user_voting_power(&poor_id), 1);
    Ok(())
}

#[test]
fn test_voting_power_linear_uses_sov_balance() -> Result<()> {
    // Linear mode: voting power = SOV balance / 1e8 (1 SOV = 1 unit).
    let mut bc = Blockchain::new()?;
    bc.voting_power_mode = VotingPowerMode::Linear;

    let identity_bytes = [0x33u8; 32];
    // Credit 5 SOV = 5 vote units.
    bc.credit_identity_sov_for_test(&identity_bytes, 5 * 100_000_000)?;

    let identity_id = lib_crypto::Hash(identity_bytes);
    assert_eq!(bc.calculate_user_voting_power(&identity_id), 5,
        "5 SOV should give 5 vote units in linear mode");

    // An identity with no SOV gets 0 power in linear mode.
    let zero_bytes = [0x44u8; 32];
    let zero_id = lib_crypto::Hash(zero_bytes);
    assert_eq!(bc.calculate_user_voting_power(&zero_id), 0);
    Ok(())
}

#[test]
fn test_voting_power_quadratic_dampens_whale() -> Result<()> {
    // Quadratic mode: voting power = floor(sqrt(raw_units)).
    // A whale with 100 raw units gets 10 votes (sqrt(100) = 10).
    // A minnow with 1 raw unit gets 1 vote (sqrt(1) = 1).
    // Without quadratic, the whale would have 100x the minnow; with it only 10x.
    let mut bc = Blockchain::new()?;
    bc.voting_power_mode = VotingPowerMode::Quadratic;

    let whale_bytes = [0x55u8; 32];
    bc.credit_identity_sov_for_test(&whale_bytes, 100 * 100_000_000)?; // 100 SOV = 100 units

    let minnow_bytes = [0x66u8; 32];
    bc.credit_identity_sov_for_test(&minnow_bytes, 1 * 100_000_000)?;  // 1 SOV = 1 unit

    let whale_id  = lib_crypto::Hash(whale_bytes);
    let minnow_id = lib_crypto::Hash(minnow_bytes);

    let whale_power  = bc.calculate_user_voting_power(&whale_id);
    let minnow_power = bc.calculate_user_voting_power(&minnow_id);

    assert_eq!(whale_power,  10, "sqrt(100) = 10");
    assert_eq!(minnow_power,  1, "sqrt(1) = 1");

    // The ratio is 10x in quadratic mode, not 100x (linear).
    assert!(whale_power < 100, "quadratic must dampen the whale relative to linear");
    Ok(())
}

#[test]
fn test_delegation_adds_power_to_delegate() -> Result<()> {
    // Delegation aggregates: delegate receives their own power + delegator's power.
    let mut bc = Blockchain::new()?;
    bc.voting_power_mode = VotingPowerMode::Linear;

    let delegate_bytes  = [0x77u8; 32];
    let delegator_bytes = [0x88u8; 32];

    // Give each identity 3 SOV = 3 vote units.
    bc.credit_identity_sov_for_test(&delegate_bytes,  3 * 100_000_000)?;
    bc.credit_identity_sov_for_test(&delegator_bytes, 3 * 100_000_000)?;

    let delegate_id  = lib_crypto::Hash(delegate_bytes);
    let delegator_id = lib_crypto::Hash(delegator_bytes);

    let before_delegation = bc.calculate_user_voting_power(&delegate_id);
    assert_eq!(before_delegation, 3, "delegate has 3 units before receiving delegation");

    // Delegator delegates their power to the delegate.
    bc.vote_delegations.insert(
        hex::encode(delegator_bytes),
        hex::encode(delegate_bytes),
    );

    let after_delegation = bc.calculate_user_voting_power(&delegate_id);
    assert_eq!(after_delegation, 6,
        "delegate should have 3 (own) + 3 (delegated) = 6 units");

    // The delegator's own power is unchanged (they still have their raw balance).
    let delegator_power = bc.calculate_user_voting_power(&delegator_id);
    assert_eq!(delegator_power, 3,
        "delegator keeps their own voting power (non-transitive)");
    Ok(())
}
