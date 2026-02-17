//! Peer Identity Model, Authentication, and Sybil Resistance (closes #984)
//!
//! # Peer Identity Model
//!
//! ## Identity = Public Key
//!
//! Every ZHTP peer is identified by its **Dilithium5 public key** (`PublicKey`).
//! The key serves as a self-certifying identifier: any node can verify the
//! identity of a message sender without consulting a central authority by
//! checking the signature against the claimed public key.
//!
//! The `UnifiedPeerId` struct consolidates the public key with two derived
//! identifiers:
//!
//! | Field        | Derivation                            | Purpose                          |
//! |--------------|---------------------------------------|----------------------------------|
//! | `public_key` | Raw Dilithium5 key pair (generated)   | Canonical identity; signs msgs   |
//! | `node_id`    | BLAKE3(DID + device_name)             | Compact routing address in DHT   |
//! | `did`        | W3C DID derived from public key       | Human-readable identity string   |
//!
//! ## Authentication Flow
//!
//! 1. **Handshake**: Upon connecting, both peers perform the UHP (Unified
//!    Handshake Protocol) key exchange.  Each peer signs the handshake
//!    transcript with its Dilithium5 private key.  The other side verifies
//!    the signature against the claimed `PublicKey`.
//!
//! 2. **Per-message authentication**: Every `ValidatorMessage` received over
//!    the mesh MUST carry a Dilithium5 signature over the canonical serialised
//!    message bytes.  `ValidatorProtocol` middleware verifies this signature
//!    before forwarding the message to the consensus engine.
//!    See `assert_consensus_sender_is_validator()` below.
//!
//! 3. **DHT messages**: Every `DhtGenericPayload` is signed by the sender
//!    (`key_id || payload` format).  `MeshMessageHandler::handle_dht_generic_payload()`
//!    verifies the signature and rejects unsigned payloads.
//!
//! # Sybil Resistance
//!
//! ## Problem
//!
//! A Sybil attack occurs when a single adversary creates many pseudonymous
//! identities to gain a disproportionate influence over a distributed system.
//! Because Dilithium key generation is cheap (microseconds), a simple public-key
//! identity scheme alone is insufficient to prevent Sybil attacks.
//!
//! ## Primary Defence: Validator-Set Membership Check
//!
//! **Consensus messages are only accepted from validators whose public key
//! appears in the current active validator set.**
//!
//! The validator set is determined by the consensus layer (lib-consensus) and
//! updated at the end of every epoch.  A message signed by a key that is not
//! in the validator set is silently dropped (after logging) before it reaches
//! the BFT consensus engine.  This is the `assert_consensus_sender_is_validator()`
//! invariant documented below.
//!
//! This membership check means that creating new key pairs confers no additional
//! voting power.  An attacker who is not a registered validator cannot inject
//! `Propose`, `Vote`, or `Commit` messages that will be acted upon.
//!
//! ## Secondary Defence: Proof-of-Work for Peer Discovery
//!
//! New peers attempting to join the mesh MUST present a valid proof-of-work
//! (PoW) nonce attached to their identity announcement.  This is implemented
//! in `lib-network/src/identity/proof_of_work.rs` and enforced in the
//! bootstrap handshake.  PoW raises the cost of creating many ephemeral
//! identities for spam / eclipse attacks.
//!
//! ## Tertiary Defence: Reputation System
//!
//! Existing peers are tracked with a floating-point reputation score
//! (`trust_score` in `PeerEntry`).  Peers that violate rate limits, present
//! invalid signatures, or send malformed messages have their score decremented.
//! Peers with very low scores are evicted from the peer registry.
//!
//! # Invariants
//!
//! The following invariants MUST hold at all times:
//!
//! 1. **No anonymous consensus messages**: Every `ValidatorMessage` MUST be
//!    accompanied by a verifiable signature from a known validator public key.
//!
//! 2. **Validator-set membership**: A peer's public key MUST appear in the
//!    current active validator set before any of its consensus messages are
//!    forwarded to the BFT engine.
//!
//! 3. **Key uniqueness**: The `PeerIdMapper` enforces a 1-to-1 mapping between
//!    `PublicKey` and `UnifiedPeerId`.  Attempting to register two `UnifiedPeerId`
//!    values that share the same `public_key` is an error.

use lib_crypto::PublicKey;

// =============================================================================
// INVARIANT: Consensus Sender Authentication (closes #984)
// =============================================================================

/// Assert that a consensus message sender is a member of the active validator set.
///
/// This is the primary Sybil-resistance check for the consensus layer.  It MUST
/// be called for every inbound `ValidatorMessage` before the message is forwarded
/// to the BFT engine.
///
/// # Arguments
///
/// * `sender` - The public key extracted from the signed consensus message.
/// * `validator_set` - The current active validator set (slice of public keys).
///
/// # Errors
///
/// Returns `Err` when `sender` is not present in `validator_set`.  The caller
/// MUST drop the message and log the violation.  It SHOULD also decrement the
/// sender's reputation score in the peer registry.
///
/// # Security Note
///
/// This check alone does not prevent a compromised validator key from being
/// used by an attacker.  Key revocation and slashing (handled by lib-consensus)
/// provide the complementary defence for that threat model.
///
/// # Example
///
/// ```rust
/// use lib_network::identity::sybil_resistance::assert_consensus_sender_is_validator;
/// use lib_crypto::PublicKey;
///
/// let sender = PublicKey::new(vec![0x01, 0x02, 0x03]);
/// let validator_set = vec![sender.clone()];
///
/// assert!(assert_consensus_sender_is_validator(&sender, &validator_set).is_ok());
///
/// let outsider = PublicKey::new(vec![0xFF, 0xFF]);
/// assert!(assert_consensus_sender_is_validator(&outsider, &validator_set).is_err());
/// ```
pub fn assert_consensus_sender_is_validator(
    sender: &PublicKey,
    validator_set: &[PublicKey],
) -> Result<(), String> {
    if !validator_set.iter().any(|v| v.key_id == sender.key_id) {
        return Err(format!(
            "SYBIL RESISTANCE: consensus message from non-validator {}; \
             message MUST be dropped",
            hex::encode(&sender.key_id[..sender.key_id.len().min(8)])
        ));
    }
    Ok(())
}

/// Assert that a peer identity has a valid (non-zero) key_id.
///
/// A peer with an all-zero key_id MUST be rejected immediately.  An all-zero
/// key_id indicates an uninitialized key and would break all downstream identity
/// checks.  Since key_id is `[u8; 32]`, it is never empty; only the all-zero
/// case is checked.
///
/// # Errors
///
/// Returns `Err` when the public key's `key_id` is all-zero (uninitialized).
pub fn assert_peer_identity_valid(peer_key: &PublicKey) -> Result<(), String> {
    // Check that key_id is not all zeros (which would indicate an uninitialized key).
    // key_id is [u8; 32] so is_empty() does not apply; the all-zero check is sufficient.
    if peer_key.key_id == [0u8; 32] {
        return Err(
            "IDENTITY INVARIANT: peer public key has all-zero key_id (uninitialized key)".to_string()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(id: &[u8]) -> PublicKey {
        PublicKey::new(id.to_vec())
    }

    // ---- assert_consensus_sender_is_validator ----

    #[test]
    fn known_validator_is_accepted() {
        let validator = make_key(&[0x01, 0x02, 0x03]);
        let set = vec![validator.clone()];
        assert!(assert_consensus_sender_is_validator(&validator, &set).is_ok());
    }

    #[test]
    fn unknown_sender_is_rejected() {
        let validator = make_key(&[0x01, 0x02]);
        let outsider = make_key(&[0xFF, 0xFE]);
        let set = vec![validator];
        let result = assert_consensus_sender_is_validator(&outsider, &set);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("SYBIL RESISTANCE"),
            "Error must reference Sybil resistance"
        );
    }

    #[test]
    fn empty_validator_set_rejects_all() {
        let sender = make_key(&[0x01]);
        let result = assert_consensus_sender_is_validator(&sender, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_validators_first_match_accepted() {
        let v1 = make_key(&[0x01]);
        let v2 = make_key(&[0x02]);
        let v3 = make_key(&[0x03]);
        let set = vec![v1.clone(), v2.clone(), v3.clone()];

        assert!(assert_consensus_sender_is_validator(&v1, &set).is_ok());
        assert!(assert_consensus_sender_is_validator(&v2, &set).is_ok());
        assert!(assert_consensus_sender_is_validator(&v3, &set).is_ok());
    }

    #[test]
    fn prefix_match_does_not_satisfy_check() {
        // A key that is a prefix of a validator key must NOT match.
        let validator = make_key(&[0x01, 0x02, 0x03, 0x04]);
        let prefix_key = make_key(&[0x01, 0x02]);
        let set = vec![validator];
        let result = assert_consensus_sender_is_validator(&prefix_key, &set);
        assert!(result.is_err(), "Prefix key should not satisfy validator membership");
    }

    // ---- assert_peer_identity_valid ----

    #[test]
    fn non_empty_key_is_valid() {
        let key = make_key(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(assert_peer_identity_valid(&key).is_ok());
    }

    #[test]
    fn all_zero_key_is_invalid() {
        // [u8; 32] cannot be empty, but an all-zero key_id signals an uninitialized key.
        let key = make_key(&[0u8; 32]);
        let result = assert_peer_identity_valid(&key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("all-zero"));
    }

    #[test]
    fn single_non_zero_byte_is_valid() {
        // A key with one non-zero byte (even if all others are zero) is valid.
        let mut bytes = vec![0u8; 32];
        bytes[31] = 1;
        let key = make_key(&bytes);
        assert!(assert_peer_identity_valid(&key).is_ok());
    }
}
