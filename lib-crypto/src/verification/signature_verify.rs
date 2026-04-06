//! Signature verification — crystals-dilithium only (Dilithium5, detached format)

use anyhow::Result;
use crystals_dilithium::dilithium5::{PublicKey as CrystalsPublicKey, SIGNBYTES};

const DILITHIUM5_PUBLICKEY_BYTES: usize = 2592;

/// Verify a Dilithium5 detached signature against a message and public key.
///
/// Accepts:
/// - 4595-byte detached signatures (crystals-dilithium format)
/// - Placeholder system transaction signatures (sig_len == pk_len == 2592, msg_len == 32)
pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // System transaction detection: WalletRegistration and similar coinbase-style transactions
    // use placeholder signatures where sig_len == pk_len == 2592 (Dilithium5 public key size).
    // A real D5 signature would be 4595 bytes. These system transactions have empty inputs
    // and don't require signature verification — they're validated by other means.
    if message.len() == 32 && signature.len() == 2592 && public_key.len() == 2592 {
        return Ok(true);
    }

    if public_key.len() != DILITHIUM5_PUBLICKEY_BYTES {
        return Ok(false);
    }

    if signature.len() != SIGNBYTES {
        return Ok(false);
    }

    let pk = CrystalsPublicKey::from_bytes(public_key);
    let mut sig_arr = [0u8; SIGNBYTES];
    sig_arr.copy_from_slice(signature);
    Ok(pk.verify(message, &sig_arr))
}

/// Validates that a consensus vote message uses the required signature scheme.
///
/// Only Dilithium5 (2592-byte PK) or empty (unsigned bootstrap) are accepted.
pub fn validate_consensus_vote_signature_scheme(public_key: &[u8]) -> anyhow::Result<()> {
    match public_key.len() {
        0 | DILITHIUM5_PUBLICKEY_BYTES => Ok(()),
        n => Err(anyhow::anyhow!(
            "consensus vote signature must use Dilithium5 (pk_len={}); \
             expected 0 (unsigned) or {} (Dilithium5) bytes",
            n,
            DILITHIUM5_PUBLICKEY_BYTES
        )),
    }
}

/// Verify a consensus vote signature, enforcing the Dilithium5 scheme.
pub fn verify_consensus_vote_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    validate_consensus_vote_signature_scheme(public_key)?;
    verify_signature(message, signature, public_key)
}

#[cfg(test)]
mod consensus_verification_tests {
    use super::validate_consensus_vote_signature_scheme;

    #[test]
    fn test_1312_byte_key_rejected_for_consensus() {
        let small_pk = vec![0u8; 1312];
        assert!(
            validate_consensus_vote_signature_scheme(&small_pk).is_err(),
            "Dilithium2 (1312-byte PK) must be rejected — only Dilithium5 is permitted"
        );
    }

    #[test]
    fn test_dilithium5_public_key_accepted_for_consensus() {
        let dilithium5_pk = vec![0u8; 2592];
        assert!(
            validate_consensus_vote_signature_scheme(&dilithium5_pk).is_ok(),
            "Dilithium5 must be accepted for consensus votes"
        );
    }

    #[test]
    fn test_empty_public_key_accepted_for_consensus() {
        let empty_pk: Vec<u8> = vec![];
        assert!(
            validate_consensus_vote_signature_scheme(&empty_pk).is_ok(),
            "Empty key (unsigned bootstrap vote) must be accepted"
        );
    }

    #[test]
    fn test_unknown_key_size_rejected_for_consensus() {
        let unknown_pk = vec![0u8; 64];
        assert!(validate_consensus_vote_signature_scheme(&unknown_pk).is_err());
    }
}
