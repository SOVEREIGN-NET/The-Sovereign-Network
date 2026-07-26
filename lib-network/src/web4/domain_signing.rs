//! Canonical domain-update signing and Dilithium5 verification.
//!
//! ## Wire format
//! `ZHTP-domain-update-v1\0domain|expected_previous_manifest_cid|new_manifest_cid|timestamp`
//!
//! The legacy unprefixed form was accepted during a one-release dual-accept
//! window (PR #2746 / #2914) and has been removed. All signers must now
//! include the `ZHTP-domain-update-v1\0` domain separation prefix.

use anyhow::{anyhow, Result};
use lib_crypto::verify_signature;

/// Hex-encoded Dilithium5 detached signatures are 4595 bytes → 9190 hex chars.
pub const DILITHIUM5_HEX_SIGNATURE_LEN: usize = 9190;

/// Domain separation prefix for domain update signatures.
/// Mirrors the `ZHTP-identity-sig-v1\0` pattern used in identity attestations.
pub const ZHTP_DOMAIN_UPDATE_SIGN_DOMAIN: &[u8] = b"ZHTP-domain-update-v1\0";

/// Returns true when a stored owner public key is present (full Dilithium5 size, non-zero).
pub fn has_owner_signing_key(owner_dilithium_pk: &[u8]) -> bool {
    owner_dilithium_pk.len() == 2592 && !owner_dilithium_pk.iter().all(|&x| x == 0)
}

fn owner_pk_array(owner_dilithium_pk: &[u8]) -> Result<[u8; 2592]> {
    if owner_dilithium_pk.len() != 2592 {
        return Err(anyhow!("owner_dilithium_pk must be exactly 2592 bytes"));
    }
    let mut arr = [0u8; 2592];
    arr.copy_from_slice(owner_dilithium_pk);
    Ok(arr)
}

/// Pipe-delimited payload shared by current and legacy formats.
fn domain_update_payload(
    domain: &str,
    expected_previous_manifest_cid: &str,
    new_manifest_cid: &str,
    timestamp: u64,
) -> String {
    format!(
        "{}|{}|{}|{}",
        domain, expected_previous_manifest_cid, new_manifest_cid, timestamp
    )
}

/// Build the canonical domain-update signing message with domain separation prefix.
///
/// **Signers must use this** (CLI, lib-client, mobile). Do not reimplement the prefix.
pub fn domain_update_signing_message(
    domain: &str,
    expected_previous_manifest_cid: &str,
    new_manifest_cid: &str,
    timestamp: u64,
) -> Vec<u8> {
    let mut message = ZHTP_DOMAIN_UPDATE_SIGN_DOMAIN.to_vec();
    message.extend_from_slice(
        domain_update_payload(
            domain,
            expected_previous_manifest_cid,
            new_manifest_cid,
            timestamp,
        )
        .as_bytes(),
    );
    message
}


/// Build the single canonical verification message (prefixed).
///
/// Legacy unprefixed candidates were removed after the one-release dual-accept
/// window. All verifiers now require the `ZHTP-domain-update-v1\0` prefix.
pub fn domain_update_verify_candidates(
    domain: &str,
    expected_previous_manifest_cid: &str,
    new_manifest_cid: &str,
    timestamp: u64,
) -> [Vec<u8>; 1] {
    [domain_update_signing_message(
        domain,
        expected_previous_manifest_cid,
        new_manifest_cid,
        timestamp,
    )]
}

/// Reject missing or malformed owner signatures before mutating domain state.
pub fn validate_domain_owner_signature_hex(signature: &str) -> Option<String> {
    if signature.is_empty() {
        return Some(
            "Domain update requires a valid signature from the domain owner".to_string(),
        );
    }
    if signature.len() != DILITHIUM5_HEX_SIGNATURE_LEN {
        return Some(format!(
            "Invalid signature length: {} chars (expected exactly {} for Dilithium5)",
            signature.len(),
            DILITHIUM5_HEX_SIGNATURE_LEN
        ));
    }
    if !signature.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("Invalid signature: must be hex-encoded Dilithium5 bytes".to_string());
    }
    None
}

/// Build the canonical domain-registration signing message (lib-client / zhtp API).
pub fn domain_registration_signing_message(domain: &str, timestamp: u64, fee_whole: u64) -> Vec<u8> {
    format!("{}|{}|{}", domain, timestamp, fee_whole).into_bytes()
}

/// Verify a domain registration signature against the owner's Dilithium5 public key.
pub fn verify_domain_registration_signature(
    owner_dilithium_pk: &[u8],
    domain: &str,
    timestamp: u64,
    fee_whole: u64,
    signature_hex: &str,
) -> Result<bool> {
    if let Some(error) = validate_domain_owner_signature_hex(signature_hex) {
        return Err(anyhow!(error));
    }

    let owner_pk = owner_pk_array(owner_dilithium_pk)?;
    let message = domain_registration_signing_message(domain, timestamp, fee_whole);
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| anyhow!("Invalid signature hex: {}", e))?;

    verify_signature(&message, &signature_bytes, owner_pk.as_slice())
        .map_err(|e| anyhow!("Domain registration signature verification failed: {}", e))
}

/// Maximum age of a domain transfer authorization signature (5 minutes).
pub const DOMAIN_TRANSFER_SIGNATURE_MAX_AGE_SECS: u64 = 300;

/// Candidate signing messages for domain transfer.
///
/// When a timestamp is present, only the timestamped format is accepted so
/// freshness checks cannot be bypassed via legacy preimages.
pub fn domain_transfer_signing_candidates(
    domain: &str,
    from_did: &str,
    to_did: &str,
    timestamp: Option<u64>,
) -> Vec<Vec<u8>> {
    if let Some(ts) = timestamp {
        return vec![format!("{}|{}|{}|{}", domain, from_did, to_did, ts).into_bytes()];
    }
    vec![
        format!("{}|{}|{}", domain, from_did, to_did).into_bytes(),
        format!("{}|{}", domain, to_did).into_bytes(),
    ]
}

/// Verify a domain transfer signature against the current owner's Dilithium5 public key.
pub fn verify_domain_transfer_signature(
    owner_dilithium_pk: &[u8],
    domain: &str,
    from_did: &str,
    to_did: &str,
    signature_bytes: &[u8],
    timestamp: Option<u64>,
) -> Result<bool> {
    if signature_bytes.is_empty() {
        return Ok(false);
    }

    if let Some(ts) = timestamp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow!("system time error: {}", e))?
            .as_secs();
        let age = now.abs_diff(ts);
        if age > DOMAIN_TRANSFER_SIGNATURE_MAX_AGE_SECS {
            return Ok(false);
        }
    }

    let owner_pk = owner_pk_array(owner_dilithium_pk)?;
    for message in domain_transfer_signing_candidates(domain, from_did, to_did, timestamp) {
        if verify_signature(&message, signature_bytes, owner_pk.as_slice()).unwrap_or(false) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Verify a domain update signature against the stored owner Dilithium5 public key.
///
/// Only the prefixed message (`ZHTP-domain-update-v1\0domain|…|timestamp`) is
/// accepted. The legacy unprefixed dual-accept window has been removed.
pub fn verify_domain_update_signature(
    owner_dilithium_pk: &[u8],
    domain: &str,
    expected_previous_manifest_cid: &str,
    new_manifest_cid: &str,
    timestamp: u64,
    signature_hex: &str,
) -> Result<bool> {
    if let Some(error) = validate_domain_owner_signature_hex(signature_hex) {
        return Err(anyhow!(error));
    }

    let owner_pk = owner_pk_array(owner_dilithium_pk)?;
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| anyhow!("Invalid signature hex: {}", e))?;

    let message = domain_update_signing_message(
        domain,
        expected_previous_manifest_cid,
        new_manifest_cid,
        timestamp,
    );

    verify_signature(&message, &signature_bytes, owner_pk.as_slice())
        .map_err(|e| anyhow!("Domain update signature verification failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::{generate_keypair, sign_message};

    #[test]
    fn domain_registration_roundtrip_sign_and_verify() {
        let keypair = generate_keypair().expect("keypair");
        let domain = "app.zhtp";
        let timestamp = 1_700_000_000u64;
        let fee = 10u64;

        let message = domain_registration_signing_message(domain, timestamp, fee);
        let sig = sign_message(&keypair, &message).expect("sign");
        let sig_hex = hex::encode(&sig.signature);

        let ok = verify_domain_registration_signature(
            keypair.public_key.dilithium_pk.as_slice(),
            domain,
            timestamp,
            fee,
            &sig_hex,
        )
        .expect("verify");
        assert!(ok);
    }

    #[test]
    fn domain_transfer_roundtrip_sign_and_verify() {
        let keypair = generate_keypair().expect("keypair");
        let domain = "app.zhtp";
        let from = "did:zhtp:abc";
        let to = "did:zhtp:def";

        let message = format!("{}|{}", domain, to);
        let sig = sign_message(&keypair, message.as_bytes()).expect("sign");

        let ok = verify_domain_transfer_signature(
            keypair.public_key.dilithium_pk.as_slice(),
            domain,
            from,
            to,
            &sig.signature,
            None,
        )
        .expect("verify");
        assert!(ok);
    }

    #[test]
    fn domain_update_roundtrip_sign_and_verify() {
        let keypair = generate_keypair().expect("keypair");
        let domain = "app.zhtp";
        let prev = "bafkabc123";
        let new_cid = "bafkdef456";
        let timestamp = 1_700_000_000u64;

        let message = domain_update_signing_message(domain, prev, new_cid, timestamp);
        let sig = sign_message(&keypair, &message).expect("sign");
        let sig_hex = hex::encode(&sig.signature);

        let ok = verify_domain_update_signature(
            keypair.public_key.dilithium_pk.as_slice(),
            domain,
            prev,
            new_cid,
            timestamp,
            &sig_hex,
        )
        .expect("verify");
        assert!(ok);

        let bad = verify_domain_update_signature(
            keypair.public_key.dilithium_pk.as_slice(),
            domain,
            prev,
            "bafkwrong",
            timestamp,
            &sig_hex,
        )
        .expect("verify runs");
        assert!(!bad);
    }

    #[test]
    fn domain_update_message_contains_prefix() {
        let domain = "app.zhtp";
        let prev = "bafkabc123";
        let new_cid = "bafkdef456";
        let timestamp = 1_700_000_000u64;

        let message = domain_update_signing_message(domain, prev, new_cid, timestamp);

        // Verify the prefix is present at the start of the message
        assert!(
            message.starts_with(ZHTP_DOMAIN_UPDATE_SIGN_DOMAIN),
            "Message must start with domain separation prefix"
        );

        // Verify the payload follows the prefix correctly
        let payload = &message[ZHTP_DOMAIN_UPDATE_SIGN_DOMAIN.len()..];
        let expected_payload = format!(
            "{}|{}|{}|{}",
            domain, prev, new_cid, timestamp
        );
        assert_eq!(
            payload,
            expected_payload.as_bytes(),
            "Payload after prefix must match pipe-delimited format"
        );
    }

    #[test]
    fn domain_update_signature_rejects_legacy_unprefixed() {
        // Legacy unprefixed signatures must now fail — dual-accept window is closed.
        let keypair = generate_keypair().expect("keypair");
        let domain = "app.zhtp";
        let prev = "bafkabc123";
        let new_cid = "bafkdef456";
        let timestamp = 1_700_000_000u64;

        let raw_message = domain_update_payload(domain, prev, new_cid, timestamp);
        let sig = sign_message(&keypair, raw_message.as_bytes()).expect("sign");
        let sig_hex = hex::encode(&sig.signature);

        let ok = verify_domain_update_signature(
            keypair.public_key.dilithium_pk.as_slice(),
            domain,
            prev,
            new_cid,
            timestamp,
            &sig_hex,
        )
        .expect("verify runs");
        assert!(
            !ok,
            "legacy unprefixed signatures must be rejected after dual-accept window closed"
        );
    }

    #[test]
    fn domain_update_verify_candidates_contains_only_prefixed() {
        let c = domain_update_verify_candidates("d.zhtp", "prev", "next", 1);
        assert_eq!(c.len(), 1, "only one candidate after legacy removal");
        assert!(c[0].starts_with(ZHTP_DOMAIN_UPDATE_SIGN_DOMAIN));
    }
}