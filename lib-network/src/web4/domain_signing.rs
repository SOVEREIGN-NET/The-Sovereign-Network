//! Canonical domain-update signing and Dilithium5 verification.
//!
//! Wire format matches zhtp-cli and lib-client:
//!   `domain|expected_previous_manifest_cid|new_manifest_cid|timestamp`

use anyhow::{anyhow, Result};
use lib_crypto::verify_signature;

/// Hex-encoded Dilithium5 detached signatures are 4595 bytes → 9190 hex chars.
pub const DILITHIUM5_HEX_SIGNATURE_LEN: usize = 9190;

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

/// Build the canonical domain-update signing message.
pub fn domain_update_signing_message(
    domain: &str,
    expected_previous_manifest_cid: &str,
    new_manifest_cid: &str,
    timestamp: u64,
) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}",
        domain, expected_previous_manifest_cid, new_manifest_cid, timestamp
    )
    .into_bytes()
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

    let message = domain_update_signing_message(
        domain,
        expected_previous_manifest_cid,
        new_manifest_cid,
        timestamp,
    );

    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| anyhow!("Invalid signature hex: {}", e))?;

    verify_signature(&message, &signature_bytes, owner_pk.as_slice())
        .map_err(|e| anyhow!("Domain update signature verification failed: {}", e))
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
}