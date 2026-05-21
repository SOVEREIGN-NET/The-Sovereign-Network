//! Observer admission client helpers
//!
//! Builds the JSON payloads for the observer admission endpoints so mobile
//! clients never have to construct bincode or understand the transaction format.

use lib_blockchain::integration::crypto_integration::{PublicKey, Signature};
use lib_blockchain::transaction::{RegisterObserverData, Transaction};
use lib_crypto::types::SignatureAlgorithm;
use serde::{Deserialize, Serialize};

// ============================================================================
// Input type
// ============================================================================

/// All inputs required to build an observer registration payload.
///
/// `sponsor_proof_level` and `rate_limit_tier` are plain strings that must
/// match the enum variant names expected by the server (e.g. `"Basic"`,
/// `"Standard"`). They are passed through as JSON and deserialized by the
/// server's serde implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterObserverInputs {
    pub observer_node_did: String,
    pub observer_dilithium_pk: Vec<u8>,
    pub endpoints: Vec<String>,
    pub sponsor_user_did: String,
    pub sponsor_proof_level: String,
    pub allowed_network: String,
    pub trusted_sync_scope: Option<String>,
    pub rate_limit_tier: String,
    pub expires_at: Option<u64>,
    pub nonce: u64,
    pub chain_id: u8,
}

// ============================================================================
// Payload builder
// ============================================================================

/// Returns the canonical signing bytes for an observer registration.
///
/// These are the 32 bytes the sponsor must sign with Dilithium before
/// calling `/admission/register`. Matches exactly what the server's
/// `hash_for_signature()` produces.
///
/// Returns `Err` if `sponsor_proof_level` or `rate_limit_tier` are not valid
/// enum variant names (e.g. `"Basic"`, `"Standard"`).
pub fn build_register_observer_payload(inputs: &RegisterObserverInputs) -> Result<Vec<u8>, serde_json::Error> {
    let zeroed_sig = zeroed_signature();
    let data = inputs_to_data(inputs, Vec::new())?;
    let tx = Transaction::new_register_observer(inputs.chain_id, data, zeroed_sig);
    let hash = lib_blockchain::transaction::hashing::hash_for_signature(&tx);
    Ok(hash.as_bytes().to_vec())
}

/// Returns the full JSON body for `POST /api/v1/observer/admission/register`.
///
/// `sponsor_signature`  — Dilithium signature over the bytes from
///                        `build_register_observer_payload`
/// `sponsor_dilithium_pk` — raw 2592-byte Dilithium public key of the sponsor
/// `sponsor_kyber_pk`   — raw 1568-byte Kyber public key of the sponsor
///
/// Returns `Err` if `sponsor_proof_level` or `rate_limit_tier` are not valid
/// enum variant names.
pub fn build_register_observer_request(
    inputs: &RegisterObserverInputs,
    sponsor_signature: &[u8],
    sponsor_dilithium_pk: &[u8],
    sponsor_kyber_pk: &[u8],
) -> Result<serde_json::Value, serde_json::Error> {
    // Validate enum fields before building the payload — ensures bad variant
    // names are caught here rather than silently producing a rejected request.
    inputs_to_data(inputs, Vec::new())?;
    Ok(serde_json::json!({
        "observer_node_did":   inputs.observer_node_did,
        "observer_public_key": inputs.observer_dilithium_pk,
        "endpoints":           inputs.endpoints,
        "sponsor_user_did":    inputs.sponsor_user_did,
        "sponsor_proof_level": inputs.sponsor_proof_level,
        "sponsor_signature":   sponsor_signature,
        "allowed_network":     inputs.allowed_network,
        "trusted_sync_scope":  inputs.trusted_sync_scope,
        "rate_limit_tier":     inputs.rate_limit_tier,
        "expires_at":          inputs.expires_at,
        "nonce":               inputs.nonce,
        "tx_signature": {
            "signature_bytes":     sponsor_signature,
            "signer_dilithium_pk": sponsor_dilithium_pk,
            "signer_kyber_pk":     sponsor_kyber_pk,
        }
    }))
}

// ============================================================================
// Internal helpers
// ============================================================================

fn inputs_to_data(inputs: &RegisterObserverInputs, sponsor_signature: Vec<u8>) -> Result<RegisterObserverData, serde_json::Error> {
    // Parse string fields into their typed enum equivalents via serde_json.
    // Variant names must match the server's enum (e.g. "Basic", "Standard").
    let proof_level = serde_json::from_value(serde_json::Value::String(inputs.sponsor_proof_level.clone()))?;
    let rate_tier = serde_json::from_value(serde_json::Value::String(inputs.rate_limit_tier.clone()))?;
    Ok(RegisterObserverData {
        observer_node_did: inputs.observer_node_did.clone(),
        observer_public_key: inputs.observer_dilithium_pk.clone(),
        endpoints: inputs.endpoints.clone(),
        sponsor_user_did: inputs.sponsor_user_did.clone(),
        sponsor_proof_level: proof_level,
        sponsor_signature,
        allowed_network: inputs.allowed_network.clone(),
        trusted_sync_scope: inputs.trusted_sync_scope.clone(),
        rate_limit_tier: rate_tier,
        expires_at: inputs.expires_at,
        nonce: inputs.nonce,
    })
}

fn zeroed_signature() -> Signature {
    Signature {
        signature: Vec::new(),
        public_key: PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: [0u8; 32],
        },
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: 0,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_inputs() -> RegisterObserverInputs {
        RegisterObserverInputs {
            observer_node_did: "did:zhtp:obs-test-node".into(),
            observer_dilithium_pk: vec![0u8; 2592],
            endpoints: vec!["127.0.0.1:9000".into()],
            sponsor_user_did: "did:zhtp:sponsor-test".into(),
            sponsor_proof_level: "Basic".into(),
            allowed_network: "testnet".into(),
            trusted_sync_scope: None,
            rate_limit_tier: "Standard".into(),
            expires_at: None,
            nonce: 0,
            chain_id: 0x03,
        }
    }

    #[test]
    fn payload_is_32_bytes() {
        let inputs = test_inputs();
        let payload = build_register_observer_payload(&inputs).expect("valid inputs");
        assert_eq!(payload.len(), 32, "canonical hash must be 32 bytes");
    }

    #[test]
    fn payload_is_deterministic() {
        let inputs = test_inputs();
        let a = build_register_observer_payload(&inputs).expect("valid inputs");
        let b = build_register_observer_payload(&inputs).expect("valid inputs");
        assert_eq!(a, b, "payload must be deterministic");
    }

    #[test]
    fn payload_changes_with_nonce() {
        let inputs_0 = test_inputs();
        let mut inputs_1 = test_inputs();
        inputs_1.nonce = 1;
        let a = build_register_observer_payload(&inputs_0).expect("valid inputs");
        let b = build_register_observer_payload(&inputs_1).expect("valid inputs");
        assert_ne!(a, b, "different nonce must produce different payload");
    }

    #[test]
    fn invalid_proof_level_returns_err() {
        let mut inputs = test_inputs();
        inputs.sponsor_proof_level = "NotAVariant".into();
        assert!(build_register_observer_payload(&inputs).is_err());
        assert!(build_register_observer_request(&inputs, &[], &[], &[]).is_err());
    }

    #[test]
    fn request_json_contains_required_fields() {
        let inputs = test_inputs();
        let sig = vec![1u8; 64];
        let dpk = vec![2u8; 2592];
        let kpk = vec![3u8; 1568];
        let json = build_register_observer_request(&inputs, &sig, &dpk, &kpk).expect("valid inputs");
        assert!(json.get("observer_node_did").is_some());
        assert!(json.get("sponsor_user_did").is_some());
        assert!(json.get("nonce").is_some());
        assert!(json.get("tx_signature").is_some());
    }

    #[test]
    fn payload_signed_via_sign_message_produces_valid_request() {
        // Acceptance criterion 2: payload signed via zhtp_client_sign_message
        // produces a request body accepted by /admission/register.
        //
        // We verify here at the lib-client boundary:
        //   - sign_message produces a non-empty signature over the canonical bytes
        //   - build_register_observer_request includes that signature in tx_signature
        //   - the request JSON is structurally valid for /admission/register
        //
        // The server-side acceptance (executor nonce check + fee debit) is covered
        // by the round-trip test in zhtp/src/api/handlers/observer_admission.rs.

        let sponsor = crate::identity::generate_identity("test-device".into())
            .expect("generate sponsor identity");

        let mut inputs = test_inputs();
        inputs.observer_dilithium_pk = sponsor.public_key.clone();

        // Step 1: get canonical bytes (what mobile calls zhtp_observer_build_payload for)
        let payload = build_register_observer_payload(&inputs).expect("valid inputs");
        assert_eq!(payload.len(), 32);

        // Step 2: sign via the same path as zhtp_client_sign_message FFI
        let signature = crate::identity::sign_message(&sponsor, &payload)
            .expect("sign_message must succeed");
        assert!(!signature.is_empty(), "signature must be non-empty");

        // Step 3: build the register request (what mobile calls zhtp_observer_build_request for)
        let kyber_pk = sponsor.kyber_public_key.clone();
        let json = build_register_observer_request(
            &inputs,
            &signature,
            &sponsor.public_key,
            &kyber_pk,
        ).expect("valid inputs");

        // Verify all fields /admission/register requires are present and non-null
        assert_eq!(json["observer_node_did"], inputs.observer_node_did);
        assert_eq!(json["sponsor_user_did"], inputs.sponsor_user_did);
        assert_eq!(json["nonce"], inputs.nonce);
        assert_eq!(json["allowed_network"], inputs.allowed_network);
        assert!(json["sponsor_signature"].is_array(), "sponsor_signature must be array");
        assert!(json["tx_signature"]["signature_bytes"].is_array(), "signature_bytes must be array");
        assert!(json["tx_signature"]["signer_dilithium_pk"].is_array(), "signer pk must be array");

        // Verify the signature bytes in the JSON match what sign_message produced
        let sig_from_json: Vec<u8> = serde_json::from_value(json["tx_signature"]["signature_bytes"].clone())
            .expect("deserialize signature");
        assert_eq!(sig_from_json, signature, "signature in request must match sign_message output");
    }
}
