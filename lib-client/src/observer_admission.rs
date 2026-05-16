//! Observer admission client helpers
//!
//! Builds the JSON payloads for the observer admission endpoints so mobile
//! clients never have to construct bincode or understand the transaction format.

use crate::crypto;
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature};
use lib_blockchain::transaction::{RegisterObserverData, Transaction};
use lib_crypto::types::SignatureAlgorithm;
use lib_types::{ObserverProofLevel, ObserverRateLimitTier};
use serde::{Deserialize, Serialize};

// ============================================================================
// Input type
// ============================================================================

/// All inputs required to build an observer registration payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterObserverInputs {
    pub observer_node_did: String,
    pub observer_dilithium_pk: Vec<u8>,
    pub endpoints: Vec<String>,
    pub sponsor_user_did: String,
    pub sponsor_proof_level: ObserverProofLevel,
    pub allowed_network: String,
    pub trusted_sync_scope: Option<String>,
    pub rate_limit_tier: ObserverRateLimitTier,
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
pub fn build_register_observer_payload(inputs: &RegisterObserverInputs) -> Vec<u8> {
    let zeroed_sig = zeroed_signature();
    let data = inputs_to_data(inputs, Vec::new());
    let tx = Transaction::new_register_observer(inputs.chain_id, data, zeroed_sig);
    let hash = lib_blockchain::transaction::hashing::hash_for_signature(&tx);
    hash.as_bytes().to_vec()
}

/// Returns the full JSON body for `POST /api/v1/observer/admission/register`.
///
/// `sponsor_signature`  — Dilithium signature over the bytes from
///                        `build_register_observer_payload`
/// `sponsor_dilithium_pk` — raw 2592-byte Dilithium public key of the sponsor
/// `sponsor_kyber_pk`   — raw 1568-byte Kyber public key of the sponsor
pub fn build_register_observer_request(
    inputs: &RegisterObserverInputs,
    sponsor_signature: &[u8],
    sponsor_dilithium_pk: &[u8],
    sponsor_kyber_pk: &[u8],
) -> serde_json::Value {
    serde_json::json!({
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
    })
}

// ============================================================================
// Internal helpers
// ============================================================================

fn inputs_to_data(inputs: &RegisterObserverInputs, sponsor_signature: Vec<u8>) -> RegisterObserverData {
    RegisterObserverData {
        observer_node_did: inputs.observer_node_did.clone(),
        observer_public_key: inputs.observer_dilithium_pk.clone(),
        endpoints: inputs.endpoints.clone(),
        sponsor_user_did: inputs.sponsor_user_did.clone(),
        sponsor_proof_level: inputs.sponsor_proof_level.clone(),
        sponsor_signature,
        allowed_network: inputs.allowed_network.clone(),
        trusted_sync_scope: inputs.trusted_sync_scope.clone(),
        rate_limit_tier: inputs.rate_limit_tier.clone(),
        expires_at: inputs.expires_at,
        nonce: inputs.nonce,
    }
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
            sponsor_proof_level: ObserverProofLevel::Basic,
            allowed_network: "testnet".into(),
            trusted_sync_scope: None,
            rate_limit_tier: ObserverRateLimitTier::Standard,
            expires_at: None,
            nonce: 0,
            chain_id: 0x03,
        }
    }

    #[test]
    fn payload_is_32_bytes() {
        let inputs = test_inputs();
        let payload = build_register_observer_payload(&inputs);
        assert_eq!(payload.len(), 32, "canonical hash must be 32 bytes");
    }

    #[test]
    fn payload_is_deterministic() {
        let inputs = test_inputs();
        let a = build_register_observer_payload(&inputs);
        let b = build_register_observer_payload(&inputs);
        assert_eq!(a, b, "payload must be deterministic");
    }

    #[test]
    fn payload_changes_with_nonce() {
        let inputs_0 = test_inputs();
        let mut inputs_1 = test_inputs();
        inputs_1.nonce = 1;
        let a = build_register_observer_payload(&inputs_0);
        let b = build_register_observer_payload(&inputs_1);
        assert_ne!(a, b, "different nonce must produce different payload");
    }

    #[test]
    fn request_json_contains_required_fields() {
        let inputs = test_inputs();
        let sig = vec![1u8; 64];
        let dpk = vec![2u8; 2592];
        let kpk = vec![3u8; 1568];
        let json = build_register_observer_request(&inputs, &sig, &dpk, &kpk);
        assert!(json.get("observer_node_did").is_some());
        assert!(json.get("sponsor_user_did").is_some());
        assert!(json.get("nonce").is_some());
        assert!(json.get("tx_signature").is_some());
    }
}
