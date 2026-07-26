//! Production grant signature crypto (Dilithium5).
//!
//! `lib-access-control` stays crypto-free; this crate implements
//! [`GrantSignatureVerifier`] for dual-auth elevate.

use lib_access_control::GrantSignatureVerifier;
use lib_crypto::post_quantum::dilithium::dilithium5_verify;

/// Dilithium5 verifier for `GrantAuthScheme::Signature`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Dilithium5GrantVerifier;

impl GrantSignatureVerifier for Dilithium5GrantVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        dilithium5_verify(message, signature, public_key).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_access_control::{
        grant_exercise_message, verify_grant_proof, GrantAuthDescriptor, GrantAuthScheme,
        GrantClass, GrantExerciseProof, GrantRecord,
    };
    use lib_access_control::{AccessDomain, AccessOperation};
    use lib_crypto::post_quantum::dilithium::{dilithium5_keypair, dilithium5_sign};

    #[test]
    fn dilithium_grant_proof_roundtrip() {
        let (pk, sk) = dilithium5_keypair();
        let rec = GrantRecord::offer_council(
            "g-dil",
            "did:zhtp:alice",
            "did:zhtp:council",
            GrantClass::AuditRead,
            vec![AccessDomain::WalletGraph],
            vec![AccessOperation::Read],
        )
        .claim_with_auth(
            GrantAuthDescriptor {
                scheme: GrantAuthScheme::Signature,
                public_key: pk.clone(),
            },
            1_000,
        )
        .unwrap();

        let binding = "sess-bind-1";
        let signed_at = 1_050u64;
        let msg = grant_exercise_message("g-dil", "did:zhtp:alice", binding, signed_at);
        let sig = dilithium5_sign(&msg, &sk).expect("sign");

        let proof = GrantExerciseProof {
            grant_id: "g-dil".into(),
            grantee_did: "did:zhtp:alice".into(),
            session_binding: binding.into(),
            signed_at_unix: signed_at,
            signature: sig,
        };
        assert!(
            verify_grant_proof(&rec, &proof, 1_060, binding, &Dilithium5GrantVerifier).is_ok()
        );

        // Wrong binding must fail.
        assert!(
            verify_grant_proof(&rec, &proof, 1_060, "other-bind", &Dilithium5GrantVerifier)
                .is_err()
        );
    }
}
