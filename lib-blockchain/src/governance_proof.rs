//! Sovereign-asset governance proof verification (SA-6 / C5).
//!
//! Validates `AssetAuthorityProof::Governance(ApprovalProof::Multisig)` against the
//! on-chain `GovernanceVerifierState`, including Dilithium signatures over a
//! domain-separated action hash.

use crate::contracts::approval_verifier::ApprovalProof;
use crate::contracts::approval_verifier::traits::Signature64;
use crate::contracts::sovereign_asset::{
    economic_rules_active, GovernanceVerifierState,
};
use crate::execution::tx_apply::StateMutator;
use crate::execution::TxApplyError;
use crate::integration::crypto_integration::PublicKey;
use crate::storage::{BlockchainStore, IdentityMetadata};

const GOVERNANCE_PROPOSAL_DOMAIN: &[u8] = b"zhtp/governance-proposal/v1\0";

/// Proposal type tag for rewards policy updates (matches `zhtp-cli` governance flow).
pub const PROPOSAL_TYPE_REWARDS_POLICY_UPDATE: &str = "rewards_policy_update";
pub const PROPOSAL_TYPE_MANIFEST_UPDATE: &str = "manifest_update";
pub const PROPOSAL_TYPE_REWARDS_DELEGATE_ROTATE: &str = "rewards_delegate_rotate";
pub const PROPOSAL_TYPE_AUTHORITY_TRANSFER: &str = "authority_transfer";
pub const PROPOSAL_TYPE_BURN_BPS_UPDATE: &str = "burn_bps_update";

/// Canonical governance action hash (shared with `zhtp-cli dao governance`).
pub fn governance_action_message_hash(
    asset_id: &[u8; 32],
    proposal_type: &str,
    payload_hash: &[u8; 32],
) -> [u8; 32] {
    lib_crypto::hash_blake3(
        &[
            GOVERNANCE_PROPOSAL_DOMAIN,
            proposal_type.as_bytes(),
            asset_id.as_slice(),
            payload_hash.as_slice(),
        ]
        .concat(),
    )
}

/// Compress a Dilithium signature into the wire `Signature64` (dao governance CLI).
pub fn signature64_from_dilithium(sig: &[u8]) -> Signature64 {
    let h1 = lib_crypto::hash_blake3(sig);
    let h2 = lib_crypto::hash_blake3(&[h1.as_slice(), b"sig64"].concat());
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h1);
    out[32..].copy_from_slice(&h2);
    Signature64::new(out)
}

fn public_key_from_identity_metadata(meta: &IdentityMetadata) -> Option<PublicKey> {
    let dilithium: [u8; 2592] = meta.public_key.as_slice().try_into().ok()?;
    if meta.kyber_public_key.len() == 1568 {
        let kyber: [u8; 1568] = meta.kyber_public_key.as_slice().try_into().ok()?;
        Some(PublicKey::new_with_kyber(dilithium, kyber))
    } else {
        Some(PublicKey::new(dilithium))
    }
}

fn resolve_public_key_by_key_id(
    store: &dyn BlockchainStore,
    key_id: &[u8; 32],
) -> Option<Vec<u8>> {
    let iter = store.iter_identity_metadata().ok()?;
    for meta in iter {
        let pk = public_key_from_identity_metadata(&meta)?;
        if &pk.key_id == key_id {
            return Some(meta.public_key);
        }
    }
    None
}

fn verify_dilithium_over_hash(
    message_hash: &[u8; 32],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    lib_crypto::verification::verify_signature(message_hash, signature, public_key)
        .unwrap_or(false)
}

/// Verify a multisig governance proof against the configured verifier.
pub fn verify_governance_multisig_proof(
    mutator: &StateMutator<'_>,
    verifier: &GovernanceVerifierState,
    proof: &ApprovalProof,
    expected_message_hash: &[u8; 32],
    block_height: u64,
) -> Result<(), TxApplyError> {
    let ApprovalProof::Multisig {
        signatures,
        signers,
        threshold,
        message_hash,
        raw_signatures,
    } = proof
    else {
        return Err(TxApplyError::InvalidType(
            "governance action requires Multisig ApprovalProof".into(),
        ));
    };

    if message_hash != expected_message_hash {
        return Err(TxApplyError::InvalidType(
            "governance proof message_hash mismatch".into(),
        ));
    }

    if signatures.len() != signers.len() {
        return Err(TxApplyError::InvalidType(
            "governance multisig signature/signer count mismatch".into(),
        ));
    }

    let (authorized, required_threshold) = match verifier {
        GovernanceVerifierState::Single { signer_key_id } => {
            if signers.len() != 1 || signers[0] != *signer_key_id {
                return Err(TxApplyError::InvalidType(
                    "single verifier requires exactly one authorized signer".into(),
                ));
            }
            (vec![*signer_key_id], 1u8)
        }
        GovernanceVerifierState::Multisig {
            signers: authorized_signers,
            threshold: verifier_threshold,
        } => (authorized_signers.clone(), *verifier_threshold),
    };

    let effective_threshold = (*threshold).max(required_threshold);
    if signers.len() < effective_threshold as usize {
        return Err(TxApplyError::InvalidType(format!(
            "governance multisig insufficient approvals: have {}, need {}",
            signers.len(),
            effective_threshold
        )));
    }

    let mut seen = std::collections::HashSet::new();
    for signer in signers {
        if !authorized.contains(signer) {
            return Err(TxApplyError::InvalidType(
                "governance signer not in on-chain verifier set".into(),
            ));
        }
        if !seen.insert(*signer) {
            return Err(TxApplyError::InvalidType(
                "duplicate governance multisig signer".into(),
            ));
        }
    }

    if economic_rules_active(block_height) {
        if raw_signatures.len() != signers.len() {
            return Err(TxApplyError::InvalidType(
                "governance multisig requires raw_signatures when economic rules are active"
                    .into(),
            ));
        }
        for (idx, (signer, raw_sig)) in signers.iter().zip(raw_signatures.iter()).enumerate() {
            let wire_sig = signatures
                .get(idx)
                .ok_or_else(|| TxApplyError::InvalidType("missing wire signature".into()))?;
            if signature64_from_dilithium(raw_sig) != *wire_sig {
                return Err(TxApplyError::InvalidType(
                    "governance wire signature does not match raw Dilithium signature".into(),
                ));
            }
            let pk = resolve_public_key_by_key_id(mutator.store(), signer).ok_or_else(|| {
                TxApplyError::InvalidType(format!(
                    "governance signer {} has no registered identity",
                    hex::encode(&signer[..8])
                ))
            })?;
            if !verify_dilithium_over_hash(expected_message_hash, raw_sig, &pk) {
                return Err(TxApplyError::InvalidType(
                    "governance multisig signature verification failed".into(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{convert_legacy_identity, BlockchainStore, SledStore};
    use crate::transaction::IdentityTransactionData;
    use lib_crypto::KeyPair;
    use std::sync::Arc;

    fn store_with_signer(kp: &KeyPair) -> Arc<dyn BlockchainStore> {
        let store = Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn BlockchainStore>;
        let did = format!("did:zhtp:{}", hex::encode(kp.public_key.key_id));
        let legacy = IdentityTransactionData {
            did,
            display_name: "test".to_string(),
            public_key: kp.public_key.dilithium_pk.to_vec(),
            ownership_proof: vec![],
            identity_type: "human".to_string(),
            did_document_hash: crate::types::Hash::zero(),
            created_at: 1,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: vec![],
            owned_wallets: vec![],
            kyber_public_key: kp.public_key.kyber_pk.to_vec(),
        };
        let (consensus, metadata) = convert_legacy_identity(&legacy);
        store.begin_block(0).unwrap();
        StateMutator::new(store.as_ref())
            .register_identity(&consensus.did_hash, &consensus, &metadata)
            .expect("seed identity");
        store.commit_block().unwrap();
        store
    }

    #[test]
    fn multisig_proof_verifies_with_raw_signatures() {
        let kp1 = KeyPair::generate().unwrap();
        let store = store_with_signer(&kp1);

        let asset_id = [0xAB; 32];
        let policy_hash = [0xCD; 32];
        let msg = governance_action_message_hash(
            &asset_id,
            PROPOSAL_TYPE_REWARDS_POLICY_UPDATE,
            &policy_hash,
        );
        let sig = kp1.sign(&msg).unwrap();
        let raw = sig.signature;
        let proof = ApprovalProof::Multisig {
            signatures: vec![signature64_from_dilithium(&raw)],
            signers: vec![kp1.public_key.key_id],
            threshold: 1,
            message_hash: msg,
            raw_signatures: vec![raw],
        };
        let verifier = GovernanceVerifierState::Single {
            signer_key_id: kp1.public_key.key_id,
        };

        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        verify_governance_multisig_proof(&mutator, &verifier, &proof, &msg, 1).unwrap();
        store.commit_block().unwrap();
    }
}