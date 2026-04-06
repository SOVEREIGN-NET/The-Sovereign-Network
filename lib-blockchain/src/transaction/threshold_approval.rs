//! Threshold Approval Primitive (#1893)
//!
//! Provides multi-signer threshold approval sets for governance actions that require
//! more than one authorized signature (e.g. Bootstrap Council, Oracle Committee).
//!
//! # Preimage construction
//!
//! Each signer must sign `compute_approval_preimage(tx_type_byte, domain, payload_bytes)`.
//! The preimage is a blake3 hash with domain-separation tags so that signatures for one
//! action cannot be replayed against a different action or domain.

use serde::{Deserialize, Serialize};

use crate::integration::crypto_integration::{PublicKey, SignatureAlgorithm};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A single approval (signature) from one authorized signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approval {
    /// The signer's Dilithium5 public key.
    pub public_key: PublicKey,
    /// The signature algorithm used (must be Dilithium5 for council approvals).
    pub algorithm: SignatureAlgorithm,
    /// Raw signature bytes over the canonical signable preimage.
    pub signature: Vec<u8>,
}

/// The authorization domain that defines which signer set is authoritative.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalDomain {
    /// Bootstrap Council — checked against `Blockchain::bootstrap_council` and `council_threshold`.
    BootstrapCouncil,
    /// A specific DAO council identified by its 32-byte DAO id.
    DaoCouncil { dao_id: [u8; 32] },
    /// Oracle price committee — checked against oracle state committee members.
    OracleCommittee,
}

/// An ordered, deduplicated set of approvals for a governance action.
///
/// `approvals` are kept sorted deterministically by public key bytes (ascending)
/// so that the set is canonical regardless of submission order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThresholdApprovalSet {
    /// Which signer set is authoritative for this action.
    pub domain: ApprovalDomain,
    /// Approvals sorted deterministically by `public_key.key_id` bytes (ascending).
    pub approvals: Vec<Approval>,
}

impl Default for ThresholdApprovalSet {
    fn default() -> Self {
        Self::new(ApprovalDomain::BootstrapCouncil)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from threshold approval validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
    /// The same signer appears more than once; carries the offending `key_id`.
    DuplicateSigner([u8; 32]),
    /// A signature failed cryptographic verification; carries the offending `key_id`.
    InvalidSignature([u8; 32]),
    /// A signer is not a member of the required authorization set; carries `key_id`.
    UnauthorizedSigner([u8; 32]),
    /// Fewer valid member approvals than required.
    ThresholdNotMet { have: usize, need: usize },
}

impl std::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThresholdError::DuplicateSigner(id) => {
                write!(f, "Duplicate signer key_id: {}", hex::encode(id))
            }
            ThresholdError::InvalidSignature(id) => {
                write!(f, "Invalid signature from key_id: {}", hex::encode(id))
            }
            ThresholdError::UnauthorizedSigner(id) => {
                write!(f, "Unauthorized signer key_id: {}", hex::encode(id))
            }
            ThresholdError::ThresholdNotMet { have, need } => {
                write!(f, "Threshold not met: have {have}, need {need}")
            }
        }
    }
}

impl std::error::Error for ThresholdError {}

// ---------------------------------------------------------------------------
// Preimage computation
// ---------------------------------------------------------------------------

/// Domain-separation tag for threshold approval preimages.
///
/// Every signer must sign a blake3 hash that starts with this tag so that
/// approval signatures cannot be cross-replayed across different protocol messages.
pub const THRESHOLD_APPROVAL_DOMAIN_TAG: &[u8] = b"ZHTP_THRESHOLD_APPROVAL_V1";

/// Compute the canonical signable preimage for a threshold-approved action.
///
/// Each signer must sign exactly this hash. The preimage is:
/// ```text
/// blake3(
///   THRESHOLD_APPROVAL_DOMAIN_TAG  ||
///   [tx_type_byte]                 ||
///   LE64(domain_bytes.len())       ||
///   domain_bytes                   ||
///   LE64(payload_bytes.len())      ||
///   payload_bytes
/// )
/// ```
///
/// # Arguments
/// * `tx_type_byte` – The `u8` discriminant of the `TransactionType`.
/// * `domain`       – The `ApprovalDomain` that restricts which signers are valid.
/// * `payload_bytes` – The canonically-serialised payload (e.g. bincode of the
///                     four fields of `InitEntityRegistryData` without the
///                     `approvals` field).
pub fn compute_approval_preimage(
    tx_type_byte: u8,
    domain: &ApprovalDomain,
    payload_bytes: &[u8],
) -> [u8; 32] {
    let domain_bytes = bincode::serialize(domain).unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(THRESHOLD_APPROVAL_DOMAIN_TAG);
    hasher.update(&[tx_type_byte]);
    hasher.update(&(domain_bytes.len() as u64).to_le_bytes());
    hasher.update(&domain_bytes);
    hasher.update(&(payload_bytes.len() as u64).to_le_bytes());
    hasher.update(payload_bytes);
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// ThresholdApprovalSet impl
// ---------------------------------------------------------------------------

impl ThresholdApprovalSet {
    /// Create a new empty approval set for the given domain.
    pub fn new(domain: ApprovalDomain) -> Self {
        Self {
            domain,
            approvals: Vec::new(),
        }
    }

    /// Verify all signatures in the set over `preimage`.
    ///
    /// Returns `Err(ThresholdError::DuplicateSigner)` if two approvals share the
    /// same `key_id`, or `Err(ThresholdError::InvalidSignature)` for a bad sig.
    ///
    /// On success every approval's signature has been verified over `preimage`
    /// and no duplicates were found.
    pub fn verify_all(&self, preimage: &[u8; 32]) -> Result<(), ThresholdError> {
        use lib_crypto::verification::verify_signature;

        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

        for approval in &self.approvals {
            let pk_bytes = approval.public_key.as_bytes();
            let signer_id = lib_crypto::hashing::hash_blake3(&pk_bytes);

            // Duplicate check
            if !seen.insert(signer_id) {
                return Err(ThresholdError::DuplicateSigner(signer_id));
            }

            if pk_bytes.is_empty() || approval.signature.len() == pk_bytes.len() {
                return Err(ThresholdError::InvalidSignature(signer_id));
            }

            // Cryptographic verification
            match verify_signature(preimage, &approval.signature, &pk_bytes) {
                Ok(true) => {}
                Ok(false) => return Err(ThresholdError::InvalidSignature(signer_id)),
                Err(_) => return Err(ThresholdError::InvalidSignature(signer_id)),
            }
        }

        Ok(())
    }

    /// Count how many approvers satisfy the membership predicate.
    ///
    /// `is_member` receives the raw Dilithium public-key bytes and returns
    /// `true` iff that key belongs to the authoritative signer set.
    pub fn count_valid_council_approvals(&self, is_member: impl Fn(&[u8]) -> bool) -> usize {
        self.approvals
            .iter()
            .filter(|a| is_member(&a.public_key.as_bytes()))
            .count()
    }
}

// ---------------------------------------------------------------------------
// Top-level free function
// ---------------------------------------------------------------------------

/// Validate a full threshold approval set.
///
/// Steps:
/// 1. Verify every signature over `preimage` (→ `InvalidSignature` / `DuplicateSigner`).
/// 2. Count signers that satisfy `is_member`.
/// 3. Return `ThresholdNotMet` if count < `threshold`.
///
/// `UnauthorizedSigner` is reported only when a signer whose key is valid but
/// is not in the member set is encountered; that logic is left to the caller to
/// add if needed — currently we only enforce the *count* requirement.
pub fn validate_threshold_approvals(
    set: &ThresholdApprovalSet,
    preimage: &[u8; 32],
    is_member: impl Fn(&[u8]) -> bool,
    threshold: usize,
) -> Result<(), ThresholdError> {
    // Step 1: verify all signatures and check for duplicates
    set.verify_all(preimage)?;

    // Step 2: count valid members
    let count = set.count_valid_council_approvals(is_member);

    // Step 3: enforce threshold
    if count < threshold {
        return Err(ThresholdError::ThresholdNotMet {
            have: count,
            need: threshold,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;

    fn make_domain() -> ApprovalDomain {
        ApprovalDomain::BootstrapCouncil
    }

    #[test]
    fn test_compute_approval_preimage_is_deterministic() {
        let domain = make_domain();
        let payload = b"hello world";
        let a = compute_approval_preimage(38, &domain, payload);
        let b = compute_approval_preimage(38, &domain, payload);
        assert_eq!(a, b);
    }

    #[test]
    fn test_compute_approval_preimage_differs_by_tx_type() {
        let domain = make_domain();
        let payload = b"hello world";
        let a = compute_approval_preimage(38, &domain, payload);
        let b = compute_approval_preimage(39, &domain, payload);
        assert_ne!(a, b);
    }

    #[test]
    fn test_compute_approval_preimage_differs_by_domain() {
        let payload = b"hello world";
        let a = compute_approval_preimage(38, &ApprovalDomain::BootstrapCouncil, payload);
        let b = compute_approval_preimage(38, &ApprovalDomain::OracleCommittee, payload);
        assert_ne!(a, b);
    }

    #[test]
    fn test_compute_approval_preimage_differs_by_payload() {
        let domain = make_domain();
        let a = compute_approval_preimage(38, &domain, b"payload_a");
        let b = compute_approval_preimage(38, &domain, b"payload_b");
        assert_ne!(a, b);
    }

    #[test]
    fn test_empty_approval_set_threshold_not_met() {
        let set = ThresholdApprovalSet::new(make_domain());
        let preimage = compute_approval_preimage(38, &make_domain(), b"test");
        let result = validate_threshold_approvals(&set, &preimage, |_| true, 1);
        assert_eq!(
            result,
            Err(ThresholdError::ThresholdNotMet { have: 0, need: 1 })
        );
    }

    #[test]
    fn test_threshold_zero_always_passes() {
        let set = ThresholdApprovalSet::new(make_domain());
        let preimage = compute_approval_preimage(38, &make_domain(), b"test");
        let result = validate_threshold_approvals(&set, &preimage, |_| true, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_count_valid_council_approvals_with_non_members() {
        use crate::integration::crypto_integration::{PublicKey, SignatureAlgorithm};

        let pk = PublicKey {
            dilithium_pk: [1u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: [1u8; 32],
        };
        let approval = Approval {
            public_key: pk,
            algorithm: SignatureAlgorithm::Dilithium5,
            signature: vec![0u8; 4595],
        };
        let set = ThresholdApprovalSet {
            domain: make_domain(),
            approvals: vec![approval],
        };

        // Non-member predicate → count 0
        assert_eq!(set.count_valid_council_approvals(|_| false), 0);
        // Always-member predicate → count 1
        assert_eq!(set.count_valid_council_approvals(|_| true), 1);
    }

    #[test]
    fn test_approval_domain_serde_roundtrip() {
        let domain = ApprovalDomain::DaoCouncil { dao_id: [42u8; 32] };
        let bytes = bincode::serialize(&domain).unwrap();
        let restored: ApprovalDomain = bincode::deserialize(&bytes).unwrap();
        assert_eq!(domain, restored);
    }

    #[test]
    fn test_verify_all_rejects_duplicate_public_key_with_forged_key_ids() {
        let signer = KeyPair::generate().unwrap();
        let preimage = compute_approval_preimage(38, &make_domain(), b"duplicate-test");
        let signature = signer.sign(&preimage).unwrap();
        let algorithm = signature.algorithm.clone();

        let mut forged_public_key = signer.public_key.clone();
        forged_public_key.key_id = [0xAB; 32];

        let set = ThresholdApprovalSet {
            domain: make_domain(),
            approvals: vec![
                Approval {
                    public_key: signer.public_key.clone(),
                    algorithm: algorithm.clone(),
                    signature: signature.signature.clone(),
                },
                Approval {
                    public_key: forged_public_key,
                    algorithm,
                    signature: signature.signature,
                },
            ],
        };

        assert!(matches!(
            set.verify_all(&preimage),
            Err(ThresholdError::DuplicateSigner(_))
        ));
    }

    #[test]
    fn test_verify_all_rejects_placeholder_signature_shape() {
        let signer = KeyPair::generate().unwrap();
        let preimage =
            compute_approval_preimage(39, &ApprovalDomain::OracleCommittee, b"shape-test");
        let pk_len = signer.public_key.dilithium_pk.len();
        let set = ThresholdApprovalSet {
            domain: ApprovalDomain::OracleCommittee,
            approvals: vec![Approval {
                public_key: signer.public_key,
                algorithm: SignatureAlgorithm::Dilithium5,
                signature: vec![0u8; pk_len],
            }],
        };

        assert!(matches!(
            set.verify_all(&preimage),
            Err(ThresholdError::InvalidSignature(_))
        ));
    }
}
