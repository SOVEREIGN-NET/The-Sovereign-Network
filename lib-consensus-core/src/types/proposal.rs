//! Wire types for proposals, votes, and consensus proofs.
//!
//! Migrated from `lib-consensus/src/types/mod.rs` per CONS-201 Scope B.
//! These types previously lived in `lib-consensus` because their proof
//! fields referenced `lib_storage::proofs::StorageCapacityAttestation`
//! and `lib_proofs::consensus::{StakeProof, WorkProof}`, both of which
//! `lib-consensus-core` is forbidden from depending on per AD-002.
//!
//! ## Resolution
//!
//! The proof fields in [`ConsensusProof`] are **opaque bytes** —
//! `Option<Vec<u8>>` carrying a bincode-serialized payload. The proof
//! shape is defined entirely outside core: `lib-blockchain` /
//! `lib-proofs` / `lib-storage` produce + verify them; consensus only
//! ships them on the wire and gates round-progress on the verifier
//! callback (CONS-103 / AD-005). The encode/decode helpers live in
//! `lib-consensus`'s [`ConsensusProofExt`] trait so consumers that DO
//! depend on those crates can still call `proof.with_stake_proof(p)`
//! / `proof.decode_stake_proof()` ergonomically.
//!
//! `lib-consensus` re-exports these types from `lib_consensus_core::
//! types` so existing import paths (`lib_consensus::ConsensusProposal`,
//! `crate::types::ConsensusVote`, etc.) keep working.

use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::IdentityId;
use lib_types::consensus::{ConsensusType, VoteType};
use serde::{Deserialize, Serialize};

/// Consensus vote on a proposal — Sovereign Network BFT vote.
///
/// Mirror of the pre-CONS-201 `lib_consensus::types::ConsensusVote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVote {
    /// Vote identifier.
    pub id: Hash,
    /// Voter validator.
    pub voter: IdentityId,
    /// Proposal being voted on.
    pub proposal_id: Hash,
    /// Vote type (PreVote / PreCommit / Commit).
    pub vote_type: VoteType,
    /// Block height.
    pub height: u64,
    /// Voting round.
    pub round: u32,
    /// Timestamp (deterministic logical clock; do not trust as wall time).
    pub timestamp: u64,
    /// Voter signature over the canonical vote payload.
    pub signature: PostQuantumSignature,
}

/// Combined consensus proof shipped with a proposal.
///
/// Each proof field is **opaque bytes** — bincode-serialized at the
/// production site, deserialized at the verifier site. See module docs
/// for the AD-002 motivation. Use [`ConsensusProofExt`] (from
/// `lib-consensus`) for ergonomic encode/decode.
///
/// [`ConsensusProofExt`]: https://docs/lib_consensus/types/trait.ConsensusProofExt.html
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProof {
    /// Consensus mechanism this proof targets.
    pub consensus_type: ConsensusType,
    /// Stake-proof bytes (bincode-serialized `lib_proofs::consensus::
    /// StakeProof`). `None` when the chosen consensus type does not
    /// produce one.
    pub stake_proof: Option<Vec<u8>>,
    /// Storage-capacity-attestation bytes (bincode-serialized
    /// `lib_storage::proofs::StorageCapacityAttestation`).
    pub storage_proof: Option<Vec<u8>>,
    /// Useful-work proof bytes (bincode-serialized
    /// `lib_proofs::consensus::WorkProof`).
    pub work_proof: Option<Vec<u8>>,
    /// ZK-DID proof bytes (already opaque pre-CONS-201).
    pub zk_did_proof: Option<Vec<u8>>,
    /// Deterministic timestamp (height-based, not wall-clock).
    pub timestamp: u64,
}

impl ConsensusProof {
    /// Construct an empty proof carrying just the consensus type +
    /// timestamp. Builders + decoders for the proof fields live on
    /// the `ConsensusProofExt` trait in `lib-consensus`.
    pub fn empty(consensus_type: ConsensusType, timestamp: u64) -> Self {
        Self {
            consensus_type,
            stake_proof: None,
            storage_proof: None,
            work_proof: None,
            zk_did_proof: None,
            timestamp,
        }
    }
}

/// Block proposal broadcast by a designated proposer in a given round.
///
/// Mirror of the pre-CONS-201 `lib_consensus::types::ConsensusProposal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposal {
    /// Proposal identifier.
    pub id: Hash,
    /// Proposer validator.
    pub proposer: IdentityId,
    /// Block height.
    pub height: u64,
    /// Consensus round this proposal is for.
    #[serde(default)]
    pub round: u32,
    /// Consensus wire-protocol version. Nodes reject proposals whose
    /// version doesn't match their own `CONSENSUS_PROTOCOL_VERSION`,
    /// producing a clear error instead of silently stalling on
    /// signature mismatches after an envelope change. Defaults to 0
    /// for proposals from pre-versioning nodes.
    #[serde(default)]
    pub protocol_version: u32,
    /// Previous block hash.
    pub previous_hash: Hash,
    /// Proposed block payload bytes.
    pub block_data: Vec<u8>,
    /// Deterministic timestamp.
    pub timestamp: u64,
    /// Proposer signature over the canonical proposal payload.
    pub signature: PostQuantumSignature,
    /// Combined proof bundle for this proposal.
    pub consensus_proof: ConsensusProof,
    /// Tendermint `validRound`: when the proposer is re-proposing a
    /// block it observed reach a prevote quorum in an earlier round,
    /// this carries that round. `None` for a freshly built block.
    /// Receivers use it in the prevote lock rule — a locked validator
    /// may prevote a conflicting block only when `valid_round >=
    /// locked_round`. Appended at struct end (never mid-struct) so
    /// bincode stays compatible; `#[serde(default)]` decodes pre-field
    /// proposals as `None`.
    #[serde(default)]
    pub valid_round: Option<u32>,
    /// Human-bumped binary epoch. Peers reject proposals whose epoch
    /// does not match [`CONSENSUS_BUILD_ID`](crate::build_id::CONSENSUS_BUILD_ID).
    /// Not part of the inner proposal signature — admission-time safety
    /// net only, not a cryptographic identity binding.
    #[serde(default)]
    pub build_id: String,
}
