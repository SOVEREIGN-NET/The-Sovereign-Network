//! Codec v1 wire types — exact bincode layout before binary-epoch fields.
//!
//! Decoding v1 frames through these types and upgrading to current
//! [`ValidatorMessage`] assigns [`LEGACY_BUILD_ID`] so admission can
//! reject with an explicit reason instead of a bincode failure.

use std::collections::BTreeMap;

use lib_consensus_core::build_id::LEGACY_BUILD_ID;
use lib_consensus_core::types::{
    ConsensusProof, ConsensusProposal, ConsensusStateView, ConsensusVote, HaltMessage,
    HeartbeatMessage, Justification, NetworkSummary, ProposeMessage, ValidatorMessage,
    VoteMessage,
};
use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::IdentityId;
use lib_types::consensus::ConsensusStep;
use serde::{Deserialize, Serialize};

use super::CodecError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum ValidatorMessageV1 {
    Propose(ProposeMessageV1),
    Vote(VoteMessageV1),
    Heartbeat(HeartbeatMessageV1),
    Halt(HaltMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ProposeMessageV1 {
    pub message_id: Hash,
    pub proposer: IdentityId,
    pub proposal: ConsensusProposalV1,
    pub justification: Option<Justification>,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct VoteMessageV1 {
    pub message_id: Hash,
    pub voter: IdentityId,
    pub vote: ConsensusVote,
    pub consensus_state: ConsensusStateView,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct HeartbeatMessageV1 {
    pub message_id: Hash,
    pub validator: IdentityId,
    pub height: u64,
    pub round: u32,
    pub step: ConsensusStep,
    pub network_summary: NetworkSummary,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ConsensusProposalV1 {
    pub id: Hash,
    pub proposer: IdentityId,
    pub height: u64,
    #[serde(default)]
    pub round: u32,
    #[serde(default)]
    pub protocol_version: u32,
    pub previous_hash: Hash,
    pub block_data: Vec<u8>,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
    pub consensus_proof: ConsensusProof,
    #[serde(default)]
    pub valid_round: Option<u32>,
}

pub(super) fn decode_v1(bytes: &[u8]) -> Result<ValidatorMessage, CodecError> {
    let msg: ValidatorMessageV1 = bincode::deserialize(bytes)
        .map_err(|e| CodecError::DeserializationFailed(e.to_string()))?;
    Ok(upgrade_v1(msg))
}

fn upgrade_v1(msg: ValidatorMessageV1) -> ValidatorMessage {
    match msg {
        ValidatorMessageV1::Propose(m) => ValidatorMessage::Propose(ProposeMessage {
            message_id: m.message_id,
            proposer: m.proposer,
            proposal: ConsensusProposal {
                id: m.proposal.id,
                proposer: m.proposal.proposer,
                height: m.proposal.height,
                round: m.proposal.round,
                protocol_version: m.proposal.protocol_version,
                previous_hash: m.proposal.previous_hash,
                block_data: m.proposal.block_data,
                timestamp: m.proposal.timestamp,
                signature: m.proposal.signature,
                consensus_proof: m.proposal.consensus_proof,
                valid_round: m.proposal.valid_round,
                build_id: LEGACY_BUILD_ID.to_string(),
            },
            justification: m.justification,
            timestamp: m.timestamp,
            signature: m.signature,
        }),
        ValidatorMessageV1::Vote(m) => ValidatorMessage::Vote(VoteMessage {
            message_id: m.message_id,
            voter: m.voter,
            vote: m.vote,
            consensus_state: m.consensus_state,
            timestamp: m.timestamp,
            signature: m.signature,
            build_id: LEGACY_BUILD_ID.to_string(),
        }),
        ValidatorMessageV1::Heartbeat(m) => ValidatorMessage::Heartbeat(HeartbeatMessage {
            message_id: m.message_id,
            validator: m.validator,
            height: m.height,
            round: m.round,
            step: m.step,
            network_summary: m.network_summary,
            timestamp: m.timestamp,
            signature: m.signature,
            build_id: LEGACY_BUILD_ID.to_string(),
            build_revision: String::new(),
        }),
        ValidatorMessageV1::Halt(m) => ValidatorMessage::Halt(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_consensus_core::types::ConsensusProof;
    use lib_types::consensus::{ConsensusType, VoteType};

    fn zero_proposal_v1() -> ConsensusProposalV1 {
        ConsensusProposalV1 {
            id: Hash::default(),
            proposer: IdentityId::default(),
            height: 0,
            round: 0,
            protocol_version: 0,
            previous_hash: Hash::default(),
            block_data: vec![],
            timestamp: 0,
            signature: PostQuantumSignature::default(),
            consensus_proof: ConsensusProof::empty(ConsensusType::ByzantineFaultTolerance, 0),
            valid_round: None,
        }
    }

    #[test]
    fn v1_vote_round_trip_assigns_legacy_build_id() {
        let v1 = ValidatorMessageV1::Vote(VoteMessageV1 {
            message_id: Hash::default(),
            voter: IdentityId::default(),
            vote: ConsensusVote {
                id: Hash::default(),
                voter: IdentityId::default(),
                proposal_id: Hash::default(),
                vote_type: VoteType::PreVote,
                height: 0,
                round: 0,
                timestamp: 0,
                signature: PostQuantumSignature::default(),
            },
            consensus_state: ConsensusStateView {
                height: 0,
                round: 0,
                step: ConsensusStep::Propose,
                known_proposals: vec![],
                vote_counts: BTreeMap::new(),
            },
            timestamp: 0,
            signature: PostQuantumSignature::default(),
        });
        let bytes = bincode::serialize(&v1).expect("encode v1");
        let upgraded = decode_v1(&bytes).expect("decode v1");
        match upgraded {
            ValidatorMessage::Vote(m) => {
                assert_eq!(m.build_id, LEGACY_BUILD_ID);
            }
            other => panic!("expected vote, got {other:?}"),
        }
    }

    #[test]
    fn v1_propose_round_trip_assigns_legacy_build_id() {
        let v1 = ValidatorMessageV1::Propose(ProposeMessageV1 {
            message_id: Hash::default(),
            proposer: IdentityId::default(),
            proposal: zero_proposal_v1(),
            justification: None,
            timestamp: 0,
            signature: PostQuantumSignature::default(),
        });
        let bytes = bincode::serialize(&v1).expect("encode v1");
        let upgraded = decode_v1(&bytes).expect("decode v1");
        match upgraded {
            ValidatorMessage::Propose(m) => {
                assert_eq!(m.proposal.build_id, LEGACY_BUILD_ID);
            }
            other => panic!("expected propose, got {other:?}"),
        }
    }
}