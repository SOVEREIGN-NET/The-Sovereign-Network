//! Sprint 2 block header commitment coverage.
//!
//! These tests replace the old PoW-field serialization assertions now that the
//! PoW-era header fields have been removed entirely.

use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::types::Hash;
use lib_types::consensus::{compute_bft_quorum_root, BftQuorumProof, CommitAttestation};

fn make_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        previous_hash: [0x11; 32],
        data_helix_root: [0x22; 32],
        timestamp: 1_700_000_000,
        height: 7,
        verification_helix_root: [0x33; 32],
        state_root: [0x44; 32],
        bft_quorum_root: [0x55; 32],
        block_hash: Hash::default(),
    }
}

#[test]
fn test_new_header_fields_survive_bincode_round_trip() {
    let original = Block::new(make_header(), vec![]);
    let bytes = bincode::serialize(&original).expect("serialization should succeed");
    let restored: Block = bincode::deserialize(&bytes).expect("deserialization should succeed");

    assert_eq!(restored.header.version, original.header.version);
    assert_eq!(restored.header.previous_hash, original.header.previous_hash);
    assert_eq!(restored.header.data_helix_root, original.header.data_helix_root);
    assert_eq!(
        restored.header.verification_helix_root,
        original.header.verification_helix_root
    );
    assert_eq!(restored.header.state_root, original.header.state_root);
    assert_eq!(restored.header.bft_quorum_root, original.header.bft_quorum_root);
    assert_eq!(restored.header.timestamp, original.header.timestamp);
    assert_eq!(restored.header.height, original.header.height);
}

#[test]
fn test_block_hash_changes_when_quorum_root_changes() {
    let mut header_a = make_header();
    let mut header_b = make_header();
    header_b.bft_quorum_root = [0x99; 32];

    let hash_a = header_a.calculate_hash();
    let hash_b = header_b.calculate_hash();

    assert_ne!(hash_a, hash_b);

    header_a.block_hash = hash_a;
    header_b.block_hash = hash_b;
    assert_ne!(header_a.block_hash, header_b.block_hash);
}

#[test]
fn test_compute_bft_quorum_root_commits_to_proposal_id() {
    let mut proof_a = BftQuorumProof {
        height: 42,
        proposal_id: [0xAA; 32],
        attestations: vec![
            CommitAttestation {
                validator_id: [0x01; 32],
                vote_id: [0x10; 32],
                proposal_id: [0xAA; 32],
                round: 3,
                signature: [0x10; 4595],
                public_key: [0x30; 2592],
            },
            CommitAttestation {
                validator_id: [0x02; 32],
                vote_id: [0x11; 32],
                proposal_id: [0xAA; 32],
                round: 3,
                signature: [0x20; 4595],
                public_key: [0x40; 2592],
            },
        ],
        total_validators: 2,
    };
    let mut proof_b = proof_a.clone();
    proof_b.proposal_id = [0xBB; 32];
    for att in &mut proof_b.attestations {
        att.proposal_id = [0xBB; 32];
    }

    assert_ne!(
        compute_bft_quorum_root(&proof_a),
        compute_bft_quorum_root(&proof_b)
    );

    proof_a.attestations[0].proposal_id = [0xCC; 32];
    assert_ne!(
        compute_bft_quorum_root(&proof_a),
        compute_bft_quorum_root(&proof_b)
    );
}
