//! Consensus integration tests — DAO proposal and vote lifecycle

use lib_blockchain::types::Hash;
use lib_blockchain::Blockchain;

/// A DAO proposal transaction can be created and retrieved from the chain.
#[test]
fn test_dao_proposal_creation() {
    let mut bc = Blockchain::new().expect("genesis");

    let proposal_id = Hash::new([0x01u8; 32]);
    bc.push_test_dao_proposal(proposal_id, 51);

    let proposals = bc.get_dao_proposals();
    assert_eq!(proposals.len(), 1, "expected one proposal");
    assert_eq!(
        proposals[0].proposal_id, proposal_id,
        "proposal ID round-trips correctly"
    );
    assert_eq!(proposals[0].proposer, "did:zhtp:test");
    assert_eq!(proposals[0].quorum_required, 51);
}

/// A DAO vote transaction can be created and retrieved for a given proposal.
#[test]
fn test_dao_vote_creation() {
    let mut bc = Blockchain::new().expect("genesis");

    let proposal_id = Hash::new([0x02u8; 32]);
    bc.push_test_dao_proposal(proposal_id, 51);
    bc.push_test_dao_vote(proposal_id, "did:zhtp:voter1", "yes");

    let votes = bc.get_dao_votes_for_proposal(&proposal_id);
    assert_eq!(votes.len(), 1, "expected one vote");
    assert_eq!(votes[0].voter, "did:zhtp:voter1");
    assert_eq!(votes[0].vote_choice, "yes");
    assert_eq!(votes[0].proposal_id, proposal_id);
}
