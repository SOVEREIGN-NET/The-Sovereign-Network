use super::*;

impl ConsensusEngine {
    /// Count votes for a proposal
    pub(super) fn count_votes_for_proposal(&self, proposal_id: &Hash, vote_type: &VoteType) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (vote, _))| {
                k.height == self.current_round.height
                    && k.round == self.current_round.round
                    && k.vote_type == *vote_type
                    && &vote.proposal_id == proposal_id
            })
            .count() as u64
    }

    /// Count prevotes for a specific proposal in a round.
    /// **CE-S1**: Quorum checks must be proposal-scoped to prevent split votes.
    pub(super) fn count_prevotes_for(&self, height: u64, round: u32, proposal_id: &Hash) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (_, voted_proposal_id))| {
                k.height == height
                    && k.round == round
                    && k.vote_type == VoteType::PreVote
                    && voted_proposal_id == proposal_id
            })
            .count() as u64
    }

    /// Count precommits for a specific proposal in a round.
    /// **CE-S1**: Quorum checks must be proposal-scoped to prevent split votes.
    pub(super) fn count_precommits_for(&self, height: u64, round: u32, proposal_id: &Hash) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (_, voted_proposal_id))| {
                k.height == height
                    && k.round == round
                    && k.vote_type == VoteType::PreCommit
                    && voted_proposal_id == proposal_id
            })
            .count() as u64
    }

    /// Count commit votes for a specific proposal at a given height, across ALL rounds.
    ///
    /// **CE-L1, CE-L2**: Commits trigger finalization regardless of local step.
    ///
    /// Round is intentionally ignored: validators may enter the Commit step in different
    /// rounds (due to timing skew) and each casts a commit vote stamped with their current
    /// round. BFT safety still holds because if proposal A got 2/3+ precommits in ANY round,
    /// no other proposal B can get 2/3+ precommits at the same height (the lock mechanism
    /// prevents it). So aggregating commit votes across rounds for the same proposal_id is safe.
    pub(super) fn count_commits_for(&self, height: u64, _round: u32, proposal_id: &Hash) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (_, voted_proposal_id))| {
                k.height == height
                    && k.vote_type == VoteType::Commit
                    && voted_proposal_id == proposal_id
            })
            .count() as u64
    }
}
