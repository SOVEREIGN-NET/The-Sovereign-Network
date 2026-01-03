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

    #[allow(dead_code)]
    pub(super) fn vote_pool_contains_vote(&self, vote: &ConsensusVote) -> bool {
        let key = VotePoolKey {
            height: vote.height,
            round: vote.round,
            vote_type: vote.vote_type,
            validator_id: vote.voter.clone(),
        };
        self.vote_pool.contains_key(&key)
    }

    #[allow(dead_code)]
    pub(super) fn count_prevotes_for_round(&self, height: u64, round: u32) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, _)| k.height == height && k.round == round && k.vote_type == VoteType::PreVote)
            .count() as u64
    }

    #[allow(dead_code)]
    pub(super) fn count_precommits_for_round(&self, height: u64, round: u32) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, _)| k.height == height && k.round == round && k.vote_type == VoteType::PreCommit)
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

    /// Count commit votes for a specific proposal in a round.
    /// **CE-L1, CE-L2**: Commits trigger finalization regardless of local step.
    pub(super) fn count_commits_for(&self, height: u64, round: u32, proposal_id: &Hash) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (_, voted_proposal_id))| {
                k.height == height
                    && k.round == round
                    && k.vote_type == VoteType::Commit
                    && voted_proposal_id == proposal_id
            })
            .count() as u64
    }
}
