//! Vote pool with composite-key equivocation detection.
//!
//! Destination for `VotePoolKey` (currently in
//! `lib-consensus/src/engines/consensus_engine/state_machine.rs:379-384`)
//! and the `vote_pool: HashMap<VotePoolKey, (ConsensusVote, Hash)>` field.
//! Composite key = `(height, round, vote_type, validator_id)`; one vote per
//! key prevents equivocation by construction.
