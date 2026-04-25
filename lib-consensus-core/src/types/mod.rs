//! Core consensus value types.
//!
//! Populated by CONS-201: `ConsensusStep`, `VoteType`, `ConsensusVote`,
//! `ConsensusProposal`, `ConsensusRound`, and the unified `ValidatorMessage`
//! (3 variants — `Propose`, `Vote`, `Heartbeat` — collapsing the prior
//! 3-variant `types::ValidatorMessage` and 5-variant
//! `validators::ValidatorMessage` into one canonical wire type).
