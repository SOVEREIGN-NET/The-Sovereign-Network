//! Byzantine fault tolerance and detection with evidence production

pub mod bft_types;
pub mod evidence;
pub mod fault_detector;
pub mod lru_cache;

pub use bft_types::*;
pub use evidence::{
    ByzantineEvidence, ConflictingVote, EquivocationEvidence, FirstVoteRecord,
    ForensicMessageType, ForensicRecord, PartitionSuspectedEvidence, ReplayEvidence,
    ReplayKey, ReplayMetadata, VoteTrackingKey,
};
pub use fault_detector::{
    ByzantineFaultDetector, ByzantineFault, ByzantineFaultType, FaultSeverity,
    DoubleSignEvent, LivenessViolation, InvalidProposalEvent, FaultDetectorConfig,
};
pub use lru_cache::BoundedLruCache;
