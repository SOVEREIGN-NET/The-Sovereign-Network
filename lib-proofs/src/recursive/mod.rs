//! Enhanced recursive proof system
//!
//! Provides advanced recursive proof aggregation and state transition circuits
//! for hierarchical mesh networks with optimized verification.

pub mod aggregated_circuit;
pub mod circuit;
pub mod state_transition;

pub use aggregated_circuit::{
    AggregatedCircuit, AggregatedCircuitBuilder, AggregatedProofMetadata, AggregationStrategy,
    CircuitAggregationRules,
};
pub use state_transition::{
    ChainValidationProof, StateTransitionChain, StateTransitionRecursiveCircuit,
    TransitionValidationRules,
};

#[cfg(feature = "real-proofs")]
pub use circuit::real::{prove_recursive_batch, verify_recursive_batch};
