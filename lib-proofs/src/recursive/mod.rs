//! Enhanced recursive proof system
//!
//! Provides advanced recursive proof aggregation and state transition circuits
//! for hierarchical mesh networks with optimized verification.

pub mod aggregated_circuit;
pub mod state_transition;

pub use aggregated_circuit::{
    AggregatedCircuit, AggregatedCircuitBuilder, AggregatedProofMetadata, AggregationStrategy,
    CircuitAggregationRules,
};
pub use state_transition::{
    ChainValidationProof, StateTransitionChain, StateTransitionRecursiveCircuit,
    TransitionValidationRules,
};
