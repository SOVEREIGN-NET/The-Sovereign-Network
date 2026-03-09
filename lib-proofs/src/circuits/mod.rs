//! Circuit implementations for various ZK proof types
//!
//! Provides specialized circuits for different proof types including
//! transaction validation, identity verification, and range proofs.

pub mod identity_circuit;
pub mod merkle_circuit;
pub mod range_circuit;
pub mod state_transition_circuit;
pub mod transaction_circuit;

// Re-export main types
pub use identity_circuit::{IdentityCircuit, IdentityWitness};
pub use merkle_circuit::MerkleCircuit;
pub use range_circuit::RangeCircuit;
pub use state_transition_circuit::{
    BlockMetadata, StateTransitionCircuit, StateTransitionProof, StateTransitionPublicInputs,
    StateTransitionWitness, StateUpdateWitness,
};
pub use transaction_circuit::{TransactionCircuit, TransactionProof, TransactionWitness};
