//! Circuit implementations for various ZK proof types
//! 
//! Provides specialized circuits for different proof types including
//! transaction validation, identity verification, and range proofs.

pub mod transaction_circuit;
pub mod state_transition_circuit;
pub mod identity_circuit;
pub mod range_circuit;
pub mod merkle_circuit;

// Re-export main types
pub use transaction_circuit::{TransactionCircuit, TransactionWitness, TransactionProof};
pub use state_transition_circuit::{
    StateTransitionCircuit, StateTransitionWitness, StateTransitionProof,
    StateTransitionPublicInputs, StateUpdateWitness, BlockMetadata,
};
pub use identity_circuit::{IdentityCircuit, IdentityWitness};
pub use range_circuit::{RangeCircuit};
pub use merkle_circuit::{MerkleCircuit};
