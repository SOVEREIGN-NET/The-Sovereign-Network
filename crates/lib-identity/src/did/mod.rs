// packages/lib-identity/src/did/mod.rs
// Decentralized Identity Document (DID) module exports

pub mod document_generation;

// Re-export all DID types and functions
pub use document_generation::*;
