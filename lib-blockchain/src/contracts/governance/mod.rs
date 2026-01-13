//! Governance Contracts Module
//!
//! This module contains all governance-related contracts for the SOV economic system:
//!
//! - `entity_registry`: DOC 01 - Phase 0 Primitives & Fiduciary Mapping
//! - `dao`: DOC 02 - Governance & Treasury Rails (TODO)
//! - `sunset`: DOC 03 - CBE Sunset Contract (TODO)
//! - `voting`: DOC 05 - Voting Primitives (TODO)
//! - `compensation_attestor`: DOC 06 - Compensation Fairness (TODO)

pub mod entity_registry;

// Re-export key types
pub use entity_registry::{EntityRegistry, EntityType, Role, EntityRegistryError};
