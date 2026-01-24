//! Contract ABI (Application Binary Interface) System
//!
//! Provides standardized, deterministic schemas for contract methods and events,
//! enabling safe cross-contract communication, code generation, and Treasury Kernel integration.
//!
//! # Design Principle (ADR-0017)
//!
//! Contracts are **intent-recording engines**, not economic executors.
//! ABIs describe WHAT contracts record, not HOW Treasury Kernel executes them.
//!
//! # Module Structure
//!
//! - `schema.rs` - Core ABI type definitions and schema format
//! - `codec.rs` - Deterministic serialization/deserialization
//! - `validation.rs` - Schema validation and type checking
//! - `privilege.rs` - Privilege markers and authorization hooks
//! - `codegen.rs` - Generate Rust/TypeScript bindings
//! - `registry.rs` - Contract ABI registry and lookup
//!
//! # Example: UBI Contract ABI
//!
//! ```json
//! {
//!   "contract": "UBI",
//!   "version": "1.0.0",
//!   "methods": [
//!     {
//!       "name": "claim",
//!       "parameters": [
//!         { "name": "citizen_id", "type": "Bytes32" },
//!         { "name": "amount", "type": "U64" }
//!       ],
//!       "returns": "ClaimResult",
//!       "privilege": {
//!         "kernel_only": true,
//!         "governance_gated": true
//!       },
//!       "semantics": "intent"
//!     }
//!   ],
//!   "events": [
//!     {
//!       "name": "ClaimRecorded",
//!       "fields": [
//!         { "name": "citizen", "type": "Bytes32" },
//!         { "name": "amount", "type": "U64" },
//!         { "name": "epoch", "type": "U64" }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! # Features
//!
//! - **Deterministic Encoding**: Canonical JSON and binary formats for schema compatibility
//! - **Type Safety**: Full type system (primitives, structs, arrays, optionals)
//! - **Privilege Markers**: Distinguish kernel-only, governance-gated, public operations
//! - **Versioning**: Schema evolution with deprecation tracking
//! - **Code Generation**: Automatic Rust and TypeScript binding generation
//! - **Validation**: Runtime type checking and schema adherence

pub mod schema;
pub mod codec;
pub mod validation;
pub mod privilege;
pub mod registry;
pub mod codegen;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod red_tests;

pub use schema::{
    ContractAbi, MethodSchema, EventSchema, ParameterType, ReturnType, FieldType,
    Parameter, EventField, ExecutionSemantics, TypeDefinition, PrivilegeRequirement,
};
pub use codec::{AbiCodec, AbiEncoder, AbiDecoder};
pub use validation::AbiValidator;
pub use privilege::{PrivilegeMarker, PrivilegeLevel};
pub use registry::AbiRegistry;
pub use codegen::AbiCodegen;
