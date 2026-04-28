//! Observer admission domain logic.
//!
//! Pure data types live in `lib-types`; this module provides the
//! deterministic policy and authorization layer that the executor and
//! downstream bootstrap/sync code consult.
//!
//! Layered scope (per the observer-admission epic):
//! - admission-2: canonical types (in `lib-types`).
//! - admission-3: registry state, lifecycle txs (in `execution::executor`).
//! - admission-4: **policy + authorization decisions** (this module).
//! - admission-5+: bootstrap, API, anti-abuse all consume this module.

pub mod policy;

pub use policy::{
    default_policy, evaluate_admission, AdmissionDecision, PolicyDenial,
};
