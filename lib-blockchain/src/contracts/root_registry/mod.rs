//! Root registry module for domain authority graph enforcement.

pub mod types;
pub mod core;
pub mod namespace_policy;
pub mod delegation_tree;

pub use core::RootRegistry;
pub use types::*;

#[cfg(test)]
mod tests;
