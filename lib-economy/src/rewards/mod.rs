//! Reward calculation system for economics
//! 
//! This module provides reward calculation capabilities for the economics package
//! without depending on lib-consensus to avoid circular dependencies

pub mod calculator;
pub mod types;

pub use calculator::*;
pub use types::*;
