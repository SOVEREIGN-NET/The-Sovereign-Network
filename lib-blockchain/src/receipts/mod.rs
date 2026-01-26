//! Transaction Receipt Module
//!
//! Provides transaction receipt management for tracking transaction status
//! through confirmation and finality stages.

pub mod types;

pub use types::{TransactionReceipt, TransactionStatus};
