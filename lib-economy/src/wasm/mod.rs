//! WebAssembly compatibility module for browser deployment
//!
//! This module provides WASM-compatible implementations for browser environments
//! where certain dependencies or features may not be available.

pub mod compatibility;
pub mod hash_blake3;
pub mod identity;
pub mod logging;

pub use compatibility::*;
pub use hash_blake3::*;
pub use identity::*;
pub use logging::*;
