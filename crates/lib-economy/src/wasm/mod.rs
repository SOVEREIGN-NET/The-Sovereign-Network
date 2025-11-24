//! WebAssembly compatibility module for browser deployment
//! 
//! This module provides WASM-compatible implementations for browser environments
//! where certain dependencies or features may not be available.

pub mod hash_blake3;
pub mod identity;
pub mod logging;
pub mod compatibility;

pub use hash_blake3::*;
pub use identity::*;
pub use logging::*;
pub use compatibility::*;
