//! WASM-compatible logging that compiles to no-op in browser environments
//! 
//! Provides logging macros that work across platforms.

/// Info logging macro for WASM compatibility
#[cfg(not(target_arch = "wasm32"))]
pub use tracing::info;

/// WASM-compatible info macro that compiles to no-op
#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        // No-op in WASM to avoid console dependencies
    };
}

#[cfg(target_arch = "wasm32")]
pub use info;
