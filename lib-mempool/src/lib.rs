//! ZHTP Mempool Admission
//!
//! Pre-consensus transaction validation for mempool admission.
//!
//! # Purpose
//!
//! The mempool acts as a holding area for unconfirmed transactions.
//! Admission checks filter out invalid transactions before they
//! consume consensus resources.
//!
//! # Architecture
//!
//! Pure data types are defined in `lib-types::mempool`:
//! - `MempoolConfig` - Configuration for admission limits
//! - `MempoolState` - Current mempool usage state
//! - `SenderState` - Per-sender state tracking
//! - `AdmitResult` - Admission check result
//! - `AdmitErrorKind` - Specific rejection reasons
//! - `AdmitTx` - Transaction data for admission
//!
//! Behavior is provided by this crate:
//! - `admit()` - Main admission check function
//! - `MempoolStateExt` - State management methods
//! - `AdmitResultExt` - Result convenience methods
//! - `AdmitError` - Error constructors
//!
//! # Usage
//!
//! ```ignore
//! use lib_mempool::{admit, MempoolConfig, MempoolState, MempoolStateExt, AdmitResult};
//! use lib_fees::FeeParams;
//!
//! let current_block = 100;
//! let result = admit(&tx, &fee_params, &config, &mempool_state, current_block);
//! match result {
//!     AdmitResult::Accepted => { /* add to mempool */ }
//!     AdmitResult::Rejected(reason) => { /* reject */ }
//! }
//! ```

pub mod admission;
pub mod config;
pub mod state;
pub mod errors;

// Re-export pure data types from lib-types (canonical location)
pub use lib_types::mempool::{
    AdmitResult,
    AdmitErrorKind,
    AdmitTx,
    MempoolConfig,
    MempoolState,
    SenderState,
};

// Re-export behavior from this crate
pub use admission::{admit, AdmitResultExt};
pub use config::MempoolConfigExt;
pub use state::MempoolStateExt;
pub use errors::AdmitError;
