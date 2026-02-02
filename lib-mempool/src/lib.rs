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
//! # Checks Performed
//!
//! 1. **Fee check**: `fee >= minimum_fee` from fee model
//! 2. **Witness caps**: Signature/proof sizes within TxKind limits
//! 3. **Signature limits**: Maximum signatures per transaction
//! 4. **Bounded totals**: Mempool size and per-address limits
//!
//! # Usage
//!
//! ```ignore
//! use lib_mempool::{admit, MempoolConfig};
//! use lib_fees::FeeModelV2;
//!
//! let result = admit(&tx, &fee_model, &config, &mempool_state);
//! match result {
//!     AdmitResult::Accepted => { /* add to mempool */ }
//!     AdmitResult::Rejected(reason) => { /* reject */ }
//! }
//! ```

pub mod admission;
pub mod config;
pub mod state;
pub mod errors;

pub use admission::{admit, AdmitResult};
pub use config::MempoolConfig;
pub use state::MempoolState;
pub use errors::{AdmitError, AdmitErrorKind};
