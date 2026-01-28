//! Cross-contract call infrastructure
//!
//! Enables contracts to safely call other contracts with type-safe parameters
//! and return values. All calls record INTENT per ADR-0017; execution is deferred
//! to Treasury Kernel.
//!
//! # Design Principles
//!
//! 1. **Explicit Syntax**: `call <contract_id>::<method>(args...)`
//!    - No dynamic dispatch
//!    - Deterministic ABI resolution
//!    - Easy static analysis
//!
//! 2. **Intent Recording**: Events are authoritative, state is cache
//!    - CrossContractCallIntent events recorded for consensus
//!    - State entries optional for replay/debugging
//!
//! 3. **Strict Recursion Limit**: Max depth = 16
//!    - Enforced at executor level
//!    - Included in recorded intent for replay validation
//!
//! 4. **Wrapped Errors**: No error pass-through
//!    - All errors wrapped in CrossContractError
//!    - Prevents ABI leakage between contracts
//!    - Only error category exposed, not details
//!
//! 5. **Strict State Isolation**: Callee cannot mutate caller state
//!    - Enforced at executor level
//!    - Preserves determinism and auditability
//!
//! # Example
//!
//! ```text
//! call 0xABC123::transfer(recipient, amount)
//! call 0xDEF456::vote(proposal_id, vote_direction)
//! ```

pub mod call;
pub mod cycle_detector;
pub mod errors;
pub mod executor;
pub mod serialization_validator;
pub mod stack;
pub mod type_validator;
pub mod validator;

pub use call::CrossContractCall;
pub use cycle_detector::{CallCycle, CallChainAnalysis, CallEdge, CycleDetector};
pub use errors::{CalleeErrorCode, CrossContractError, ContractId};
pub use executor::{CallExecutor, CrossContractCallIntent, CrossContractCallResult};
pub use serialization_validator::{SerializationFormat, SerializationValidator};
pub use stack::{CallStack, MAX_RECURSION_DEPTH};
pub use type_validator::{TypeSpec, TypeValidator};
pub use validator::{CallValidator, MethodSignature, ValidationResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_loads() {
        // Verify module can be imported
        let _code = CalleeErrorCode::ValidationFailed;
    }
}
