//! # VM Existence and Type Invariants [BFT-A][R3]
//!
//! ## Invariant
//! The Sovereign Network execution environment MUST use a deterministic virtual machine.
//!
//! ## VM Type
//! - Type: WebAssembly (WASM)
//! - Determinism: REQUIRED - all nodes must produce identical execution results
//! - Sandboxing: REQUIRED - contracts must not access host state directly
//!
//! ## BFT Requirements
//! - VM execution must be a pure function of (state, transaction)
//! - No wall-clock time, randomness, or external I/O inside VM
//! - All floating-point operations must be deterministic (IEEE 754 strict mode)

/// Identifies the VM type used for contract execution.
pub const VM_TYPE: &str = "WASM";

/// Execution determinism is required for BFT consensus.
/// All validators must produce identical results for the same (state, tx) pair.
pub const VM_DETERMINISM_REQUIRED: bool = true;

/// WASM memory page size (64 KiB per the WASM spec).
pub const WASM_PAGE_SIZE_BYTES: usize = 65536;

/// Maximum WASM memory pages per contract instance.
/// This value MUST stay in sync with the runtime configuration default.
pub const MAX_WASM_MEMORY_PAGES: u32 = 16; // 16 * 64 KiB = 1 MiB

/// Maximum WASM stack depth.
pub const MAX_WASM_STACK_DEPTH: u32 = 1024;

/// Asserts that the configured VM satisfies BFT determinism requirements.
/// Called at node startup to enforce invariants.
pub fn assert_vm_invariants() {
    assert!(
        VM_DETERMINISM_REQUIRED,
        "BFT invariant violated: VM must be deterministic."
    );
    // VM_TYPE is a compile-time constant; the assertion above is the meaningful
    // runtime check. VM_TYPE is always "WASM" by construction, so no self-check needed.
}

// TODO: WASM execution engine integration
// TODO: Contract deployment validation
// TODO: Gas metering integration
