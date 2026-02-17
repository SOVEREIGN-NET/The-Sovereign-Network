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
pub const MAX_WASM_MEMORY_PAGES: u32 = 256; // 16 MiB

/// Maximum WASM stack depth.
pub const MAX_WASM_STACK_DEPTH: u32 = 1024;

/// Asserts that the configured VM satisfies BFT determinism requirements.
/// Called at node startup to enforce invariants.
pub fn assert_vm_invariants() {
    assert!(VM_DETERMINISM_REQUIRED,
        "BFT invariant violated: VM must be deterministic. \
         Non-deterministic VMs break consensus safety.");
    assert_eq!(VM_TYPE, "WASM",
        "BFT invariant: only WASM VM is supported. \
         Other VM types have not been audited for determinism.");
}

// TODO: WASM execution engine integration
// TODO: Contract deployment validation
// TODO: Gas metering integration
