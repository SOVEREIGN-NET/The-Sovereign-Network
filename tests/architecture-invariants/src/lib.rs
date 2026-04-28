//! Architecture-invariants ratchets (CONS-603).
//!
//! Tests in this crate are grep-based regression guards: they pin
//! workspace-level patterns that the consensus rewrite established as
//! invariants. Failing one of these tests means a recent change
//! reintroduced something the architecture says shouldn't exist (an
//! inline `.await` on a side-effect from the FSM, an old `lib-network`
//! broadcaster trait re-export, etc.).
//!
//! Tests live under `tests/architecture-invariants/tests/` and are run
//! as part of `cargo test --workspace`. Each one shells out to `grep`
//! against the source tree; a non-empty match list is a failure.
//!
//! ## Adding new ratchets
//!
//! When the architecture pins a new invariant, add a `#[test]` to
//! `tests/invariants.rs` (or a new `tests/<theme>.rs` file). Use
//! `grep_workspace(pattern, paths)` from [`crate::grep`] for
//! consistency with the existing checks.

pub mod grep;
