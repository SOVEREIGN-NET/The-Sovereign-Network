//! ZHTP UTXO types.
//!
//! This crate is a thin re-export of the canonical consensus UTXO types from
//! [`lib_types::primitives`]. It exists to preserve the `lib_utxo::*` import
//! path for downstream consumers. All type definitions, serialization, and
//! impls live in `lib-types`.
//!
//! # Rationale
//!
//! Prior to unification, both `lib-utxo` and `lib-blockchain::storage` defined
//! their own `Utxo` / `OutPoint` structs with divergent fields. The
//! production, on-disk struct is the authoritative shape; the standalone
//! `lib-utxo` version was an orphan spike. To remove drift, the canonical
//! types now live in `lib-types::primitives` and every crate re-exports from
//! there.

pub use lib_types::primitives::{OutPoint, Utxo, UtxoMerkleProof};
