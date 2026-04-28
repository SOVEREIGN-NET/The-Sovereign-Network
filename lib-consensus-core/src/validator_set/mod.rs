//! `ValidatorManager`, validator-set snapshots (write-once per height), and
//! the 1/3-per-epoch churn cap.
//!
//! Destination for `lib-consensus/src/validators/validator_manager.rs` plus
//! the snapshot machinery currently in
//! `lib-consensus/src/engines/consensus_engine/mod.rs`
//! (`ValidatorSetSnapshot`, `snapshot_validator_set`,
//! `validator_set_for_height`).
