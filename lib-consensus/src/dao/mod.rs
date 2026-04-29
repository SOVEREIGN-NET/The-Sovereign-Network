//! Back-compat shim: DAO module relocated to `lib_governance::dao` per
//! CONS-106 / AD-003. This module re-exports the new home so existing
//! `lib_consensus::dao::*` and `lib_consensus::Dao*` paths keep working
//! during the rewrite. Will be deleted in CONS-508 along with the rest of
//! lib-consensus.

pub use lib_governance::dao::*;
pub use lib_governance::dao::dao_engine;
pub use lib_governance::dao::dao_types;
