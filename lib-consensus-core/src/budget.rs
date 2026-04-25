//! Consensus-affecting constants — single source of truth.
//!
//! Per AD-011 (`docs/epics/consensus-rewrite-decisions.md`), every constant
//! that materially affects BFT safety or liveness lives here. The runtime
//! asserts at startup that the wired transport's idle timer is compatible
//! (`TransportInfo::idle_timeout()`).
//!
//! Populated by CONS-310. This file is intentionally empty until that issue
//! lands; the constants are listed in the issue body and architecture doc § 6.3.
