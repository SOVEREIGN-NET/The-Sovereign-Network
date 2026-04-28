//! Pure slash math — no policy.
//!
//! Destination for the math half of `lib-consensus/src/slashing/mod.rs`
//! (e.g. `calculate_slash_amount`, `safety_ban_status`,
//! `liveness_jail_status`, `JAIL_DURATION_BLOCKS`,
//! `DOUBLE_SIGN_SLASH_PERCENT`). The *policy* half (jail-end orchestration,
//! economic side effects) belongs in `lib-economy` per AD-003.
