//! Architecture-invariant ratchets (CONS-603).
//!
//! Each test asserts that a specific code pattern that the consensus
//! rewrite eliminated stays gone. A failure here means a recent
//! change reintroduced the forbidden shape — the test message names
//! the AD / CONS issue that established the invariant.

use architecture_invariants::grep::{
    drop_comment_only_matches, drop_lines_containing, grep_workspace,
};

/// AD-006 / CONS-306: `lib-consensus-core/src/fsm/` contains a pure
/// FSM. No `.await` on side-effect ports (broadcaster, finalization)
/// may appear there — those go through action channels, not inline.
#[test]
fn no_inline_await_on_side_effects_in_fsm() {
    let matches = grep_workspace(
        r"(broadcaster|finalize|broadcast_to_validators|commit_finalized)\..*\.await",
        &["lib-consensus-core/src/fsm/"],
    );
    let matches = drop_comment_only_matches(matches);
    assert!(
        matches.is_empty(),
        "FSM must have no inline `.await` on side-effect ports (AD-006). \
         Found:\n  {}\nMove the side effect through the runtime's action \
         executor (CONS-306 / CONS-307) instead.",
        matches.join("\n  ")
    );
}

/// CONS-202 / CONS-401 / CONS-507: `lib-network` no longer hosts a
/// `MessageBroadcaster` trait or `MeshMessageBroadcaster` impl — the
/// canonical trait lives at `lib_consensus_core::ports::broadcaster`.
/// A regression that re-introduced either name would mean a parallel
/// trait shape resurfaced.
#[test]
fn no_broadcaster_trait_in_lib_network() {
    let matches = grep_workspace(
        r"\b(trait\s+MessageBroadcaster|MeshMessageBroadcaster|MockMessageBroadcaster)\b",
        &["lib-network/src/"],
    );
    let matches = drop_comment_only_matches(matches);
    assert!(
        matches.is_empty(),
        "lib-network must not host a MessageBroadcaster trait or impl \
         (CONS-202 / CONS-507). Found:\n  {}",
        matches.join("\n  ")
    );
}

/// CONS-401: there is exactly one `MessageBroadcaster` trait
/// definition workspace-wide, in `lib-consensus-core/src/ports/
/// broadcaster.rs`. A second `trait MessageBroadcaster` anywhere
/// means a parallel trait was reintroduced — exactly what
/// CONS-202 + CONS-401 collapsed.
#[test]
fn single_message_broadcaster_trait_definition() {
    let matches = grep_workspace(r"^\s*pub\s+trait\s+MessageBroadcaster\b", &[]);
    let canonical = "lib-consensus-core/src/ports/broadcaster.rs";
    let extras: Vec<_> = matches
        .iter()
        // grep -rn prefixes with `./` when called with `.`; strip
        // before comparing against the canonical path.
        .filter(|line| {
            let stripped = line.strip_prefix("./").unwrap_or(line);
            !stripped.starts_with(canonical)
        })
        .cloned()
        .collect();
    assert!(
        extras.is_empty(),
        "Multiple MessageBroadcaster trait definitions (CONS-401 says \
         exactly one, in {}). Extras:\n  {}",
        canonical,
        extras.join("\n  ")
    );
    assert!(
        matches
            .iter()
            .any(|l| l.strip_prefix("./").unwrap_or(l).starts_with(canonical)),
        "Canonical MessageBroadcaster trait at {} not found — search \
         pattern or canonical path drifted.",
        canonical
    );
}

/// AD-002 / CONS-310: `lib-network` must not import consensus-affecting
/// constants directly. `WRONG_CHAIN_HALT_THRESHOLD`,
/// `MAX_BROADCAST_BUDGET_MS`, `WATCHDOG_THRESHOLD_MULTIPLIER`, and
/// `COMMIT_FAILURE_HALT_THRESHOLD` are owned by
/// `lib_consensus_core::budget`. Their numeric values must not be
/// hard-coded at the network layer either — that creates two-source-of-
/// truth drift.
#[test]
fn no_consensus_constants_in_lib_network() {
    let matches = grep_workspace(
        r"\b(WRONG_CHAIN_HALT_THRESHOLD|MAX_BROADCAST_BUDGET_MS|WATCHDOG_THRESHOLD_MULTIPLIER|COMMIT_FAILURE_HALT_THRESHOLD)\b",
        &["lib-network/src/"],
    );
    // Tolerate doc comments that mention the constant by name — they
    // don't import or duplicate it.
    let matches = drop_comment_only_matches(matches);
    assert!(
        matches.is_empty(),
        "lib-network has direct references to consensus-budget \
         constants (CONS-310 / AD-011). Found:\n  {}\nImport from \
         `lib_consensus_core::budget` if the value is genuinely needed.",
        matches.join("\n  ")
    );
}

/// CONS-501a: the canonical path for validator-discovery types is
/// `lib_consensus_net::discovery`. Deep imports under
/// `lib_consensus::validators::validator_discovery::` from external
/// crates are forbidden (the path still works inside lib-consensus
/// via re-export, but external use should hit the new canonical
/// location).
#[test]
fn no_external_deep_imports_of_validator_discovery() {
    let matches = grep_workspace(
        r"lib_consensus::validators::validator_discovery::",
        &[
            "lib-network/src/",
            "lib-blockchain/src/",
            "lib-consensus-core/src/",
            "lib-consensus-net/src/",
            "lib-consensus-runtime/src/",
            "zhtp/src/",
            "zhtp-cli/src/",
            "zhtp-daemon/src/",
        ],
    );
    let matches = drop_comment_only_matches(matches);
    assert!(
        matches.is_empty(),
        "External crates must not deep-import `lib_consensus::validators::\
         validator_discovery::*` (CONS-501a). Use `lib_consensus_net::\
         discovery::*` instead. Found:\n  {}",
        matches.join("\n  ")
    );
}

/// CONS-202 / CONS-401: similar to the discovery rule, deep imports
/// under `lib_consensus::validators::validator_protocol::` from
/// external crates should hit the new canonical
/// `lib_consensus_net::validator_protocol` (or
/// `lib_consensus_core::types::messages` for the value types).
#[test]
fn no_external_deep_imports_of_validator_protocol() {
    let matches = grep_workspace(
        r"lib_consensus::validators::validator_protocol::",
        &[
            "lib-network/src/",
            "lib-blockchain/src/",
            "lib-consensus-core/src/",
            "lib-consensus-net/src/",
            "lib-consensus-runtime/src/",
            "zhtp/src/",
            "zhtp-cli/src/",
            "zhtp-daemon/src/",
        ],
    );
    let matches = drop_comment_only_matches(matches);
    assert!(
        matches.is_empty(),
        "External crates must not deep-import `lib_consensus::validators::\
         validator_protocol::*` (CONS-501b / CONS-401). Use \
         `lib_consensus_net::validator_protocol::*` or \
         `lib_consensus_core::types::messages::*` instead. Found:\n  {}",
        matches.join("\n  ")
    );
}

/// CONS-302 totality: every `(FsmState, Event)` pair must produce a
/// non-empty action list. The pin lives in
/// `lib-consensus-core/src/fsm/transition.rs::transition_total_no_silent_drops`.
/// This ratchet just confirms the test exists and hasn't been deleted.
#[test]
fn fsm_totality_test_exists() {
    let matches = grep_workspace(
        r"fn\s+transition_total_no_silent_drops",
        &["lib-consensus-core/src/fsm/"],
    );
    // We only care that *some* test by this name exists; bigger refactors
    // may rename it but the ratchet should be updated alongside.
    let matches = drop_lines_containing(matches, &[]);
    assert!(
        !matches.is_empty(),
        "FSM totality test (`transition_total_no_silent_drops`) is missing. \
         CONS-302 + CONS-603 require a test that asserts every \
         (FsmState, Event) pair returns a non-empty action list. Restore it \
         before merging."
    );
}

/// CONS-308 + CONS-401: the canonical `ValidatorMessage` enum lives at
/// `lib_consensus_core::types::messages`. Confirm a single `pub enum
/// ValidatorMessage` definition workspace-wide.
#[test]
fn single_validator_message_enum_definition() {
    let matches = grep_workspace(r"^\s*pub\s+enum\s+ValidatorMessage\b", &[]);
    let canonical = "lib-consensus-core/src/types/messages.rs";
    let extras: Vec<_> = matches
        .iter()
        // grep -rn prefixes with `./` when called with `.`; strip
        // before comparing against the canonical path.
        .filter(|line| {
            let stripped = line.strip_prefix("./").unwrap_or(line);
            !stripped.starts_with(canonical)
        })
        .cloned()
        .collect();
    assert!(
        extras.is_empty(),
        "Multiple ValidatorMessage enum definitions (CONS-201 says \
         exactly one, in {}). Extras:\n  {}",
        canonical,
        extras.join("\n  ")
    );
}
