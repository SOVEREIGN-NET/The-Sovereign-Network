//! Transport introspection port (CONS-403).
//!
//! Per AD-002, the consensus engine never reaches into the transport for
//! configuration. But the *runtime* needs a narrow read-only handle to
//! detect transport misconfigurations that would silently break the
//! broadcast watchdog (CONS-309) before it ever fires.
//!
//! The runtime startup check (planned in `lib-consensus-runtime`)
//! refuses to start whenever the transport's reported idle timeout
//! exceeds `lib_consensus_core::budget::MAX_BROADCAST_BUDGET_MS * 100`.
//! See `crate::budget` for the rationale and the test that pins the
//! ceiling at 75 s.
//!
//! This trait is intentionally tiny: just enough surface for that
//! startup assertion plus a name for diagnostics. Anything richer
//! belongs in a runtime-side trait (CONS-501..504 territory).
//!
//! ## Implementations
//!
//! - `lib-consensus-runtime`'s zhtp QUIC adapter returns the QUIC
//!   `max_idle_timeout` configured in
//!   `lib-network/src/protocols/quic_mesh.rs`.
//! - `NoOpTransportInfo` here is a test/benchmark double that returns
//!   a budget-respecting timeout so consensus tests don't have to wire
//!   a real transport.

use std::time::Duration;

/// Read-only introspection of the transport that delivers
/// `ValidatorMessage`s. Implementations must be cheap to call — the
/// runtime calls them at startup and may surface them in diagnostics.
pub trait TransportInfo: Send + Sync {
    /// The transport's idle timeout. The runtime startup check
    /// compares this against `budget::MAX_BROADCAST_BUDGET_MS * 100`.
    /// A timeout longer than the ceiling means stuck broadcasts
    /// disappear into the transport instead of surfacing to the
    /// watchdog.
    fn idle_timeout(&self) -> Duration;

    /// Short, stable name used in operator-facing error messages and
    /// dashboards (e.g. `"zhtp-quic-mesh"`). MUST NOT depend on
    /// runtime state — the runtime startup check needs to print it
    /// before the transport is fully wired.
    fn name(&self) -> &str;
}

/// In-memory test double. Returns the largest idle timeout that still
/// passes the startup check at `MAX_BROADCAST_BUDGET_MS = 750` ms,
/// keeping unit tests on the safe side of the budget.
pub struct NoOpTransportInfo;

impl TransportInfo for NoOpTransportInfo {
    fn idle_timeout(&self) -> Duration {
        // Exactly the runtime ceiling — passes the `<= ceiling` check
        // by one millisecond's worth of margin in any realistic
        // implementation. Tests that need a *failing* transport should
        // construct their own with an explicit, larger timeout.
        Duration::from_millis(crate::budget::MAX_BROADCAST_BUDGET_MS * 100 - 1)
    }

    fn name(&self) -> &str {
        "noop-transport"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_transport_passes_runtime_ceiling() {
        // Guard the contract for `NoOpTransportInfo`: idle timeout
        // must be strictly under the runtime's startup ceiling so
        // tests that depend on it are never the canary.
        let ceiling = Duration::from_millis(crate::budget::MAX_BROADCAST_BUDGET_MS * 100);
        assert!(
            NoOpTransportInfo.idle_timeout() < ceiling,
            "NoOpTransportInfo.idle_timeout() must be strictly below the runtime ceiling"
        );
    }

    #[test]
    fn noop_transport_name_is_stable() {
        // Name is operator-facing — pin it so a future rename forces
        // a runbook update.
        assert_eq!(NoOpTransportInfo.name(), "noop-transport");
    }
}
