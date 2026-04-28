//! `ConsensusRuntime` — single owner of the consensus loop and side-effect
//! dispatch.
//!
//! ## Status (CONS-502 scaffold)
//!
//! This first cut wraps the existing `lib_consensus::ConsensusEngine` and
//! does **just two things**:
//!
//! 1. Runs the **startup transport-compatibility check** documented in
//!    `lib_consensus_core::budget` (CONS-310 / CONS-403). If the transport's
//!    `idle_timeout()` exceeds `MAX_BROADCAST_BUDGET_MS * 100`, runtime
//!    construction fails with [`RuntimeError::TransportIdleTooLong`] —
//!    surfacing the misconfiguration before any consensus rounds run.
//! 2. Delegates `run()` to `ConsensusEngine::run_consensus_loop()`.
//!
//! Follow-up PRs add (in order):
//! - **CONS-502b**: engine event-injection channel + watchdog spawn
//!   (closes CONS-309 fully).
//! - **CONS-502c**: `Action` executor task driven by the action channel
//!   from CONS-306/307.
//! - **CONS-502d**: zhtp swap from `engine.run_consensus_loop()` to
//!   `ConsensusRuntime::run()`.
//!
//! Until CONS-502d lands, zhtp keeps calling the engine directly — this
//! crate is **opt-in** and changes nothing in production.

use std::sync::Arc;

use lib_consensus::{ConsensusEngine, ConsensusError};
use lib_consensus_core::budget::MAX_BROADCAST_BUDGET_MS;
use lib_consensus_core::ports::TransportInfo;

/// Errors surfaced by [`ConsensusRuntime::new`] — all configuration errors
/// caught at startup, never during a round.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The transport's idle timeout exceeds the runtime ceiling
    /// (`MAX_BROADCAST_BUDGET_MS * 100`). A transport that lets a stuck
    /// broadcast sit silently for longer than the watchdog budget × 100
    /// would mask liveness bugs the watchdog is meant to surface.
    #[error(
        "transport `{transport}` reports idle_timeout = {actual_ms} ms, exceeds \
         the consensus runtime ceiling of {ceiling_ms} ms (MAX_BROADCAST_BUDGET_MS × 100). \
         Lower the transport's idle timeout or raise MAX_BROADCAST_BUDGET_MS in \
         lib_consensus_core::budget — both are cross-cutting protocol decisions \
         (AD-011)."
    )]
    TransportIdleTooLong {
        transport: String,
        actual_ms: u128,
        ceiling_ms: u128,
    },
}

/// Runtime ceiling for the transport idle timeout (CONS-310). Computed
/// once so tests and error messages share the exact same number. The
/// `lib_consensus_core::budget::tests::broadcast_budget_times_100_is_75_seconds`
/// test pins the underlying constant.
fn transport_idle_ceiling_ms() -> u128 {
    u128::from(MAX_BROADCAST_BUDGET_MS) * 100
}

/// Owns the `ConsensusEngine` and the future orchestration glue. See the
/// module docs for the staged build-out.
pub struct ConsensusRuntime {
    engine: ConsensusEngine,
    transport_name: String,
}

impl ConsensusRuntime {
    /// Build a runtime around `engine`, asserting the transport is
    /// compatible with the consensus budget. The transport is consulted
    /// only at construction; the runtime never holds it after that.
    pub fn new(
        engine: ConsensusEngine,
        transport: &dyn TransportInfo,
    ) -> Result<Self, RuntimeError> {
        let ceiling_ms = transport_idle_ceiling_ms();
        let actual_ms = transport.idle_timeout().as_millis();
        if actual_ms > ceiling_ms {
            return Err(RuntimeError::TransportIdleTooLong {
                transport: transport.name().to_string(),
                actual_ms,
                ceiling_ms,
            });
        }
        Ok(Self {
            engine,
            transport_name: transport.name().to_string(),
        })
    }

    /// Convenience builder for callers that already hold a
    /// `Arc<dyn TransportInfo>`. The Arc is only used to read at startup.
    pub fn from_arc(
        engine: ConsensusEngine,
        transport: Arc<dyn TransportInfo>,
    ) -> Result<Self, RuntimeError> {
        Self::new(engine, transport.as_ref())
    }

    /// Operator-facing transport name captured at startup. Useful in
    /// dashboards alongside engine diagnostics.
    pub fn transport_name(&self) -> &str {
        &self.transport_name
    }

    /// Drive the consensus loop. Today this is a thin delegate to
    /// `ConsensusEngine::run_consensus_loop()`. CONS-502b/c add the
    /// watchdog and action-executor tasks alongside, in a single
    /// `tokio::select!` per AD-006.
    pub async fn run(mut self) -> Result<(), ConsensusError> {
        tracing::info!(
            "ConsensusRuntime starting (transport={})",
            self.transport_name
        );
        self.engine.run_consensus_loop().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_consensus_core::ports::NoOpTransportInfo;
    use std::time::Duration;

    /// Test fixture: a transport that returns whatever idle timeout we
    /// hand it. Lives only here — production transports are concrete
    /// types in their respective adapter modules.
    struct ConfigurableTransport {
        idle: Duration,
        name: &'static str,
    }
    impl TransportInfo for ConfigurableTransport {
        fn idle_timeout(&self) -> Duration {
            self.idle
        }
        fn name(&self) -> &str {
            self.name
        }
    }

    /// We can't construct a real `ConsensusEngine` here without a full
    /// lib-consensus fixture (config + broadcaster + identity). The
    /// startup check is a pure function of `transport`, so we exercise
    /// it via the standalone classifier and spot-check the error shape.
    fn classify_transport(t: &dyn TransportInfo) -> Result<(), RuntimeError> {
        let ceiling_ms = transport_idle_ceiling_ms();
        let actual_ms = t.idle_timeout().as_millis();
        if actual_ms > ceiling_ms {
            Err(RuntimeError::TransportIdleTooLong {
                transport: t.name().to_string(),
                actual_ms,
                ceiling_ms,
            })
        } else {
            Ok(())
        }
    }

    #[test]
    fn ceiling_matches_budget_documented_value() {
        // Budget says 750 ms × 100 = 75 000 ms. Pin the relationship so
        // any change to either constant is a visible failure.
        assert_eq!(transport_idle_ceiling_ms(), 75_000);
    }

    #[test]
    fn noop_transport_passes_startup_check() {
        // The provided NoOpTransportInfo is the canonical "good"
        // fixture; if it ever stops passing this check, every consensus
        // unit test using it would silently start failing.
        assert!(classify_transport(&NoOpTransportInfo).is_ok());
    }

    #[test]
    fn transport_at_ceiling_passes() {
        let t = ConfigurableTransport {
            idle: Duration::from_millis(75_000),
            name: "exact-ceiling",
        };
        assert!(classify_transport(&t).is_ok());
    }

    #[test]
    fn transport_one_ms_over_ceiling_fails() {
        let t = ConfigurableTransport {
            idle: Duration::from_millis(75_001),
            name: "one-ms-over",
        };
        let err = classify_transport(&t).unwrap_err();
        match err {
            RuntimeError::TransportIdleTooLong {
                transport,
                actual_ms,
                ceiling_ms,
            } => {
                assert_eq!(transport, "one-ms-over");
                assert_eq!(actual_ms, 75_001);
                assert_eq!(ceiling_ms, 75_000);
            }
        }
    }

    #[test]
    fn realistic_quic_idle_300s_fails_loudly() {
        // The current zhtp QUIC mesh idle timeout is 300 s (issue #907).
        // This test documents the AD-011 collision: under today's
        // budget, a real production transport fails the startup check.
        // Resolution belongs to a coordinated change of MAX_BROADCAST_
        // BUDGET_MS or the QUIC config — see CONS-403 PR #2412 body.
        let t = ConfigurableTransport {
            idle: Duration::from_secs(300),
            name: "zhtp-quic-mesh",
        };
        let err = classify_transport(&t).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("zhtp-quic-mesh"), "msg = {}", msg);
        assert!(msg.contains("300000"), "msg = {}", msg);
        assert!(msg.contains("75000"), "msg = {}", msg);
    }

    #[test]
    fn error_message_names_constant_and_ad() {
        // The error must give an operator enough to act without reading
        // source: the constant name and the AD reference.
        let t = ConfigurableTransport {
            idle: Duration::from_secs(120),
            name: "test-transport",
        };
        let msg = format!("{}", classify_transport(&t).unwrap_err());
        assert!(msg.contains("MAX_BROADCAST_BUDGET_MS"), "msg = {}", msg);
        assert!(msg.contains("AD-011"), "msg = {}", msg);
    }
}
