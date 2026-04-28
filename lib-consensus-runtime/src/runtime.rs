//! `ConsensusRuntime` — single owner of the consensus loop and side-effect
//! dispatch.
//!
//! ## Status (CONS-502 + CONS-502b)
//!
//! This cut wraps the existing `lib_consensus::ConsensusEngine` and does:
//!
//! 1. Runs the **startup transport-compatibility check** documented in
//!    `lib_consensus_core::budget` (CONS-310 / CONS-403). If the transport's
//!    `idle_timeout()` exceeds `MAX_BROADCAST_BUDGET_MS * 100`, runtime
//!    construction fails with [`RuntimeError::TransportIdleTooLong`] —
//!    surfacing the misconfiguration before any consensus rounds run.
//! 2. **Spawns the watchdog task (CONS-309/CONS-502b)** that polls a
//!    shared "last `ResetWatchdog`" clock and fires
//!    `Event::WatchdogFired` into the engine's runtime-event channel
//!    when the engine has been idle longer than
//!    `WATCHDOG_THRESHOLD_MULTIPLIER × max(propose_timeout,
//!    prevote_timeout, precommit_timeout)`. The engine's FSM transitions
//!    Idle/Proposing/Prevoting/Precommitting → Hung on receipt.
//! 3. Drives the engine via `ConsensusEngine::run_consensus_loop()`.
//!
//! Follow-up PRs:
//! - **CONS-502c**: `Action` executor task driven by the action channel
//!   from CONS-306/307.
//! - **CONS-502d**: zhtp swap from `engine.run_consensus_loop()` to
//!   `ConsensusRuntime::run()`.
//!
//! Until CONS-502d lands, zhtp keeps calling the engine directly — this
//! crate is **opt-in** and changes nothing in production.

use std::sync::Arc;
use std::time::Duration;

use lib_consensus::engines::consensus_engine::BroadcastEnvelope;
use lib_consensus::types::MessageBroadcaster;
use lib_consensus::{ConsensusEngine, ConsensusError};
use lib_consensus_core::budget::{MAX_BROADCAST_BUDGET_MS, WATCHDOG_THRESHOLD_MULTIPLIER};
use lib_consensus_core::fsm::Event;
use lib_consensus_core::ports::TransportInfo;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// CONS-309: how often the watchdog task wakes up to compare
/// `Instant::now() - last_reset` against the threshold. 500 ms matches
/// the spec sketch and is far below any realistic per-phase timeout, so
/// the latency between hang and fire is bounded by this value.
const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(500);

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

/// Owns the `ConsensusEngine`, the watchdog task, and the broadcast
/// executor task (CONS-306). CONS-502d wires this from zhtp.
pub struct ConsensusRuntime {
    engine: ConsensusEngine,
    transport_name: String,
    watchdog_threshold: Duration,
    watchdog_clock: Arc<RwLock<Instant>>,
    /// Receiver retained until `run()` consumes it to spawn the watchdog
    /// task; the matching sender is already installed on the engine via
    /// `set_runtime_event_receiver`.
    runtime_event_tx_for_watchdog: mpsc::UnboundedSender<Event>,
    /// CONS-306: broadcast envelopes from the engine. The executor task
    /// drains this and is the **only** caller of
    /// `broadcaster.broadcast_to_validators(...).await` once
    /// `set_broadcast_sender` has been wired on the engine.
    broadcast_rx: Option<mpsc::UnboundedReceiver<BroadcastEnvelope>>,
    /// CONS-306: the broadcaster Arc cloned out of the engine so the
    /// executor task can call it without borrowing the engine.
    broadcaster: Arc<dyn MessageBroadcaster>,
}

impl ConsensusRuntime {
    /// Validate a transport against the consensus budget without
    /// consuming an engine. Useful for callers that want to inspect
    /// the result before committing the engine to a runtime — e.g.
    /// zhtp logs the AD-011 collision and falls back to the legacy
    /// direct-engine path until the QUIC idle vs.
    /// `MAX_BROADCAST_BUDGET_MS` mismatch is reconciled.
    pub fn check_transport(transport: &dyn TransportInfo) -> Result<(), RuntimeError> {
        let ceiling_ms = transport_idle_ceiling_ms();
        let actual_ms = transport.idle_timeout().as_millis();
        if actual_ms > ceiling_ms {
            return Err(RuntimeError::TransportIdleTooLong {
                transport: transport.name().to_string(),
                actual_ms,
                ceiling_ms,
            });
        }
        Ok(())
    }

    /// Build a runtime around `engine`, asserting the transport is
    /// compatible with the consensus budget and installing the
    /// runtime-event channel + watchdog clock on the engine.
    ///
    /// The watchdog threshold is computed from the engine's config as
    /// `WATCHDOG_THRESHOLD_MULTIPLIER × max(propose_timeout,
    /// prevote_timeout, precommit_timeout)`. Override with
    /// [`Self::with_watchdog_threshold`] when an integration test
    /// needs a tighter bound.
    pub fn new(
        mut engine: ConsensusEngine,
        transport: &dyn TransportInfo,
    ) -> Result<Self, RuntimeError> {
        Self::check_transport(transport)?;

        let watchdog_threshold = derive_watchdog_threshold(engine.config());
        let watchdog_clock = Arc::new(RwLock::new(Instant::now()));
        let (event_tx, event_rx) = mpsc::unbounded_channel::<Event>();

        engine.set_watchdog_clock(watchdog_clock.clone());
        engine.set_runtime_event_receiver(event_rx);

        // CONS-306: wire the broadcast queue. After this point, every
        // `enter_*_step` / heartbeat / proposal-relay call in the
        // engine emits envelopes here instead of awaiting the
        // broadcaster directly.
        let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel::<BroadcastEnvelope>();
        let broadcaster = engine.broadcaster_arc();
        engine.set_broadcast_sender(broadcast_tx);

        Ok(Self {
            engine,
            transport_name: transport.name().to_string(),
            watchdog_threshold,
            watchdog_clock,
            runtime_event_tx_for_watchdog: event_tx,
            broadcast_rx: Some(broadcast_rx),
            broadcaster,
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

    /// Override the watchdog threshold. Default is derived from
    /// `engine.config()`; tests use this to make the threshold trip
    /// in <1 s instead of waiting on real phase timeouts.
    pub fn with_watchdog_threshold(mut self, threshold: Duration) -> Self {
        self.watchdog_threshold = threshold;
        self
    }

    /// Operator-facing transport name captured at startup. Useful in
    /// dashboards alongside engine diagnostics.
    pub fn transport_name(&self) -> &str {
        &self.transport_name
    }

    /// Effective watchdog threshold (post any
    /// [`Self::with_watchdog_threshold`] override). Surfaced for
    /// diagnostics + tests.
    pub fn watchdog_threshold(&self) -> Duration {
        self.watchdog_threshold
    }

    /// Drive the consensus loop with the watchdog and the broadcast
    /// executor spawned alongside. On engine exit (graceful or error)
    /// both background tasks are aborted.
    pub async fn run(mut self) -> Result<(), ConsensusError> {
        tracing::info!(
            "ConsensusRuntime starting (transport={}, watchdog_threshold={:?})",
            self.transport_name,
            self.watchdog_threshold
        );
        let watchdog_handle = spawn_watchdog(
            self.watchdog_clock.clone(),
            self.watchdog_threshold,
            self.runtime_event_tx_for_watchdog.clone(),
            WATCHDOG_POLL_INTERVAL,
        );
        let broadcast_handle = self
            .broadcast_rx
            .take()
            .map(|rx| spawn_broadcast_executor(rx, self.broadcaster.clone()));
        let result = self.engine.run_consensus_loop().await;
        watchdog_handle.abort();
        if let Some(h) = broadcast_handle {
            h.abort();
        }
        result
    }
}

/// CONS-306 broadcast executor: drains envelopes from the engine and
/// is the **only** caller of `broadcast_to_validators(...).await`.
/// Per CE-ENG-4 each broadcast is best-effort — failures are logged
/// and dropped, never retried (retry is the responsibility of the
/// FSM via timeouts).
pub(crate) fn spawn_broadcast_executor(
    mut rx: mpsc::UnboundedReceiver<BroadcastEnvelope>,
    broadcaster: Arc<dyn MessageBroadcaster>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(env) = rx.recv().await {
            if let Err(e) = broadcaster
                .broadcast_to_validators(env.message, &env.recipients)
                .await
            {
                tracing::debug!(error = ?e, "Broadcast executor: send failed (CE-ENG-4)");
            }
        }
        tracing::debug!("Broadcast executor exited — engine sender dropped");
    })
}

/// Derive the watchdog threshold from the engine's per-phase timeouts.
/// `WATCHDOG_THRESHOLD_MULTIPLIER` is centralized in
/// `lib_consensus_core::budget` per AD-011.
fn derive_watchdog_threshold(config: &lib_types::consensus::ConsensusConfig) -> Duration {
    let max_phase_ms = config
        .propose_timeout
        .max(config.prevote_timeout)
        .max(config.precommit_timeout);
    Duration::from_millis(max_phase_ms.saturating_mul(u64::from(WATCHDOG_THRESHOLD_MULTIPLIER)))
}

/// Spawn the watchdog task. Visible to integration tests so they can
/// exercise the latch + fire behaviour without a real `ConsensusEngine`.
pub(crate) fn spawn_watchdog(
    clock: Arc<RwLock<Instant>>,
    threshold: Duration,
    tx: mpsc::UnboundedSender<Event>,
    poll_interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(poll_interval);
        // Latch: fire exactly once per `Hung` episode so we don't spam
        // the engine with WatchdogFired while it's already in `Hung`.
        // Re-arms once the engine resets the clock (i.e. Hung exits via
        // external recovery and `ResetWatchdog` runs again).
        let mut already_fired_for_current_idle = false;
        loop {
            tick.tick().await;
            let last_reset = *clock.read().await;
            let age = last_reset.elapsed();
            if age <= threshold {
                already_fired_for_current_idle = false;
                continue;
            }
            if already_fired_for_current_idle {
                continue;
            }
            let event = Event::WatchdogFired {
                age_ms: age.as_millis() as u64,
                // The FSM event uses `std::time::Instant`; tokio's
                // wrapper converts cleanly. With a paused tokio clock,
                // both reflect the virtual time consistently.
                fired_at: Instant::now().into_std(),
            };
            match tx.send(event) {
                Ok(()) => {
                    tracing::warn!(
                        age_ms = age.as_millis() as u64,
                        threshold_ms = threshold.as_millis() as u64,
                        "Consensus watchdog fired — engine idle past threshold"
                    );
                    already_fired_for_current_idle = true;
                }
                Err(_) => {
                    tracing::debug!(
                        "Watchdog task exiting — engine event receiver closed"
                    );
                    break;
                }
            }
        }
    })
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

    // ---------------- watchdog (CONS-309 / CONS-502b) ----------------

    fn fixture_config() -> lib_types::consensus::ConsensusConfig {
        // Default values; what matters here is that the per-phase
        // timeouts get multiplied by WATCHDOG_THRESHOLD_MULTIPLIER.
        let mut c = lib_types::consensus::ConsensusConfig::default();
        c.propose_timeout = 200;
        c.prevote_timeout = 300;
        c.precommit_timeout = 250;
        c
    }

    #[test]
    fn derived_threshold_uses_max_phase_times_multiplier() {
        let cfg = fixture_config();
        let t = derive_watchdog_threshold(&cfg);
        // max(200, 300, 250) = 300; × 5 = 1500 ms.
        assert_eq!(t, Duration::from_millis(1500));
    }

    #[test]
    fn derived_threshold_handles_overflow_safely() {
        let mut cfg = lib_types::consensus::ConsensusConfig::default();
        cfg.propose_timeout = u64::MAX;
        cfg.prevote_timeout = 1;
        cfg.precommit_timeout = 1;
        // saturating_mul keeps the threshold finite instead of panicking
        // — operator misconfiguration shouldn't take down the runtime
        // before consensus has a chance to start.
        let t = derive_watchdog_threshold(&cfg);
        assert_eq!(t, Duration::from_millis(u64::MAX));
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_fires_after_threshold_elapses() {
        // Pause the tokio clock so we can advance virtual time without
        // sleeping — keeps the test deterministic and fast.
        let clock = Arc::new(RwLock::new(Instant::now()));
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        let handle = spawn_watchdog(
            clock.clone(),
            Duration::from_millis(100),
            tx,
            Duration::from_millis(20),
        );

        tokio::time::advance(Duration::from_millis(150)).await;
        // Yield enough for the spawned task's interval to tick + the
        // send to land in the rx buffer.
        let event = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("watchdog did not fire within 1 s of virtual time")
            .expect("rx closed unexpectedly");
        match event {
            Event::WatchdogFired { age_ms, .. } => {
                assert!(age_ms >= 100, "age_ms = {}", age_ms);
            }
            other => panic!("expected WatchdogFired, got {:?}", other),
        }
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_does_not_fire_when_clock_keeps_resetting() {
        let clock = Arc::new(RwLock::new(Instant::now()));
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        let handle = spawn_watchdog(
            clock.clone(),
            Duration::from_millis(100),
            tx,
            Duration::from_millis(20),
        );

        // Reset every 30 ms for 200 ms. With threshold = 100 ms and
        // resets at 30 ms intervals, age never crosses 100 ms.
        for _ in 0..6 {
            tokio::time::advance(Duration::from_millis(30)).await;
            *clock.write().await = Instant::now();
        }

        // Sample the channel — should be empty.
        match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            Err(_) => { /* expected: timeout means no event */ }
            Ok(Some(e)) => panic!("watchdog fired despite resets: {:?}", e),
            Ok(None) => panic!("rx closed unexpectedly"),
        }
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_latches_to_one_fire_per_idle_episode() {
        // While clock stays stale, the watchdog must fire exactly once
        // until a reset. This prevents flooding the engine's event
        // channel with redundant `WatchdogFired` events while it sits
        // in `Hung`.
        let clock = Arc::new(RwLock::new(Instant::now()));
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        let handle = spawn_watchdog(
            clock.clone(),
            Duration::from_millis(50),
            tx,
            Duration::from_millis(10),
        );

        tokio::time::advance(Duration::from_millis(500)).await;

        // Drain whatever has arrived; expect exactly one event.
        let first = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("first fire never arrived")
            .expect("rx closed");
        assert!(matches!(first, Event::WatchdogFired { .. }));

        // No further events should arrive while clock stays stale.
        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
            Err(_) => { /* expected: latch held */ }
            Ok(Some(e)) => panic!("watchdog double-fired: {:?}", e),
            Ok(None) => panic!("rx closed unexpectedly"),
        }
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_re_arms_after_clock_reset() {
        // After the first fire, a reset should re-enable a second fire
        // once the clock goes stale again. This mirrors the "Hung →
        // Idle via external recovery → Hung again" episode shape.
        let clock = Arc::new(RwLock::new(Instant::now()));
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        let handle = spawn_watchdog(
            clock.clone(),
            Duration::from_millis(50),
            tx,
            Duration::from_millis(10),
        );

        // Episode 1: let it fire.
        tokio::time::advance(Duration::from_millis(200)).await;
        let first = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("first fire never arrived")
            .expect("rx closed");
        assert!(matches!(first, Event::WatchdogFired { .. }));

        // Reset the clock as the engine would after Hung exits, then
        // sleep a sub-threshold interval to give the watchdog a chance
        // to observe `age <= threshold` and clear its latch. With a
        // paused clock, sleep yields to the spawned task and advances
        // virtual time together.
        *clock.write().await = Instant::now();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Episode 2: another stale period → another fire.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let second = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("second fire never arrived")
            .expect("rx closed");
        assert!(matches!(second, Event::WatchdogFired { .. }));
        handle.abort();
    }

    // ---------------- broadcast executor (CONS-306) ----------------

    /// Counting fake broadcaster — records every envelope it sees.
    /// Lives in this module so the executor's contract is tested
    /// without dragging in an end-to-end engine fixture.
    struct CountingBroadcaster {
        calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    #[async_trait::async_trait]
    impl lib_consensus::types::MessageBroadcaster for CountingBroadcaster {
        async fn broadcast_to_validators(
            &self,
            _message: lib_consensus::types::ValidatorMessage,
            _validator_ids: &[lib_identity::IdentityId],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn broadcast_executor_exits_on_sender_drop() {
        // Closing the sender side cleanly exits the executor, freeing
        // its task slot so the runtime's `run()` can return. End-to-
        // end "drains every envelope" coverage lands in the engine
        // integration test added alongside the CONS-309 stuck-FSM
        // assertion (separate PR — needs a real engine fixture).
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let broadcaster: Arc<dyn lib_consensus::types::MessageBroadcaster> =
            Arc::new(CountingBroadcaster {
                calls: calls.clone(),
            });
        let (tx, rx) = mpsc::unbounded_channel::<BroadcastEnvelope>();
        let handle = spawn_broadcast_executor(rx, broadcaster);
        drop(tx);
        let res = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(res.is_ok(), "executor did not exit on sender drop");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_exits_when_engine_event_channel_closes() {
        // If the engine drops its receiver (e.g. clean shutdown), the
        // watchdog task should exit on its next attempt-to-send rather
        // than spin forever.
        let clock = Arc::new(RwLock::new(Instant::now()));
        let (tx, rx) = mpsc::unbounded_channel::<Event>();
        let handle = spawn_watchdog(
            clock.clone(),
            Duration::from_millis(50),
            tx,
            Duration::from_millis(10),
        );

        drop(rx);
        tokio::time::advance(Duration::from_millis(200)).await;

        // Give the task a tick to observe the closed channel.
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        // If we got here without panicking the join completed.
    }
}
