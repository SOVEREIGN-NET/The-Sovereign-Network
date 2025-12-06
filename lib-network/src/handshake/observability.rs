//! Observability and metrics for Unified Handshake Protocol
//!
//! **FINDING 4 FIX:** Provides observability hooks for monitoring handshake
//! operations, detecting attacks, and tracking performance metrics.
//!
//! This module implements a trait-based observer pattern that allows external
//! systems (Prometheus, logging, alerting) to receive notifications about
//! handshake events without coupling the core protocol to specific monitoring
//! implementations.

use std::time::Instant;

/// Handshake event types for observability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEvent {
    /// ClientHello message received
    ClientHelloReceived,
    /// ClientHello signature verification started
    ClientHelloVerificationStarted,
    /// ClientHello signature verification succeeded
    ClientHelloVerificationSuccess,
    /// ClientHello signature verification failed
    ClientHelloVerificationFailed,

    /// ServerHello message created
    ServerHelloCreated,
    /// ServerHello signature verification started
    ServerHelloVerificationStarted,
    /// ServerHello signature verification succeeded
    ServerHelloVerificationSuccess,
    /// ServerHello signature verification failed
    ServerHelloVerificationFailed,

    /// ClientFinish message received
    ClientFinishReceived,
    /// ClientFinish signature verification started
    ClientFinishVerificationStarted,
    /// ClientFinish signature verification succeeded
    ClientFinishVerificationSuccess,
    /// ClientFinish signature verification failed
    ClientFinishVerificationFailed,

    /// Handshake completed successfully
    HandshakeComplete,

    /// Replay attack detected
    ReplayAttackDetected,
    /// Invalid timestamp detected
    InvalidTimestampDetected,
    /// Invalid protocol version detected
    InvalidProtocolVersionDetected,
    /// NodeId verification failed
    NodeIdVerificationFailed,
    /// Nonce cache full (may indicate DoS)
    NonceCacheFull,
}

/// Failure reason for handshake events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    /// Replay attack (nonce already used)
    ReplayAttack,
    /// Invalid signature
    InvalidSignature,
    /// Invalid timestamp (too old/too new)
    InvalidTimestamp,
    /// Invalid protocol version
    InvalidProtocolVersion,
    /// NodeId verification failed
    NodeIdVerificationFailed,
    /// Other error with description
    Other(String),
}

/// Handshake metrics snapshot
#[derive(Debug, Clone)]
pub struct HandshakeMetrics {
    /// Duration of verification operation
    pub duration_micros: u64,
    /// Nonce cache size
    pub nonce_cache_size: usize,
    /// Nonce cache utilization (0.0 to 1.0)
    pub nonce_cache_utilization: f64,
    /// Protocol version
    pub protocol_version: u8,
}

/// Observer trait for handshake events
///
/// Implementations can track metrics, emit logs, send alerts, etc.
/// The trait uses non-async methods to avoid forcing async on observers.
pub trait HandshakeObserver: Send + Sync {
    /// Called when a handshake event occurs
    ///
    /// # Parameters
    /// - `event`: The type of event that occurred
    /// - `metrics`: Optional metrics snapshot at time of event
    fn on_event(&self, event: HandshakeEvent, metrics: Option<HandshakeMetrics>);

    /// Called when a handshake operation fails
    ///
    /// # Parameters
    /// - `event`: The event that failed
    /// - `reason`: Why the operation failed
    /// - `metrics`: Optional metrics snapshot at time of failure
    fn on_failure(&self, event: HandshakeEvent, reason: FailureReason, metrics: Option<HandshakeMetrics>);
}

/// No-op observer that does nothing (default)
#[derive(Debug, Clone, Copy)]
pub struct NoOpObserver;

impl HandshakeObserver for NoOpObserver {
    fn on_event(&self, _event: HandshakeEvent, _metrics: Option<HandshakeMetrics>) {
        // No-op
    }

    fn on_failure(&self, _event: HandshakeEvent, _reason: FailureReason, _metrics: Option<HandshakeMetrics>) {
        // No-op
    }
}

/// Logging observer that emits tracing events
///
/// Useful for debugging and development
#[derive(Debug, Clone, Copy)]
pub struct LoggingObserver;

impl HandshakeObserver for LoggingObserver {
    fn on_event(&self, event: HandshakeEvent, metrics: Option<HandshakeMetrics>) {
        if let Some(m) = metrics {
            tracing::debug!(
                event = ?event,
                duration_micros = m.duration_micros,
                nonce_cache_size = m.nonce_cache_size,
                nonce_cache_utilization = m.nonce_cache_utilization,
                protocol_version = m.protocol_version,
                "Handshake event"
            );
        } else {
            tracing::debug!(event = ?event, "Handshake event");
        }
    }

    fn on_failure(&self, event: HandshakeEvent, reason: FailureReason, metrics: Option<HandshakeMetrics>) {
        if let Some(m) = metrics {
            tracing::warn!(
                event = ?event,
                reason = ?reason,
                duration_micros = m.duration_micros,
                nonce_cache_size = m.nonce_cache_size,
                "Handshake failure"
            );
        } else {
            tracing::warn!(event = ?event, reason = ?reason, "Handshake failure");
        }
    }
}

/// Helper for timing operations
pub struct Timer {
    start: Instant,
}

impl Timer {
    /// Start a new timer
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Get elapsed time in microseconds
    pub fn elapsed_micros(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_observer() {
        let observer = NoOpObserver;

        // Should not panic
        observer.on_event(HandshakeEvent::ClientHelloReceived, None);
        observer.on_failure(
            HandshakeEvent::ClientHelloVerificationFailed,
            FailureReason::InvalidSignature,
            None,
        );
    }

    #[test]
    fn test_logging_observer() {
        let observer = LoggingObserver;

        let metrics = HandshakeMetrics {
            duration_micros: 1000,
            nonce_cache_size: 100,
            nonce_cache_utilization: 0.5,
            protocol_version: 1,
        };

        // Should not panic
        observer.on_event(HandshakeEvent::ClientHelloReceived, Some(metrics.clone()));
        observer.on_failure(
            HandshakeEvent::ClientHelloVerificationFailed,
            FailureReason::InvalidSignature,
            Some(metrics),
        );
    }

    #[test]
    fn test_timer() {
        let timer = Timer::start();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let elapsed = timer.elapsed_micros();

        // Should be at least 1ms (1000 microseconds)
        assert!(elapsed >= 1000);
    }
}
