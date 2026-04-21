//! Relay Admission Policy and Eligibility State Machine (#2201)
//!
//! Defines and enforces relay admission states (eligible, probation, blocked)
//! based on identity/trust/health criteria.

use serde::{Deserialize, Serialize};

/// Relay admission state for a peer.
///
/// Governs whether a peer may participate in message routing for others.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayAdmissionState {
    /// New or under-evaluation peer; may route but with penalty.
    Probation,
    /// Fully approved for relay/routing duties.
    Eligible,
    /// Explicitly barred from routing (abuse, health, trust failure).
    Blocked,
}

/// Detailed relay admission status for a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAdmissionStatus {
    /// Current admission state.
    pub state: RelayAdmissionState,
    /// Human-readable reason for the current state.
    pub reason: String,
    /// Unix timestamp of last evaluation.
    pub evaluated_at: u64,
    /// DID of evaluator, or "auto" for heuristic evaluation.
    pub evaluated_by: Option<String>,
    /// If Probation, when the probation period expires.
    pub probation_end: Option<u64>,
    /// If Blocked, when the block expires (None = permanent).
    pub block_expires: Option<u64>,
}

impl RelayAdmissionStatus {
    /// Create a new `Eligible` status.
    pub fn eligible(reason: impl Into<String>, evaluated_at: u64) -> Self {
        Self {
            state: RelayAdmissionState::Eligible,
            reason: reason.into(),
            evaluated_at,
            evaluated_by: Some("auto".to_string()),
            probation_end: None,
            block_expires: None,
        }
    }

    /// Create a new `Probation` status.
    pub fn probation(reason: impl Into<String>, evaluated_at: u64, end: u64) -> Self {
        Self {
            state: RelayAdmissionState::Probation,
            reason: reason.into(),
            evaluated_at,
            evaluated_by: Some("auto".to_string()),
            probation_end: Some(end),
            block_expires: None,
        }
    }

    /// Create a new `Blocked` status.
    pub fn blocked(reason: impl Into<String>, evaluated_at: u64, expires: Option<u64>) -> Self {
        Self {
            state: RelayAdmissionState::Blocked,
            reason: reason.into(),
            evaluated_at,
            evaluated_by: Some("auto".to_string()),
            probation_end: None,
            block_expires: expires,
        }
    }

    /// Returns true if a `Blocked` status has expired and should be re-evaluated.
    pub fn is_block_expired(&self, now: u64) -> bool {
        self.state == RelayAdmissionState::Blocked
            && self.block_expires.map_or(false, |exp| now >= exp)
    }

    /// Returns true if a `Probation` status has expired.
    pub fn is_probation_expired(&self, now: u64) -> bool {
        self.state == RelayAdmissionState::Probation
            && self.probation_end.map_or(false, |exp| now >= exp)
    }
}

/// Summary of relay admission counts across the registry.
#[derive(Debug, Clone, Default)]
pub struct RelayAdmissionSummary {
    pub eligible: usize,
    pub probation: usize,
    pub blocked: usize,
    pub unevaluated: usize,
}

/// Evaluate relay admission for a peer based on heuristics.
///
/// # Criteria for `Eligible`
/// - `authenticated` + `quantum_secure` both true
/// - `trust_score` >= 0.5
/// - `tier` >= Tier2
/// - `connection_metrics.stability_score` >= 0.6
/// - `connection_metrics.latency_ms` <= 500
/// - `capabilities.routing_capacity` >= 10
/// - `last_seen` within the last hour
///
/// # Criteria for `Probation`
/// - Missing 1–2 eligible criteria
/// - `trust_score` >= 0.3
/// - `authenticated` is true
///
/// # Criteria for `Blocked`
/// - `trust_score` < 0.3, or
/// - `tier` == Untrusted, or
/// - `authenticated` is false
pub fn evaluate_relay_admission(
    authenticated: bool,
    quantum_secure: bool,
    trust_score: f64,
    tier: &super::PeerTier,
    stability_score: f64,
    latency_ms: u32,
    routing_capacity: u32,
    last_seen: u64,
    now: u64,
    existing: Option<&RelayAdmissionStatus>,
) -> RelayAdmissionStatus {
    // Preserve existing block unless expired
    if let Some(existing) = existing {
        if existing.state == RelayAdmissionState::Blocked && !existing.is_block_expired(now) {
            return RelayAdmissionStatus {
                state: RelayAdmissionState::Blocked,
                reason: format!("Block still active: {}", existing.reason),
                evaluated_at: now,
                evaluated_by: existing.evaluated_by.clone(),
                probation_end: None,
                block_expires: existing.block_expires,
            };
        }
    }

    // Hard block conditions
    if !authenticated {
        return RelayAdmissionStatus::blocked(
            "Peer is not authenticated",
            now,
            None,
        );
    }
    if trust_score < 0.3 {
        return RelayAdmissionStatus::blocked(
            format!("Trust score {:.2} below minimum threshold 0.3", trust_score),
            now,
            None,
        );
    }
    if *tier == super::PeerTier::Untrusted {
        return RelayAdmissionStatus::blocked(
            "Peer tier is Untrusted",
            now,
            None,
        );
    }

    // Score eligible criteria
    let mut eligible_criteria = 0;
    let total_criteria = 7;

    if quantum_secure { eligible_criteria += 1; }
    if trust_score >= 0.5 { eligible_criteria += 1; }
    if *tier >= super::PeerTier::Tier2 { eligible_criteria += 1; }
    if stability_score >= 0.6 { eligible_criteria += 1; }
    if latency_ms <= 500 { eligible_criteria += 1; }
    if routing_capacity >= 10 { eligible_criteria += 1; }
    if now.saturating_sub(last_seen) <= 3600 { eligible_criteria += 1; }

    if eligible_criteria == total_criteria {
        RelayAdmissionStatus::eligible("All admission criteria met", now)
    } else if eligible_criteria >= total_criteria - 2 {
        let reason = format!(
            "Partial criteria met ({}/{}): quantum={}, trust={:.2}, tier={:?}, stability={:.2}, latency={}ms, capacity={}, fresh={}",
            eligible_criteria,
            total_criteria,
            quantum_secure,
            trust_score,
            tier,
            stability_score,
            latency_ms,
            routing_capacity,
            now.saturating_sub(last_seen) <= 3600,
        );
        RelayAdmissionStatus::probation(reason, now, now + 3600)
    } else {
        RelayAdmissionStatus::blocked(
            format!(
                "Insufficient criteria ({}/{}): quantum={}, trust={:.2}, tier={:?}, stability={:.2}, latency={}ms, capacity={}, fresh={}",
                eligible_criteria,
                total_criteria,
                quantum_secure,
                trust_score,
                tier,
                stability_score,
                latency_ms,
                routing_capacity,
                now.saturating_sub(last_seen) <= 3600,
            ),
            now,
            Some(now + 86400), // 24h temporary block
        )
    }
}
