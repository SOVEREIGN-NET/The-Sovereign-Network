use crate::types::relay_type::LongRangeRelayType;
use lib_crypto::PublicKey;
use serde::{Deserialize, Serialize};

/// Health state of a long-range relay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayHealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Long-range relay for extending mesh network reach
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LongRangeRelay {
    /// Relay identifier
    pub relay_id: String,
    /// Relay type (LoRaWAN, Satellite, Cellular)
    pub relay_type: LongRangeRelayType,
    /// Geographic coverage area
    pub coverage_radius_km: f64,
    /// Maximum throughput
    pub max_throughput_mbps: u32,
    /// Cost per MB for relay usage
    pub cost_per_mb_tokens: u64,
    /// Relay operator's public key
    pub operator: PublicKey,
    /// Revenue sharing percentage for UBI
    pub ubi_share_percentage: f32,
    /// Unix timestamp of last successful use
    pub last_used_at: u64,
    /// Total messages successfully routed through this relay
    pub total_messages_routed: u64,
    /// Consecutive routing failures
    pub consecutive_failures: u32,
    /// Consecutive routing successes
    pub consecutive_successes: u32,
    /// Average latency observed (ms)
    pub avg_latency_ms: u32,
    /// Health score 0.0–1.0 (derived from success/failure ratio)
    pub health_score: f32,
}

impl LongRangeRelay {
    /// Create a new relay with default health state
    pub fn new(
        relay_id: String,
        relay_type: LongRangeRelayType,
        coverage_radius_km: f64,
        max_throughput_mbps: u32,
        cost_per_mb_tokens: u64,
        operator: PublicKey,
        ubi_share_percentage: f32,
    ) -> Self {
        Self {
            relay_id,
            relay_type,
            coverage_radius_km,
            max_throughput_mbps,
            cost_per_mb_tokens,
            operator,
            ubi_share_percentage,
            last_used_at: 0,
            total_messages_routed: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            avg_latency_ms: 0,
            health_score: 1.0,
        }
    }

    /// Derive health state from score
    pub fn health_state(&self) -> RelayHealthState {
        if self.health_score >= 0.7 {
            RelayHealthState::Healthy
        } else if self.health_score >= 0.3 {
            RelayHealthState::Degraded
        } else {
            RelayHealthState::Unhealthy
        }
    }

    /// Update health after a successful routing
    pub fn record_success(&mut self, latency_ms: u32) {
        self.consecutive_successes += 1;
        self.consecutive_failures = 0;
        self.total_messages_routed += 1;
        self.last_used_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // EWMA for latency
        if self.avg_latency_ms == 0 {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = ((self.avg_latency_ms as f32 * 0.7) + (latency_ms as f32 * 0.3)) as u32;
        }
        // Health score = success ratio weighted by recency
        self.health_score = (self.health_score * 0.8 + 1.0 * 0.2).min(1.0);
    }

    /// Update health after a failed routing
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.consecutive_successes = 0;
        self.last_used_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Penalize health score; rapid consecutive failures drop it fast
        let penalty = 0.1 * self.consecutive_failures.min(5) as f32;
        self.health_score = (self.health_score - penalty).max(0.0);
    }
}
