//! Ingress steering and load-balancing across relay peers.
//!
//! Gateway/bootstrap nodes use this module to distribute incoming mesh
//! routing traffic to relay-capable Tier2 peers instead of handling all
//! forwarding directly.

use crate::identity::unified_peer::UnifiedPeerId;
use crate::peer_registry::{PeerTier, SharedPeerRegistry};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Relay pool entry with runtime health metadata.
pub struct RelayPoolEntry {
    pub peer_id: UnifiedPeerId,
    pub did: String,
    pub state: Mutex<RelayState>,
    pub latency_ewma_ms: AtomicU64,
    pub consecutive_failures: AtomicU32,
    pub consecutive_successes: AtomicU32,
    pub in_flight: AtomicUsize,
    pub last_healthy: Mutex<Option<Instant>>,
    pub capacity_score: AtomicU64, // tokens per second capacity
}

/// Lifecycle state of a relay peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    Healthy,
    Degraded,
    Unhealthy,
    CircuitOpen,
}

impl RelayPoolEntry {
    fn new(peer_id: UnifiedPeerId, did: String) -> Self {
        Self {
            peer_id,
            did,
            state: Mutex::new(RelayState::Healthy),
            latency_ewma_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            in_flight: AtomicUsize::new(0),
            last_healthy: Mutex::new(Some(Instant::now())),
            capacity_score: AtomicU64::new(0),
        }
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn inc_in_flight(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_in_flight(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Load balancer for distributing mesh routing traffic across relay peers.
pub struct IngressSteering {
    registry: SharedPeerRegistry,
    relays: Arc<RwLock<Vec<Arc<RelayPoolEntry>>>>,
    rr_counter: AtomicUsize,
    config: SteeringConfig,
    /// Total messages steered to each relay (by DID).
    steered_counter: Mutex<HashMap<String, AtomicU64>>,
    /// Total circuit breaker open events.
    circuit_opens: AtomicU64,
    /// Total circuit breaker close (recovery) events.
    circuit_closes: AtomicU64,
}

/// Configuration for ingress steering.
#[derive(Debug, Clone)]
pub struct SteeringConfig {
    pub max_relay_peers: usize,
    pub health_check_interval_secs: u64,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_recovery_secs: u64,
    pub selection_policy: SelectionPolicy,
}

impl Default for SteeringConfig {
    fn default() -> Self {
        Self {
            max_relay_peers: 64,
            health_check_interval_secs: 10,
            circuit_breaker_threshold: 5,
            circuit_breaker_recovery_secs: 30,
            selection_policy: SelectionPolicy::WeightedLatency,
        }
    }
}

/// Relay selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionPolicy {
    RoundRobin,
    WeightedLatency,
    LeastConnections,
}

impl IngressSteering {
    /// Create a new ingress steering instance and discover initial relay peers.
    pub async fn new(registry: SharedPeerRegistry, config: SteeringConfig) -> Self {
        let steering = Self {
            registry,
            relays: Arc::new(RwLock::new(Vec::new())),
            rr_counter: AtomicUsize::new(0),
            config,
            steered_counter: Mutex::new(HashMap::new()),
            circuit_opens: AtomicU64::new(0),
            circuit_closes: AtomicU64::new(0),
        };
        steering.refresh_relays().await;
        steering
    }

    /// Re-query the registry for Tier2 peers, add new ones and remove stale entries.
    pub async fn refresh_relays(&self) {
        let registry = self.registry.read().await;
        let tier2_peers: Vec<_> = registry
            .peers_by_tier(PeerTier::Tier2)
            .filter(|e| e.authenticated && e.quantum_secure)
            .map(|e| (e.peer_id.clone(), e.peer_id.did().to_string()))
            .collect();
        drop(registry);

        let mut relays = self.relays.write().await;

        // Add new peers.
        for (peer_id, did) in &tier2_peers {
            if !relays.iter().any(|r| r.peer_id == *peer_id) {
                if relays.len() >= self.config.max_relay_peers {
                    warn!(
                        "Max relay peers reached ({}), skipping new peer {}",
                        self.config.max_relay_peers,
                        did
                    );
                    break;
                }
                relays.push(Arc::new(RelayPoolEntry::new(peer_id.clone(), did.clone())));
                debug!("Added relay peer {} to ingress pool", did);
            }
        }

        // Remove stale peers (no longer Tier2 or no longer in registry).
        let active_ids: std::collections::HashSet<_> =
            tier2_peers.iter().map(|(id, _)| id.clone()).collect();
        relays.retain(|r| active_ids.contains(&r.peer_id));

        info!(
            "Ingress steering pool refreshed: {} relays active",
            relays.len()
        );
    }

    /// Select a healthy relay for the given destination.
    pub async fn select_relay(
        &self,
        _destination: &UnifiedPeerId,
    ) -> Option<Arc<RelayPoolEntry>> {
        let relays = self.relays.read().await;
        if relays.is_empty() {
            return None;
        }

        // Filter out circuit-open and unhealthy peers.
        let mut candidates: Vec<Arc<RelayPoolEntry>> = Vec::new();
        for entry in relays.iter() {
            let state = *entry.state.lock().await;
            if state == RelayState::Healthy || state == RelayState::Degraded {
                candidates.push(Arc::clone(entry));
            }
        }
        drop(relays);

        if candidates.is_empty() {
            return None;
        }

        let selected = match self.config.selection_policy {
            SelectionPolicy::RoundRobin => {
                let idx =
                    self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Arc::clone(&candidates[idx])
            }
            SelectionPolicy::WeightedLatency => {
                // Lower latency = higher weight. Score = latency + penalty for inflight.
                let mut best = None;
                let mut best_score = u64::MAX;
                for entry in candidates {
                    let latency = entry.latency_ewma_ms.load(Ordering::Relaxed);
                    let inflight_penalty = entry.in_flight() as u64 * 10;
                    let score = if latency == 0 {
                        inflight_penalty
                    } else {
                        latency + inflight_penalty
                    };
                    if score < best_score {
                        best_score = score;
                        best = Some(entry);
                    }
                }
                best.expect("candidates is non-empty")
            }
            SelectionPolicy::LeastConnections => {
                let mut best = None;
                let mut best_inflight = usize::MAX;
                for entry in candidates {
                    let inflight = entry.in_flight();
                    if inflight < best_inflight {
                        best_inflight = inflight;
                        best = Some(entry);
                    }
                }
                best.expect("candidates is non-empty")
            }
        };

        selected.inc_in_flight();

        // Track telemetry.
        {
            let mut counters = self.steered_counter.lock().await;
            counters
                .entry(selected.did.clone())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }

        Some(selected)
    }

    /// Record a successful relay operation.
    pub async fn record_success(&self, peer_id: &UnifiedPeerId, latency_ms: u64) {
        let relays = self.relays.read().await;
        if let Some(entry) = relays.iter().find(|r| r.peer_id == *peer_id).cloned() {
            drop(relays);
            entry.dec_in_flight();
            entry.latency_ewma_ms.store(
                ewma(
                    entry.latency_ewma_ms.load(Ordering::Relaxed),
                    latency_ms,
                ),
                Ordering::Relaxed,
            );
            *entry.last_healthy.lock().await = Some(Instant::now());

            let state = *entry.state.lock().await;
            if state == RelayState::Degraded || state == RelayState::Unhealthy {
                let new_val =
                    entry.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
                if new_val >= 3 {
                    Self::transition_state(&entry, RelayState::Healthy, &self.circuit_closes)
                        .await;
                    entry.consecutive_failures.store(0, Ordering::Relaxed);
                }
            } else {
                entry.consecutive_failures.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Record a failed relay operation.
    pub async fn record_failure(&self, peer_id: &UnifiedPeerId) {
        let relays = self.relays.read().await;
        if let Some(entry) = relays.iter().find(|r| r.peer_id == *peer_id).cloned() {
            drop(relays);
            entry.dec_in_flight();
            entry.consecutive_successes.store(0, Ordering::Relaxed);
            let failures =
                entry.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

            let state = *entry.state.lock().await;
            match state {
                RelayState::Healthy | RelayState::Degraded => {
                    if failures >= self.config.circuit_breaker_threshold {
                        Self::transition_state(
                            &entry,
                            RelayState::CircuitOpen,
                            &self.circuit_opens,
                        )
                        .await;
                    } else if failures >= self.config.circuit_breaker_threshold.saturating_sub(2)
                    {
                        Self::transition_state(&entry, RelayState::Degraded, &self.circuit_opens)
                            .await;
                    }
                }
                RelayState::Unhealthy => {
                    Self::transition_state(
                        &entry,
                        RelayState::CircuitOpen,
                        &self.circuit_opens,
                    )
                    .await;
                }
                _ => {}
            }
        }
    }

    /// Start the background health-check loop.
    pub fn start_health_check_loop(self: &Arc<Self>) {
        let steering = Arc::clone(self);
        tokio::spawn(async move {
            let interval = Duration::from_secs(steering.config.health_check_interval_secs);
            loop {
                tokio::time::sleep(interval).await;
                steering.run_health_checks().await;
            }
        });
    }

    /// Run one sweep of health checks over all relay entries.
    async fn run_health_checks(&self) {
        self.refresh_relays().await;

        let relays = self.relays.read().await;
        let entries: Vec<Arc<RelayPoolEntry>> = relays.iter().map(Arc::clone).collect();
        drop(relays);

        for entry in entries {
            self.check_one(entry).await;
        }
    }

    async fn check_one(&self, entry: Arc<RelayPoolEntry>) {
        let now = Instant::now();

        // If circuit is open, check if recovery window has passed.
        {
            let state = *entry.state.lock().await;
            if state == RelayState::CircuitOpen {
                let last_healthy = *entry.last_healthy.lock().await;
                let recovery = Duration::from_secs(self.config.circuit_breaker_recovery_secs);
                if last_healthy.map_or(true, |t| now.duration_since(t) >= recovery) {
                    Self::transition_state(
                        &entry,
                        RelayState::Unhealthy,
                        &self.circuit_closes,
                    )
                    .await;
                    entry.consecutive_successes.store(0, Ordering::Relaxed);
                }
                return;
            }
        }

        // Probe: look up peer in registry and check recent metrics.
        let registry = self.registry.read().await;
        let probe_ok = if let Some(peer_entry) = registry.get(&entry.peer_id) {
            peer_entry.authenticated
                && peer_entry.quantum_secure
                && peer_entry.tier == PeerTier::Tier2
        } else {
            false
        };
        drop(registry);

        if probe_ok {
            entry.consecutive_failures.store(0, Ordering::Relaxed);
            let state = *entry.state.lock().await;
            if state == RelayState::Unhealthy || state == RelayState::Degraded {
                let new_val =
                    entry.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
                if new_val >= 3 {
                    Self::transition_state(&entry, RelayState::Healthy, &self.circuit_closes)
                        .await;
                }
            }
        } else {
            entry.consecutive_successes.store(0, Ordering::Relaxed);
            let failures =
                entry.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            let state = *entry.state.lock().await;
            match state {
                RelayState::Healthy => {
                    if failures
                        >= self.config.circuit_breaker_threshold.saturating_sub(2)
                    {
                        Self::transition_state(
                            &entry,
                            RelayState::Degraded,
                            &self.circuit_opens,
                        )
                        .await;
                    }
                }
                RelayState::Degraded => {
                    if failures >= self.config.circuit_breaker_threshold {
                        Self::transition_state(
                            &entry,
                            RelayState::CircuitOpen,
                            &self.circuit_opens,
                        )
                        .await;
                    }
                }
                RelayState::Unhealthy => {
                    Self::transition_state(
                        &entry,
                        RelayState::CircuitOpen,
                        &self.circuit_opens,
                    )
                    .await;
                }
                _ => {}
            }
        }
    }

    /// Determine whether a relay's circuit breaker is currently open.
    pub async fn is_circuit_open(&self, entry: &RelayPoolEntry) -> bool {
        let state = *entry.state.lock().await;
        state == RelayState::CircuitOpen
    }

    /// Get telemetry snapshot.
    pub async fn telemetry_snapshot(&self) -> IngressTelemetry {
        let steered = {
            let counters = self.steered_counter.lock().await;
            counters
                .iter()
                .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
                .collect()
        };
        IngressTelemetry {
            steered_messages: steered,
            circuit_opens: self.circuit_opens.load(Ordering::Relaxed),
            circuit_closes: self.circuit_closes.load(Ordering::Relaxed),
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    async fn transition_state(
        entry: &RelayPoolEntry,
        new_state: RelayState,
        counter: &AtomicU64,
    ) {
        let mut state_guard = entry.state.lock().await;
        if *state_guard != new_state {
            let old = format!("{:?}", *state_guard);
            let new_str = format!("{:?}", new_state);
            tracing::info!(
                relay = %entry.did,
                "Relay state transition: {} -> {}",
                old,
                new_str
            );
            *state_guard = new_state;
            if new_state == RelayState::CircuitOpen {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Telemetry snapshot for ingress steering.
#[derive(Debug, Clone, Default)]
pub struct IngressTelemetry {
    /// Messages steered to each relay (DID -> count).
    pub steered_messages: HashMap<String, u64>,
    /// Total circuit breaker open events.
    pub circuit_opens: u64,
    /// Total circuit breaker recovery events.
    pub circuit_closes: u64,
}

fn ewma(old: u64, new: u64) -> u64 {
    if old == 0 {
        new
    } else {
        ((old * 8) + (new * 2)) / 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn test_registry() -> SharedPeerRegistry {
        Arc::new(RwLock::new(crate::peer_registry::PeerRegistry::new()))
    }

    #[tokio::test]
    async fn test_select_relay_round_robin() {
        let registry = test_registry();
        let mut config = SteeringConfig::default();
        config.selection_policy = SelectionPolicy::RoundRobin;
        let steering = IngressSteering::new(registry, config).await;

        // Empty pool -> None
        let dest = crate::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(
            lib_crypto::PublicKey::new([1u8; 2592]),
        );
        assert!(steering.select_relay(&dest).await.is_none());
    }

    #[tokio::test]
    async fn test_record_failure_transitions_to_degraded() {
        let registry = test_registry();
        let config = SteeringConfig {
            circuit_breaker_threshold: 3,
            ..SteeringConfig::default()
        };
        let steering = IngressSteering::new(registry, config).await;

        let peer_id = crate::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(
            lib_crypto::PublicKey::new([2u8; 2592]),
        );
        let entry = Arc::new(RelayPoolEntry::new(peer_id.clone(), "did:test".to_string()));
        {
            let mut relays = steering.relays.write().await;
            relays.push(entry.clone());
        }

        assert_eq!(*entry.state.lock().await, RelayState::Healthy);
        steering.record_failure(&peer_id).await;
        assert_eq!(*entry.state.lock().await, RelayState::Degraded);
    }

    #[tokio::test]
    async fn test_record_success_promotes_degraded() {
        let registry = test_registry();
        let steering = IngressSteering::new(registry, SteeringConfig::default()).await;

        let peer_id = crate::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(
            lib_crypto::PublicKey::new([3u8; 2592]),
        );
        let entry = Arc::new(RelayPoolEntry::new(peer_id.clone(), "did:test".to_string()));
        {
            let mut relays = steering.relays.write().await;
            relays.push(entry.clone());
            *entry.state.lock().await = RelayState::Degraded;
        }

        entry.consecutive_successes.store(0, Ordering::Relaxed);
        steering.record_success(&peer_id, 10).await;
        steering.record_success(&peer_id, 10).await;
        assert_eq!(*entry.state.lock().await, RelayState::Degraded);
        steering.record_success(&peer_id, 10).await;
        assert_eq!(*entry.state.lock().await, RelayState::Healthy);
    }

    #[tokio::test]
    async fn test_telemetry_counters() {
        let registry = test_registry();
        let steering = IngressSteering::new(registry, SteeringConfig::default()).await;

        let peer_id = crate::identity::unified_peer::UnifiedPeerId::from_public_key_legacy(
            lib_crypto::PublicKey::new([4u8; 2592]),
        );
        let entry = Arc::new(RelayPoolEntry::new(peer_id.clone(), "did:relay".to_string()));
        {
            let mut relays = steering.relays.write().await;
            relays.push(entry.clone());
        }

        let _ = steering.select_relay(&peer_id).await;
        let telemetry = steering.telemetry_snapshot().await;
        assert_eq!(telemetry.steered_messages.get("did:relay"), Some(&1));
    }
}
