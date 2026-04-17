//! Backend pool for gateway request routing.
//!
//! Maintains a set of healthy upstream validator/full-node backends,
//! performs background health checks, and selects the best backend
//! for each incoming request.

use crate::config::{BackendSelectionPolicy, GatewayConfig};
use crate::metrics::{log_pool_snapshot, log_state_transition, GatewayMetrics};
use anyhow::{anyhow, Context, Result};
use lib_identity::ZhtpIdentity;
use lib_network::web4::client::Web4ClientConfig;
use lib_network::web4::{TrustConfig, Web4Client};
use lib_protocols::types::ZhtpRequest;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Origin of a backend entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendSource {
    Static,
    Dynamic,
}

/// Lifecycle state of a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendState {
    Healthy,
    Unhealthy,
    HalfOpen,
    Quarantined,
}

/// A single upstream backend and its runtime metadata.
pub struct BackendEntry {
    pub addr: String,
    #[allow(dead_code)]
    pub source: BackendSource,
    pub state: Mutex<BackendState>,
    pub protocol_version: Mutex<Option<String>>,
    pub latency_ewma_ms: AtomicU64,
    pub consecutive_failures: AtomicU32,
    pub consecutive_successes: AtomicU32,
    pub in_flight: AtomicUsize,
    pub last_healthy: Mutex<Option<Instant>>,
    pub last_checked: Mutex<Option<Instant>>,
    pub cooldown_until: Mutex<Option<Instant>>,
    pub client: Arc<RwLock<Web4Client>>,
}

impl BackendEntry {
    fn new(addr: String, source: BackendSource, client: Web4Client) -> Self {
        Self {
            addr,
            source,
            state: Mutex::new(BackendState::Healthy),
            protocol_version: Mutex::new(None),
            latency_ewma_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            in_flight: AtomicUsize::new(0),
            last_healthy: Mutex::new(Some(Instant::now())),
            last_checked: Mutex::new(Some(Instant::now())),
            cooldown_until: Mutex::new(None),
            client: Arc::new(RwLock::new(client)),
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

/// Pool of upstream backends with health tracking and selection.
pub struct BackendPool {
    cfg: GatewayConfig,
    identity: Arc<ZhtpIdentity>,
    trust_config: TrustConfig,
    static_entries: Vec<Arc<BackendEntry>>,
    dynamic_entries: Arc<RwLock<HashMap<String, Arc<BackendEntry>>>>,
    rr_counter: AtomicUsize,
    metrics: GatewayMetrics,
}

impl BackendPool {
    /// Create a new pool and connect to all static backends.
    pub async fn new(
        cfg: GatewayConfig,
        identity: ZhtpIdentity,
        trust_config: TrustConfig,
    ) -> Result<Self> {
        let mut static_entries = Vec::new();
        let identity = Arc::new(identity);

        for addr in &cfg.static_backends {
            match Self::connect_backend(addr, &identity, &trust_config).await {
                Ok(client) => {
                    info!(addr = %addr, "Static backend connected");
                    static_entries.push(Arc::new(BackendEntry::new(
                        addr.clone(),
                        BackendSource::Static,
                        client,
                    )));
                }
                Err(e) => {
                    warn!(addr = %addr, error = %e, "Failed to connect to static backend on startup");
                    // Still add the entry so background health checks can retry.
                    static_entries.push(Arc::new(BackendEntry::new(
                        addr.clone(),
                        BackendSource::Static,
                        Self::dummy_client(addr, &identity, &trust_config).await?,
                    )));
                }
            }
        }

        if static_entries.is_empty() {
            return Err(anyhow!("No static backends configured"));
        }

        Ok(Self {
            cfg,
            identity,
            trust_config,
            static_entries,
            dynamic_entries: Arc::new(RwLock::new(HashMap::new())),
            rr_counter: AtomicUsize::new(0),
            metrics: GatewayMetrics::new(),
        })
    }

    /// Start background health-check and optional dynamic-discovery tasks.
    pub fn metrics_snapshot(&self) -> crate::metrics::MetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn start_background_tasks(
        self: &Arc<Self>,
        peer_registry: Option<lib_network::SharedPeerRegistry>,
    ) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let interval = Duration::from_millis(pool.cfg.health_check_interval_ms);
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = pool.run_health_checks().await {
                    warn!(error = %e, "Health check sweep failed");
                }
            }
        });

        if self.cfg.dynamic_backend_discovery {
            if let Some(registry) = peer_registry {
                let pool = Arc::clone(self);
                tokio::spawn(async move {
                    let interval = Duration::from_millis(pool.cfg.health_check_interval_ms * 2);
                    loop {
                        tokio::time::sleep(interval).await;
                        pool.run_dynamic_discovery(registry.clone()).await;
                    }
                });
            } else {
                warn!("dynamic_backend_discovery is enabled but no PeerRegistry was provided");
            }
        }
    }

    /// Pick the best healthy backend for the given request.
    pub async fn pick_backend(&self, _req: &ZhtpRequest) -> Result<Arc<BackendEntry>> {
        self.metrics.record_request();
        let max_in_flight = self.cfg.max_in_flight_per_backend;

        // Gather candidates from healthy dynamic and static backends.
        let mut candidates: Vec<Arc<BackendEntry>> = Vec::new();

        // 1. Healthy dynamic backends
        {
            let dynamic = self.dynamic_entries.read().await;
            for entry in dynamic.values() {
                if Self::is_routable(entry, max_in_flight).await {
                    candidates.push(Arc::clone(entry));
                }
            }
        }

        // 2. Healthy static backends
        for entry in &self.static_entries {
            if Self::is_routable(entry, max_in_flight).await {
                candidates.push(Arc::clone(entry));
            }
        }

        // 3. Half-open static backends (last resort)
        if candidates.is_empty() {
            for entry in &self.static_entries {
                let state = *entry.state.lock().await;
                if state == BackendState::HalfOpen && Self::is_past_cooldown(entry).await {
                    candidates.push(Arc::clone(entry));
                }
            }
        }

        if candidates.is_empty() {
            self.metrics.record_failure();
            return Err(anyhow!("No healthy backend available"));
        }

        let selected = match self.cfg.backend_selection {
            BackendSelectionPolicy::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Arc::clone(&candidates[idx])
            }
            BackendSelectionPolicy::LowestLatency | BackendSelectionPolicy::LeastInflight => {
                // Use unified scoring: lower latency + penalty for inflight.
                let mut best = None;
                let mut best_score = u64::MAX;
                for entry in candidates {
                    let score = entry.latency_ewma_ms.load(Ordering::Relaxed)
                        + (entry.in_flight() as u64 * 10);
                    if score < best_score {
                        best_score = score;
                        best = Some(entry);
                    }
                }
                best.expect("candidates is non-empty")
            }
        };

        selected.inc_in_flight();
        Ok(selected)
    }

    /// Report a successful request to a backend.
    pub async fn report_success(&self, addr: &str, latency_ms: u64) {
        self.metrics.record_success();
        if let Some(entry) = self.find_entry(addr).await {
            entry.dec_in_flight();
            entry.latency_ewma_ms.store(ewma(entry.latency_ewma_ms.load(Ordering::Relaxed), latency_ms), Ordering::Relaxed);
            *entry.last_healthy.lock().await = Some(Instant::now());
            *entry.last_checked.lock().await = Some(Instant::now());

            let state = *entry.state.lock().await;
            if state == BackendState::HalfOpen {
                let new_val = entry.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
                if new_val >= self.cfg.recovery_threshold {
                    Self::transition_state(&entry, BackendState::Healthy).await;
                    entry.consecutive_failures.store(0, Ordering::Relaxed);
                }
            } else if state == BackendState::Unhealthy {
                // Should not happen (unhealthy gets no traffic), but handle gracefully.
                Self::transition_state(&entry, BackendState::HalfOpen).await;
            } else {
                entry.consecutive_failures.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Report a retried request.
    pub fn record_retry(&self) {
        self.metrics.record_retry();
    }

    /// Report a failed request to a backend.
    pub async fn report_failure(&self, addr: &str) {
        self.metrics.record_failure();
        if let Some(entry) = self.find_entry(addr).await {
            entry.dec_in_flight();
            *entry.last_checked.lock().await = Some(Instant::now());
            entry.consecutive_successes.store(0, Ordering::Relaxed);
            let failures = entry.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

            let state = *entry.state.lock().await;
            match state {
                BackendState::Healthy => {
                    if failures >= self.cfg.unhealthy_threshold {
                        Self::transition_state(&entry, BackendState::Unhealthy).await;
                        *entry.cooldown_until.lock().await =
                            Some(Instant::now() + Duration::from_millis(self.cfg.cooldown_ms));
                    }
                }
                BackendState::HalfOpen => {
                    Self::transition_state(&entry, BackendState::Unhealthy).await;
                    *entry.cooldown_until.lock().await =
                        Some(Instant::now() + Duration::from_millis(self.cfg.cooldown_ms));
                }
                _ => {}
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    async fn run_dynamic_discovery(&self, peer_registry: lib_network::SharedPeerRegistry) {
        let registry = peer_registry.read().await;
        let candidates: Vec<_> = registry
            .all_peers()
            .filter(|p| p.authenticated && p.capabilities.is_backend_candidate())
            .filter_map(|p| {
                p.capabilities
                    .api_endpoint
                    .clone()
                    .map(|ep| (ep, p.capabilities.clone()))
            })
            .collect();
        drop(registry);

        for (addr, caps) in candidates {
            self.metrics.record_dynamic_candidate();
            let exists = {
                let dynamic = self.dynamic_entries.read().await;
                dynamic.contains_key(&addr)
            };
            if exists {
                continue;
            }

            info!(
                addr = %addr,
                node_type = ?caps.node_type,
                protocol_version = ?caps.protocol_version,
                "Discovered dynamic backend candidate"
            );

            match Self::connect_backend(&addr, &self.identity, &self.trust_config).await {
                Ok(client) => {
                    let entry = Arc::new(BackendEntry::new(
                        addr.clone(),
                        BackendSource::Dynamic,
                        client,
                    ));
                    *entry.state.lock().await = BackendState::Quarantined;
                    *entry.protocol_version.lock().await = caps.protocol_version.clone();

                    let mut dynamic = self.dynamic_entries.write().await;
                    dynamic.insert(addr, entry);
                }
                Err(e) => {
                    debug!(addr = %addr, error = %e, "Failed to connect to dynamic backend candidate");
                }
            }
        }

        self.log_pool_snapshot().await;
    }

    async fn run_health_checks(&self) -> Result<()> {
        // Check static backends.
        for entry in &self.static_entries {
            self.check_one(Arc::clone(entry)).await;
        }

        // Check dynamic backends.
        let dynamic: Vec<Arc<BackendEntry>> = {
            let map = self.dynamic_entries.read().await;
            map.values().map(Arc::clone).collect()
        };
        for entry in dynamic {
            self.check_one(entry).await;
        }

        Ok(())
    }

    async fn check_one(&self, entry: Arc<BackendEntry>) {
        let now = Instant::now();

        // State-driven gating.
        let state = *entry.state.lock().await;
        match state {
            BackendState::Unhealthy => {
                if !Self::is_past_cooldown(&entry).await {
                    return;
                }
                Self::transition_state(&entry, BackendState::HalfOpen).await;
                entry.consecutive_successes.store(0, Ordering::Relaxed);
            }
            BackendState::Quarantined => {
                // Allow probes so we can promote after repeated success.
            }
            _ => {}
        }

        let probe_result = Self::probe_backend(&entry, &self.identity, &self.trust_config).await;
        *entry.last_checked.lock().await = Some(now);

        let state = *entry.state.lock().await;
        match probe_result {
            Ok(latency_ms) => {
                entry.latency_ewma_ms.store(ewma(entry.latency_ewma_ms.load(Ordering::Relaxed), latency_ms), Ordering::Relaxed);
                entry.consecutive_failures.store(0, Ordering::Relaxed);
                *entry.last_healthy.lock().await = Some(now);

                if state == BackendState::HalfOpen {
                    let new_val = entry.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
                    if new_val >= self.cfg.recovery_threshold {
                        Self::transition_state(&entry, BackendState::Healthy).await;
                    }
                } else if state == BackendState::Quarantined {
                    let new_val = entry.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
                    if new_val >= self.cfg.recovery_threshold
                        && Self::is_quarantined_promotable(&entry).await
                    {
                        info!(addr = %entry.addr, "Promoting quarantined dynamic backend to Healthy");
                        Self::transition_state(&entry, BackendState::Healthy).await;
                        self.metrics.record_dynamic_promotion();
                    }
                }
            }
            Err(e) => {
                debug!(addr = %entry.addr, error = %e, "Health probe failed");
                entry.consecutive_successes.store(0, Ordering::Relaxed);
                let failures = entry.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

                if state == BackendState::Healthy {
                    if failures >= self.cfg.unhealthy_threshold {
                        Self::transition_state(&entry, BackendState::Unhealthy).await;
                        *entry.cooldown_until.lock().await =
                            Some(now + Duration::from_millis(self.cfg.cooldown_ms));
                    }
                } else if state == BackendState::HalfOpen {
                    Self::transition_state(&entry, BackendState::Unhealthy).await;
                    *entry.cooldown_until.lock().await =
                        Some(now + Duration::from_millis(self.cfg.cooldown_ms));
                }
            }
        }
    }

    /// Attempt a lightweight health probe.
    async fn probe_backend(
        entry: &BackendEntry,
        identity: &ZhtpIdentity,
        trust_config: &TrustConfig,
    ) -> Result<u64> {
        let start = Instant::now();

        // First try to send a lightweight request through the existing client.
        let existing_ok = {
            let client_guard = entry.client.read().await;
            let req = ZhtpRequest::get("/healthz".to_string(), Some(identity.id.clone()))?;
            match tokio::time::timeout(
                Duration::from_millis(2000),
                client_guard.request(req),
            )
            .await
            {
                Ok(Ok(resp)) => resp.status.is_success(),
                _ => false,
            }
        };

        if existing_ok {
            return Ok(start.elapsed().as_millis() as u64);
        }

        // Existing client failed; try to reconnect.
        let mut client_guard = entry.client.write().await;
        let new_client = Self::connect_backend(&entry.addr, identity, trust_config).await?;
        *client_guard = new_client;

        // Verify with a request after reconnect.
        let req = ZhtpRequest::get("/healthz".to_string(), Some(identity.id.clone()))?;
        let resp = tokio::time::timeout(Duration::from_millis(2000), client_guard.request(req))
            .await
            .map_err(|_| anyhow!("Health probe request timed out after reconnect"))?
            .context("Health probe request failed after reconnect")?;

        if !resp.status.is_success() {
            return Err(anyhow!(
                "Health probe returned non-success status: {}",
                resp.status.code()
            ));
        }

        Ok(start.elapsed().as_millis() as u64)
    }

    async fn connect_backend(
        addr: &str,
        identity: &ZhtpIdentity,
        trust_config: &TrustConfig,
    ) -> Result<Web4Client> {
        let client_config = Web4ClientConfig {
            allow_bootstrap: trust_config.bootstrap_mode,
            cache_dir: Some(crate::config::DaemonConfig::root_dir()?.join("client-cache")),
            session_id: Some(format!("gateway-backend-{}", addr.replace(['/', ':'], "_"))),
        };

        let mut client = if trust_config.bootstrap_mode {
            Web4Client::new_bootstrap_with_config(identity.clone(), client_config)
                .await
                .context("Failed to construct bootstrap Web4 client")?
        } else {
            Web4Client::new_with_trust_and_config(
                identity.clone(),
                trust_config.clone(),
                client_config,
            )
            .await
            .context("Failed to construct Web4 client")?
        };

        client
            .connect(addr)
            .await
            .with_context(|| format!("Failed to connect to backend {}", addr))?;
        Ok(client)
    }

    async fn dummy_client(addr: &str, identity: &ZhtpIdentity, trust_config: &TrustConfig) -> Result<Web4Client> {
        // Used for entries that failed initial connection so the struct is still valid.
        // The background health check will reconnect before any traffic is routed.
        let cache_dir = crate::config::DaemonConfig::root_dir()?
            .join("client-cache")
            .join(addr.replace(['/', ':'], "_"));
        let client_config = Web4ClientConfig {
            allow_bootstrap: trust_config.bootstrap_mode,
            cache_dir: Some(cache_dir),
            session_id: Some(format!("gateway-dummy-{}", addr.replace(['/', ':'], "_"))),
        };
        if trust_config.bootstrap_mode {
            Web4Client::new_bootstrap_with_config(identity.clone(), client_config)
                .await
                .context("Failed to construct dummy bootstrap client")
        } else {
            Web4Client::new_with_trust_and_config(
                identity.clone(),
                trust_config.clone(),
                client_config,
            )
            .await
            .context("Failed to construct dummy client")
        }
    }

    async fn is_routable(entry: &BackendEntry, max_in_flight: usize) -> bool {
        let state = *entry.state.lock().await;
        state == BackendState::Healthy
            && Self::is_past_cooldown(entry).await
            && entry.in_flight() < max_in_flight
    }

    async fn is_past_cooldown(entry: &BackendEntry) -> bool {
        match *entry.cooldown_until.lock().await {
            Some(until) => Instant::now() >= until,
            None => true,
        }
    }

    async fn is_quarantined_promotable(entry: &BackendEntry) -> bool {
        // Simple protocol-version check: if the peer advertises a version, it must be non-empty.
        // In production this can be expanded to a semver compatibility matrix.
        let pv = entry.protocol_version.lock().await;
        match &*pv {
            Some(v) => !v.is_empty(),
            None => true, // No version advertised == no version gate
        }
    }

    async fn transition_state(entry: &BackendEntry, new_state: BackendState) {
        let mut state_guard = entry.state.lock().await;
        if *state_guard != new_state {
            let old = format!("{:?}", *state_guard);
            let new_str = format!("{:?}", new_state);
            log_state_transition(&entry.addr, &old, &new_str);
            *state_guard = new_state;
        }
    }

    pub async fn healthy_count(&self) -> usize {
        let dynamic = self.dynamic_entries.read().await;
        let mut count = 0usize;
        for entry in self.static_entries.iter().chain(dynamic.values()) {
            if *entry.state.lock().await == BackendState::Healthy {
                count += 1;
            }
        }
        count
    }

    async fn log_pool_snapshot(&self) {
        let (static_total, dynamic_total, healthy, unhealthy, half_open, quarantined) = {
            let dynamic = self.dynamic_entries.read().await;
            let mut healthy = 0usize;
            let mut unhealthy = 0usize;
            let mut half_open = 0usize;
            let mut quarantined = 0usize;

            for entry in self.static_entries.iter().chain(dynamic.values()) {
                match *entry.state.lock().await {
                    BackendState::Healthy => healthy += 1,
                    BackendState::Unhealthy => unhealthy += 1,
                    BackendState::HalfOpen => half_open += 1,
                    BackendState::Quarantined => quarantined += 1,
                }
            }

            (self.static_entries.len(), dynamic.len(), healthy, unhealthy, half_open, quarantined)
        };

        log_pool_snapshot(static_total, dynamic_total, healthy, unhealthy, half_open, quarantined);
    }

    async fn find_entry(&self, addr: &str) -> Option<Arc<BackendEntry>> {
        for entry in &self.static_entries {
            if entry.addr == addr {
                return Some(Arc::clone(entry));
            }
        }
        self.dynamic_entries.read().await.get(addr).map(Arc::clone)
    }
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

    fn test_identity() -> ZhtpIdentity {
        ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            "test-device",
            Some([0u8; 64]),
        )
        .expect("test identity")
    }

    fn test_gateway_config(backends: Vec<String>) -> GatewayConfig {
        GatewayConfig {
            static_backends: backends,
            backend_selection: BackendSelectionPolicy::LowestLatency,
            retry_idempotent_requests: false,
            ..GatewayConfig::default()
        }
    }

    fn unique_root() -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string();
        std::env::temp_dir().join(format!("zhtp-daemon-test-{}", unique))
    }

    async fn test_pool(backends: Vec<String>) -> BackendPool {
        let root = unique_root();
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("ZHTP_DAEMON_ROOT_DIR", &root);
        let identity = test_identity();
        let cfg = test_gateway_config(backends);
        let trust = TrustConfig::bootstrap();
        BackendPool::new(cfg, identity, trust).await.expect("pool")
    }

    use std::sync::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn pick_backend_prefers_lowest_score() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pool = test_pool(vec!["a:1".to_string(), "b:1".to_string()]).await;

        pool.static_entries[0]
            .latency_ewma_ms
            .store(100, Ordering::Relaxed);
        pool.static_entries[1]
            .latency_ewma_ms
            .store(10, Ordering::Relaxed);

        let dummy_req = ZhtpRequest::get("/".to_string(), None).unwrap();
        let picked = pool.pick_backend(&dummy_req).await.unwrap();
        assert_eq!(picked.addr, "b:1");
        picked.dec_in_flight(); // balance the inc from pick
    }

    #[tokio::test]
    async fn report_failure_moves_healthy_to_unhealthy() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pool = test_pool(vec!["a:1".to_string()]).await;
        let threshold = pool.cfg.unhealthy_threshold;

        for _ in 0..threshold - 1 {
            pool.report_failure("a:1").await;
        }
        assert_eq!(*pool.static_entries[0].state.lock().await, BackendState::Healthy);

        pool.report_failure("a:1").await;
        assert_eq!(*pool.static_entries[0].state.lock().await, BackendState::Unhealthy);
        assert!(pool.static_entries[0].cooldown_until.lock().await.is_some());
    }

    #[tokio::test]
    async fn report_success_promotes_halfopen_to_healthy() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pool = test_pool(vec!["a:1".to_string()]).await;
        let threshold = pool.cfg.recovery_threshold;

        *pool.static_entries[0].state.lock().await = BackendState::HalfOpen;
        pool.static_entries[0].consecutive_successes.store(0, Ordering::Relaxed);

        for _ in 0..threshold - 1 {
            pool.report_success("a:1", 10).await;
        }
        assert_eq!(*pool.static_entries[0].state.lock().await, BackendState::HalfOpen);

        pool.report_success("a:1", 10).await;
        assert_eq!(*pool.static_entries[0].state.lock().await, BackendState::Healthy);
        assert_eq!(pool.static_entries[0].consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn metrics_counters_increment() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pool = test_pool(vec!["a:1".to_string()]).await;
        let before = pool.metrics.snapshot();

        let dummy_req = ZhtpRequest::get("/".to_string(), None).unwrap();
        let _ = pool.pick_backend(&dummy_req).await.unwrap();
        pool.report_success("a:1", 10).await;
        pool.report_failure("a:1").await;
        pool.record_retry();

        let after = pool.metrics.snapshot();
        assert_eq!(after.requests_total, before.requests_total + 1);
        assert_eq!(after.requests_success, before.requests_success + 1);
        assert_eq!(after.requests_failure, before.requests_failure + 1);
        assert_eq!(after.retries_total, before.retries_total + 1);
    }
}
