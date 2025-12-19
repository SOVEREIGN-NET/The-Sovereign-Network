//! HTTPS Gateway Server Implementation
//!
//! Provides HTTPS termination for browsers to access Web4 content.
//! Uses axum with rustls for TLS termination.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::{RwLock, watch};
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, error, debug};

use crate::web4_stub::{DomainRegistry, Web4ContentService, ZdnsResolver};

use super::config::{GatewayTlsConfig, TlsMode};
use super::handlers::{gateway_handler, redirect_handler, health_handler, info_handler, GatewayState};

/// Rate limit configuration
const RATE_LIMIT_REQUESTS_PER_MINUTE: u32 = 100;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 30; // Background cleanup interval
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// Maximum unique IPs to track in rate limiter (prevents memory exhaustion from spoofed sources)
const RATE_LIMIT_MAX_ENTRIES: usize = 10_000;

/// Per-IP rate limiting state with bounded size and background cleanup
///
/// Design: O(1) per-request hot path, O(n) cleanup in background task
/// - check_rate_limit() only does HashMap get/insert (O(1) amortized)
/// - Background task runs every 30s to evict expired entries
/// - Max 10k entries prevents memory exhaustion from IP spoofing
#[derive(Clone)]
struct RateLimitState {
    requests: Arc<RwLock<HashMap<IpAddr, (u32, Instant)>>>,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start background cleanup task with shutdown support
    /// Task will exit when shutdown signal is received
    fn start_cleanup_task(&self, mut shutdown_rx: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let requests = self.requests.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(RATE_LIMIT_CLEANUP_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut map = requests.write().await;
                        let before = map.len();
                        let now = Instant::now();
                        map.retain(|_, (_, timestamp)| now.duration_since(*timestamp).as_secs() < RATE_LIMIT_WINDOW_SECS);
                        let after = map.len();
                        if before != after {
                            debug!(
                                evicted = before - after,
                                remaining = after,
                                "Rate limiter cleanup"
                            );
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        debug!("Rate limiter cleanup task received shutdown signal");
                        break;
                    }
                }
            }
        })
    }

    /// Check if an IP has exceeded the rate limit - O(1) hot path
    /// Returns false if rate limit exceeded OR if map is full (rejects new IPs when at capacity)
    async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = Instant::now();

        // Fast path: check with read lock first
        {
            let requests = self.requests.read().await;
            if let Some((count, timestamp)) = requests.get(&ip) {
                // Check if window is still valid
                if now.duration_since(*timestamp).as_secs() < RATE_LIMIT_WINDOW_SECS {
                    // Need write lock to increment, but we know this IP exists
                    drop(requests);
                    return self.increment_existing(ip, now).await;
                }
                // Window expired - need write lock to reset
            }
        }

        // Slow path: need write lock for new entry or reset
        self.add_or_reset(ip, now).await
    }

    /// Increment counter for existing IP (already confirmed to exist with valid window)
    async fn increment_existing(&self, ip: IpAddr, now: Instant) -> bool {
        let mut requests = self.requests.write().await;
        if let Some(entry) = requests.get_mut(&ip) {
            // Re-check window in case of race
            if now.duration_since(entry.1).as_secs() >= RATE_LIMIT_WINDOW_SECS {
                entry.0 = 1;
                entry.1 = now;
                return true;
            }
            entry.0 += 1;
            return entry.0 <= RATE_LIMIT_REQUESTS_PER_MINUTE;
        }
        // Entry was removed between read and write - treat as new
        self.try_insert_new(&mut requests, ip, now)
    }

    /// Add new entry or reset expired one
    async fn add_or_reset(&self, ip: IpAddr, now: Instant) -> bool {
        let mut requests = self.requests.write().await;

        // Check if entry exists (might have been added since read lock)
        if let Some(entry) = requests.get_mut(&ip) {
            if now.duration_since(entry.1).as_secs() >= RATE_LIMIT_WINDOW_SECS {
                // Reset expired window
                entry.0 = 1;
                entry.1 = now;
                return true;
            }
            entry.0 += 1;
            return entry.0 <= RATE_LIMIT_REQUESTS_PER_MINUTE;
        }

        self.try_insert_new(&mut requests, ip, now)
    }

    /// Try to insert a new IP entry, respecting capacity limits
    fn try_insert_new(&self, requests: &mut HashMap<IpAddr, (u32, Instant)>, ip: IpAddr, now: Instant) -> bool {
        if requests.len() >= RATE_LIMIT_MAX_ENTRIES {
            warn!(
                ip = %ip,
                entries = requests.len(),
                "Rate limit map at capacity, rejecting new IP"
            );
            return false;
        }
        requests.insert(ip, (1, now));
        true
    }
}

/// Rate limiting middleware
async fn rate_limit_middleware(
    State(rate_limit): State<RateLimitState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let ip = addr.ip();

    if !rate_limit.check_rate_limit(ip).await {
        warn!(ip = %ip, "Rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "60")],
            "Rate limit exceeded. Please try again later.",
        ).into_response();
    }

    next.run(request).await
}

/// HSTS state for middleware
#[derive(Clone)]
struct HstsState {
    header_value: Option<String>,
}

impl HstsState {
    fn new(config: &GatewayTlsConfig) -> Self {
        let header_value = if config.mode != TlsMode::Disabled {
            Some(format!("max-age={}; includeSubDomains", config.hsts_max_age))
        } else {
            None
        };
        Self { header_value }
    }
}

/// HSTS middleware - adds Strict-Transport-Security header to ALL responses
async fn hsts_middleware(
    State(hsts): State<HstsState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    // Add HSTS header if TLS is enabled
    if let Some(ref hsts_value) = hsts.header_value {
        if let Ok(value) = axum::http::HeaderValue::from_str(hsts_value) {
            response.headers_mut().insert(
                axum::http::header::STRICT_TRANSPORT_SECURITY,
                value,
            );
        }
    }

    response
}

/// Server handle for graceful shutdown
struct ServerHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl ServerHandle {
    fn new() -> (Self, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (Self { shutdown_tx: tx }, rx)
    }

    fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// HTTPS Gateway Server for Web4 browser access
pub struct HttpsGateway {
    config: GatewayTlsConfig,
    content_service: Arc<Web4ContentService>,
    is_running: Arc<RwLock<bool>>,
    server_handles: Arc<RwLock<Vec<ServerHandle>>>,
    /// Background task handles (cleanup tasks, etc.) that should be aborted on shutdown
    background_tasks: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

impl HttpsGateway {
    /// Create a new HTTPS gateway with the given domain registry
    pub async fn new(
        registry: Arc<DomainRegistry>,
        config: GatewayTlsConfig,
    ) -> Result<Self> {
        config.validate().map_err(|e| anyhow::anyhow!(e))?;

        let content_service = Arc::new(Web4ContentService::new(registry));

        Ok(Self {
            config,
            content_service,
            is_running: Arc::new(RwLock::new(false)),
            server_handles: Arc::new(RwLock::new(Vec::new())),
            background_tasks: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create with ZDNS resolver for cached domain lookups
    pub async fn new_with_zdns(
        registry: Arc<DomainRegistry>,
        zdns_resolver: Arc<ZdnsResolver>,
        config: GatewayTlsConfig,
    ) -> Result<Self> {
        config.validate().map_err(|e| anyhow::anyhow!(e))?;

        let content_service = Arc::new(Web4ContentService::with_zdns(registry, zdns_resolver));

        Ok(Self {
            config,
            content_service,
            is_running: Arc::new(RwLock::new(false)),
            server_handles: Arc::new(RwLock::new(Vec::new())),
            background_tasks: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create with existing content service (for sharing with other handlers)
    pub fn with_content_service(
        content_service: Arc<Web4ContentService>,
        config: GatewayTlsConfig,
    ) -> Result<Self> {
        config.validate().map_err(|e| anyhow::anyhow!(e))?;

        Ok(Self {
            config,
            content_service,
            is_running: Arc::new(RwLock::new(false)),
            server_handles: Arc::new(RwLock::new(Vec::new())),
            background_tasks: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Start the HTTPS gateway server
    pub async fn start(&self) -> Result<()> {
        // Check if already running
        {
            let running = self.is_running.read().await;
            if *running {
                return Err(anyhow::anyhow!("Gateway already running"));
            }
        }

        // Clear any old handles and mark as running
        {
            let mut handles = self.server_handles.write().await;
            handles.clear();
        }
        {
            let mut tasks = self.background_tasks.write().await;
            // Abort any lingering background tasks from previous runs
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        *self.is_running.write().await = true;

        info!("Starting HTTPS Gateway...");
        info!("  TLS Mode: {:?}", self.config.mode);
        info!("  HTTPS Port: {}", self.config.https_port);
        if let Some(http_port) = self.config.http_port {
            info!("  HTTP Port: {} (redirect: {})", http_port, self.config.enable_http_redirect);
        }
        info!("  Gateway Suffix: '{}'", self.config.gateway_suffix);
        info!("  Bare Domains: {}", self.config.allow_bare_sovereign_domains);
        info!("  Rate Limit: {} req/min per IP", RATE_LIMIT_REQUESTS_PER_MINUTE);
        info!("  Max Body Size: {} MB", MAX_REQUEST_BODY_SIZE / 1024 / 1024);
        info!("  Request Timeout: {}s", REQUEST_TIMEOUT_SECS);

        // Build shared state
        let state = GatewayState {
            content_service: self.content_service.clone(),
            config: Arc::new(self.config.clone()),
        };

        // Build rate limit state and start background cleanup with shutdown support
        let rate_limit = RateLimitState::new();
        let (cleanup_handle, cleanup_shutdown_rx) = ServerHandle::new();
        let cleanup_task = rate_limit.start_cleanup_task(cleanup_shutdown_rx);
        {
            let mut handles = self.server_handles.write().await;
            handles.push(cleanup_handle);
        }
        {
            let mut tasks = self.background_tasks.write().await;
            tasks.push(cleanup_task);
        }
        debug!("  Rate limiter cleanup task started (interval: {}s)", RATE_LIMIT_CLEANUP_INTERVAL_SECS);

        // Build HSTS state
        let hsts = HstsState::new(&self.config);

        // Build CORS layer from configuration
        let cors = self.build_cors_layer();
        debug!("  CORS origins: {:?}", self.config.cors_origins);

        // Build main router with rate limiting, body limits, timeouts, and HSTS
        // Note: Layer order is bottom-up (first added = outermost layer)
        // HSTS middleware is outermost to ensure header is added to ALL responses
        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/info", get(info_handler))
            .fallback(gateway_handler)
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY_SIZE))
            .route_layer(middleware::from_fn_with_state(
                rate_limit.clone(),
                rate_limit_middleware,
            ))
            .route_layer(middleware::from_fn_with_state(
                hsts.clone(),
                hsts_middleware,
            ))
            .with_state(state.clone());

        // Start HTTPS server with graceful shutdown
        if self.config.mode != TlsMode::Disabled {
            let tls_config = self.build_tls_config().await?;
            let https_addr = SocketAddr::new(self.config.bind_addr, self.config.https_port);

            info!("  HTTPS listening on: {}", https_addr);

            let (handle, mut shutdown_rx) = ServerHandle::new();
            {
                let mut handles = self.server_handles.write().await;
                handles.push(handle);
            }

            let is_running = self.is_running.clone();
            let app_clone = app.clone();
            tokio::spawn(async move {
                let server = axum_server::bind_rustls(https_addr, tls_config)
                    .serve(app_clone.into_make_service_with_connect_info::<SocketAddr>());

                tokio::select! {
                    result = server => {
                        if let Err(e) = result {
                            error!("HTTPS server error: {}", e);
                            *is_running.write().await = false;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        info!("HTTPS server received shutdown signal");
                    }
                }
            });
        }

        // Start HTTP redirect server (optional) with graceful shutdown
        // Note: HTTP redirect server also includes HSTS middleware so first-touch
        // HTTP responses set HSTS and browsers will persist the upgrade policy.
        if let Some(http_port) = self.config.http_port {
            if self.config.enable_http_redirect && self.config.mode != TlsMode::Disabled {
                let http_addr = SocketAddr::new(self.config.bind_addr, http_port);
                let redirect_app = Router::new()
                    .route("/health", get(health_handler))
                    .fallback(redirect_handler)
                    .route_layer(middleware::from_fn_with_state(
                        rate_limit.clone(),
                        rate_limit_middleware,
                    ))
                    .route_layer(middleware::from_fn_with_state(
                        hsts.clone(),
                        hsts_middleware,
                    ))
                    .with_state(state);

                info!("  HTTP redirect listening on: {}", http_addr);

                let (handle, mut shutdown_rx) = ServerHandle::new();
                {
                    let mut handles = self.server_handles.write().await;
                    handles.push(handle);
                }

                tokio::spawn(async move {
                    let listener = match tokio::net::TcpListener::bind(http_addr).await {
                        Ok(l) => l,
                        Err(e) => {
                            error!("Failed to bind HTTP redirect listener: {}", e);
                            return;
                        }
                    };

                    let server = axum::serve(
                        listener,
                        redirect_app.into_make_service_with_connect_info::<SocketAddr>(),
                    );

                    tokio::select! {
                        result = server => {
                            if let Err(e) = result {
                                error!("HTTP redirect server error: {}", e);
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            info!("HTTP redirect server received shutdown signal");
                        }
                    }
                });
            } else if self.config.mode == TlsMode::Disabled {
                // HTTP-only mode (no TLS)
                let http_addr = SocketAddr::new(self.config.bind_addr, http_port);

                info!("  HTTP listening on: {} (TLS disabled)", http_addr);

                let (handle, mut shutdown_rx) = ServerHandle::new();
                {
                    let mut handles = self.server_handles.write().await;
                    handles.push(handle);
                }

                let is_running = self.is_running.clone();
                tokio::spawn(async move {
                    let listener = match tokio::net::TcpListener::bind(http_addr).await {
                        Ok(l) => l,
                        Err(e) => {
                            error!("Failed to bind HTTP listener: {}", e);
                            *is_running.write().await = false;
                            return;
                        }
                    };

                    let server = axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    );

                    tokio::select! {
                        result = server => {
                            if let Err(e) = result {
                                error!("HTTP server error: {}", e);
                                *is_running.write().await = false;
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            info!("HTTP server received shutdown signal");
                        }
                    }
                });
            }
        }

        info!("HTTPS Gateway started successfully");
        Ok(())
    }

    /// Stop the gateway server gracefully
    pub async fn stop(&self) {
        info!("Stopping HTTPS Gateway...");

        // Signal all servers and background tasks to shutdown
        {
            let handles = self.server_handles.read().await;
            for handle in handles.iter() {
                handle.shutdown();
            }
            info!("  Sent shutdown signal to {} server/task handle(s)", handles.len());
        }

        // Wait briefly for graceful shutdown, then abort any lingering background tasks
        tokio::time::sleep(Duration::from_millis(100)).await;
        {
            let mut tasks = self.background_tasks.write().await;
            let task_count = tasks.len();
            for task in tasks.drain(..) {
                task.abort();
            }
            if task_count > 0 {
                debug!("  Aborted {} background task(s)", task_count);
            }
        }

        // Clear handles and mark as stopped
        {
            let mut handles = self.server_handles.write().await;
            handles.clear();
        }
        *self.is_running.write().await = false;

        info!("HTTPS Gateway stopped");
    }

    /// Check if gateway is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Build TLS configuration from settings
    async fn build_tls_config(&self) -> Result<RustlsConfig> {
        match self.config.mode {
            TlsMode::StandardCa | TlsMode::PrivateCa => {
                // Load certificates from disk
                let cert_path = self.config.effective_cert_path();
                let key_path = self.config.effective_key_path();

                info!("Loading TLS certificates from:");
                info!("  Cert: {:?}", cert_path);
                info!("  Key:  {:?}", key_path);

                RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .context("Failed to load TLS certificates")
            }
            TlsMode::SelfSigned => {
                // Generate or load self-signed certificate
                let cert_path = self.config.effective_cert_path();
                let key_path = self.config.effective_key_path();

                if cert_path.exists() && key_path.exists() {
                    info!("Loading existing self-signed certificates from:");
                    info!("  Cert: {:?}", cert_path);
                    info!("  Key:  {:?}", key_path);

                    RustlsConfig::from_pem_file(&cert_path, &key_path)
                        .await
                        .context("Failed to load self-signed certificates")
                } else {
                    info!("Generating self-signed certificate...");
                    self.generate_self_signed_cert(&cert_path, &key_path)?;

                    RustlsConfig::from_pem_file(&cert_path, &key_path)
                        .await
                        .context("Failed to load generated certificates")
                }
            }
            TlsMode::Disabled => {
                Err(anyhow::anyhow!("Cannot build TLS config when TLS is disabled"))
            }
        }
    }

    /// Generate a self-signed certificate for development
    fn generate_self_signed_cert(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        use rcgen::{CertifiedKey, generate_simple_self_signed};

        // Ensure data directory exists
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Generate certificate with SANs
        let subject_alt_names = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "*.zhtp".to_string(),
            "*.sov".to_string(),
            "*.zhtp.localhost".to_string(),
            "*.sov.localhost".to_string(),
            format!("*{}", self.config.gateway_suffix),
        ];

        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)
            .context("Failed to generate self-signed certificate")?;

        // Save certificate
        fs::write(cert_path, cert.pem())?;
        info!("  Saved certificate to: {:?}", cert_path);

        // Save private key
        fs::write(key_path, key_pair.serialize_pem())?;
        info!("  Saved private key to: {:?}", key_path);

        // Set restrictive permissions on key file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(key_path, perms)?;
        }

        info!("Self-signed certificate generated successfully");
        info!("  WARNING: This certificate is for development only.");
        info!("  Browsers will show a security warning.");

        Ok(())
    }

    /// Get the gateway's HTTPS URL
    pub fn https_url(&self) -> String {
        let port = self.config.https_port;
        if port == 443 {
            format!("https://{}", self.config.bind_addr)
        } else {
            format!("https://{}:{}", self.config.bind_addr, port)
        }
    }

    /// Get the gateway's HTTP URL (if enabled)
    pub fn http_url(&self) -> Option<String> {
        self.config.http_port.map(|port| {
            if port == 80 {
                format!("http://{}", self.config.bind_addr)
            } else {
                format!("http://{}:{}", self.config.bind_addr, port)
            }
        })
    }

    /// Build CORS layer from configuration
    fn build_cors_layer(&self) -> CorsLayer {
        // Check if wildcard is configured
        let has_wildcard = self.config.cors_origins.iter().any(|o| o == "*");

        if has_wildcard {
            // Allow any origin
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        } else {
            // Parse configured origins
            let origins: Vec<_> = self.config.cors_origins
                .iter()
                .filter_map(|origin| origin.parse().ok())
                .collect();

            if origins.is_empty() {
                // Fallback to restrictive - no origins allowed
                warn!("No valid CORS origins configured, using restrictive policy");
                CorsLayer::new()
                    .allow_methods(Any)
                    .allow_headers(Any)
            } else {
                CorsLayer::new()
                    .allow_origin(origins)
                    .allow_methods(Any)
                    .allow_headers(Any)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rate_limit_allows_requests() {
        let rate_limit = RateLimitState::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First request should be allowed
        assert!(rate_limit.check_rate_limit(ip).await);

        // Requests up to limit should be allowed
        for _ in 1..RATE_LIMIT_REQUESTS_PER_MINUTE {
            assert!(rate_limit.check_rate_limit(ip).await);
        }
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_excess() {
        let rate_limit = RateLimitState::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Use up all requests
        for _ in 0..RATE_LIMIT_REQUESTS_PER_MINUTE {
            rate_limit.check_rate_limit(ip).await;
        }

        // Next request should be blocked
        assert!(!rate_limit.check_rate_limit(ip).await);
    }

    #[tokio::test]
    async fn test_rate_limit_max_entries() {
        let rate_limit = RateLimitState::new();

        // Fill up to max entries
        for i in 0..RATE_LIMIT_MAX_ENTRIES {
            let ip = IpAddr::V4(Ipv4Addr::new(
                ((i >> 24) & 0xFF) as u8,
                ((i >> 16) & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                (i & 0xFF) as u8,
            ));
            assert!(rate_limit.check_rate_limit(ip).await, "Entry {} should be allowed", i);
        }

        // New IP should be rejected when at capacity
        let new_ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
        assert!(!rate_limit.check_rate_limit(new_ip).await, "Should reject new IPs at capacity");
    }

    #[test]
    fn test_hsts_state_enabled() {
        let config = GatewayTlsConfig {
            mode: TlsMode::SelfSigned,
            hsts_max_age: 31536000,
            ..Default::default()
        };

        let hsts = HstsState::new(&config);
        assert!(hsts.header_value.is_some());
        assert_eq!(
            hsts.header_value.unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[test]
    fn test_hsts_state_disabled() {
        let config = GatewayTlsConfig {
            mode: TlsMode::Disabled,
            hsts_max_age: 31536000,
            ..Default::default()
        };

        let hsts = HstsState::new(&config);
        assert!(hsts.header_value.is_none());
    }

    #[test]
    fn test_hsts_state_production() {
        let config = GatewayTlsConfig {
            mode: TlsMode::StandardCa,
            hsts_max_age: 63072000, // 2 years
            ..Default::default()
        };

        let hsts = HstsState::new(&config);
        assert!(hsts.header_value.is_some());
        assert_eq!(
            hsts.header_value.unwrap(),
            "max-age=63072000; includeSubDomains"
        );
    }

    #[tokio::test]
    async fn test_cleanup_task_responds_to_shutdown() {
        let rate_limit = RateLimitState::new();
        let (handle, shutdown_rx) = ServerHandle::new();

        // Start the cleanup task
        let task = rate_limit.start_cleanup_task(shutdown_rx);

        // Give task time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Task should be running
        assert!(!task.is_finished());

        // Send shutdown signal
        handle.shutdown();

        // Task should complete within a reasonable time
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            task
        ).await;

        assert!(result.is_ok(), "Cleanup task should complete after shutdown signal");
    }
}
