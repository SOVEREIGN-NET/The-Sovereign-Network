//! HTTPS Gateway Server Implementation
//!
//! Provides HTTPS termination for browsers to access Web4 content.
//! Uses axum with rustls for TLS termination.

use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
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
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{RwLock, watch};
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, error};

use lib_network::{DomainRegistry, Web4ContentService, ZdnsResolver, ZdnsConfig};

use super::config::{GatewayTlsConfig, TlsMode};
use super::handlers::{gateway_handler, redirect_handler, health_handler, info_handler, GatewayState};

/// Rate limit configuration
const RATE_LIMIT_REQUESTS_PER_MINUTE: u32 = 100;
const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 60;
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Per-IP rate limiting state
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

    /// Check if an IP has exceeded the rate limit
    async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();

        // Clean up old entries (older than 1 minute)
        requests.retain(|_, (_, timestamp)| now.duration_since(*timestamp).as_secs() < 60);

        // Check/update this IP's count
        let entry = requests.entry(ip).or_insert((0, now));

        // Reset if window expired
        if now.duration_since(entry.1).as_secs() >= 60 {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;

        entry.0 <= RATE_LIMIT_REQUESTS_PER_MINUTE
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

        // Build rate limit state
        let rate_limit = RateLimitState::new();

        // Build CORS layer
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        // Build main router with rate limiting, body limits, and timeouts
        // Note: Layer order is bottom-up (first added = outermost layer)
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

        // Signal all servers to shutdown
        {
            let handles = self.server_handles.read().await;
            for handle in handles.iter() {
                handle.shutdown();
            }
            info!("  Sent shutdown signal to {} server(s)", handles.len());
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
}
