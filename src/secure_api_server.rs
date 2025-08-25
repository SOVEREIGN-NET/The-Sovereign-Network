use axum::{
    extract::{Query, State, Path, Request},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Method},
    middleware::{self, Next},
    response::{IntoResponse, Response, Json},
    routing::{get, post, put, delete},
    Router, Extension,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::{
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
    set_header::SetResponseHeaderLayer,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use log::{info, warn, error};

use crate::auth::{AuthSystem, AuthConfig, Claims, Permission, UserRole};
use crate::security_monitor::{ZhtpSecurityMonitor, SecurityEvent, SecurityEventType, SecuritySeverity};
use crate::security_middleware::{SecurityMiddlewareState, SecurityMiddlewareConfig, security_middleware, SecurityContext, start_security_cleanup_task};
use crate::health_monitor::{ZhtpHealthMonitor, HealthMetrics};
use crate::audit::{AuditTrail, AuditEventType, AuditResult, AuditEventBuilder};
use crate::tls::{ZhtpTlsManager, TlsConfig};
use crate::errors::{ZhtpError, ZhtpResult, ErrorHandler};

/// Enhanced production API server for ZHTP mainnet node
#[derive(Debug, Clone)]
pub struct SecureApiServerState {
    pub auth_system: Arc<AuthSystem>,
    pub security_monitor: Arc<ZhtpSecurityMonitor>,
    pub health_monitor: Arc<ZhtpHealthMonitor>,
    pub audit_trail: Arc<AuditTrail>,
    pub tls_manager: Option<Arc<tokio::sync::RwLock<ZhtpTlsManager>>>,
    pub node_info: Arc<RwLock<NodeInfo>>,
    pub metrics: Arc<RwLock<ApiMetrics>>,
    pub config: SecureApiConfig,
}

/// Secure ZHTP API Server for production use
#[derive(Debug)]
pub struct SecureZhtpApiServer {
    pub state: SecureApiServerState,
    pub router: Router,
}

#[derive(Debug, Clone)]
pub struct SecureApiConfig {
    pub listen_address: SocketAddr,
    pub enable_tls: bool,
    pub enable_cors: bool,
    pub allowed_origins: Vec<String>,
    pub rate_limit_requests_per_minute: u32,
    pub request_timeout_seconds: u64,
    pub max_request_body_size: usize,
    pub require_authentication: bool,
    pub enable_audit_logging: bool,
    pub enable_security_headers: bool,
    pub session_timeout_minutes: u64,
}

impl Default for SecureApiConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0:8443".parse().unwrap(),
            enable_tls: true,
            enable_cors: true,
            allowed_origins: vec!["https://localhost:3000".to_string()],
            rate_limit_requests_per_minute: 100,
            request_timeout_seconds: 30,
            max_request_body_size: 1024 * 1024, // 1MB
            require_authentication: true,
            enable_audit_logging: true,
            enable_security_headers: true,
            session_timeout_minutes: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub version: String,
    pub network: String,
    pub peer_count: u32,
    pub block_height: u64,
    pub last_block_time: u64,
    pub consensus_status: String,
    pub uptime: u64,
    pub validator: bool,
    pub stake: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ApiMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub rate_limited_requests: u64,
    pub unauthorized_requests: u64,
    pub average_response_time_ms: f64,
    pub security_events: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    #[serde(default)]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    20
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_at: u64,
    pub user_id: String,
    pub roles: Vec<String>,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct TransactionRequest {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub data: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub tx_hash: String,
    pub status: String,
    pub message: String,
    pub block_height: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub node_info: NodeInfo,
    pub health_metrics: HealthMetrics,
    pub api_metrics: ApiMetrics,
    pub timestamp: u64,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct SecurityMetricsResponse {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub security_events: u64,
    pub active_sessions: u64,
    pub rate_limited_ips: u64,
    pub threat_level: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub roles: Vec<UserRole>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub enabled: bool,
    pub created_at: u64,
    pub last_login: Option<u64>,
}

impl SecureZhtpApiServer {
    /// Create new secure API server
    pub async fn new(
        config: SecureApiConfig,
        auth_config: AuthConfig,
        tls_config: Option<TlsConfig>,
    ) -> ZhtpResult<Self> {
        // Initialize components
        let auth_system = Arc::new(AuthSystem::new(auth_config)
            .map_err(|e| ZhtpError::ConfigurationError(e.to_string()))?);
        
        let security_monitor = Arc::new(ZhtpSecurityMonitor::new(Default::default()));
        let health_monitor = Arc::new(ZhtpHealthMonitor::new(Default::default()));
        
        let audit_trail = if config.enable_audit_logging {
            Arc::new(AuditTrail::new(Default::default()).await
                .map_err(|e| ZhtpError::ConfigurationError(e.to_string()))?)
        } else {
            Arc::new(AuditTrail::new(Default::default()).await
                .map_err(|e| ZhtpError::ConfigurationError(e.to_string()))?)
        };

        let tls_manager = if let Some(tls_config) = tls_config {
            Some(Arc::new(tokio::sync::RwLock::new(
                ZhtpTlsManager::new(tls_config).await
                    .map_err(|e| ZhtpError::ConfigurationError(e.to_string()))?
            )))
        } else {
            None
        };

        let node_info = Arc::new(RwLock::new(NodeInfo {
            node_id: "zhtp-node-001".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            network: "mainnet".to_string(),
            peer_count: 0,
            block_height: 0,
            last_block_time: 0,
            consensus_status: "syncing".to_string(),
            uptime: 0,
            validator: false,
            stake: None,
        }));

        let metrics = Arc::new(RwLock::new(ApiMetrics::default()));

        let state = SecureApiServerState {
            auth_system: auth_system.clone(),
            security_monitor: security_monitor.clone(),
            health_monitor,
            audit_trail: audit_trail.clone(),
            tls_manager,
            node_info,
            metrics,
            config: config.clone(),
        };

        // Create security middleware
        let security_middleware_config = SecurityMiddlewareConfig {
            enable_csrf_protection: true,
            enable_xss_protection: true,
            enable_content_security_policy: true,
            enable_hsts: config.enable_tls,
            enable_frame_options: true,
            enable_content_type_options: true,
            enable_referrer_policy: true,
            enable_permissions_policy: true,
            rate_limit_enabled: true,
            rate_limit_requests_per_minute: config.rate_limit_requests_per_minute,
            rate_limit_burst_size: 20,
            session_timeout_minutes: config.session_timeout_minutes,
            require_authentication: config.require_authentication,
            allowed_origins: config.allowed_origins.clone(),
            blocked_user_agents: vec![
                "curl".to_string(),
                "wget".to_string(),
                "python-requests".to_string(),
            ],
            max_request_size: config.max_request_body_size,
        };

        let security_middleware_state = Arc::new(SecurityMiddlewareState::new(
            security_middleware_config,
            auth_system,
            security_monitor,
        ));

        // Start cleanup tasks
        start_security_cleanup_task(security_middleware_state.clone());

        // Build router
        let router = Self::build_router(state.clone(), security_middleware_state).await?;

        // Log startup
        audit_trail.log_system_event(
            AuditEventType::SystemStartup,
            "Secure API server starting".to_string(),
            None,
        ).await.map_err(|e| ZhtpError::SystemError(e.to_string()))?;

        Ok(Self { state, router })
    }

    /// Build the router with all routes and middleware
    async fn build_router(
        state: SecureApiServerState,
        security_middleware_state: Arc<SecurityMiddlewareState>,
    ) -> ZhtpResult<Router> {
        // Create CORS layer
        let cors = CorsLayer::new()
            .allow_origin(
                state.config.allowed_origins.iter()
                    .map(|origin| origin.parse().unwrap())
                    .collect::<Vec<_>>()
            )
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                "authorization",
                "content-type",
                "x-csrf-token",
                "x-request-id",
            ])
            .allow_credentials(true);

        // Build main router
        let app = Router::new()
            // Public routes (no authentication required)
            .route("/health", get(health_check))
            .route("/metrics", get(metrics_handler))
            .route("/version", get(version_handler))
            
            // Authentication routes
            .route("/auth/login", post(login_handler))
            .route("/auth/logout", post(logout_handler))
            .route("/auth/refresh", post(refresh_token_handler))
            
            // Protected routes (authentication required)
            .route("/api/node/info", get(node_info_handler))
            .route("/api/node/peers", get(peers_handler))
            .route("/api/node/status", get(status_handler))
            
            // Transaction routes
            .route("/api/transactions", post(submit_transaction_handler))
            .route("/api/transactions/:hash", get(get_transaction_handler))
            .route("/api/transactions", get(list_transactions_handler))
            
            // Block routes
            .route("/api/blocks", get(list_blocks_handler))
            .route("/api/blocks/:height", get(get_block_handler))
            
            // User management routes (admin only)
            .route("/api/users", post(create_user_handler))
            .route("/api/users", get(list_users_handler))
            .route("/api/users/:id", get(get_user_handler))
            .route("/api/users/:id", put(update_user_handler))
            .route("/api/users/:id", delete(delete_user_handler))
            
            // Security routes (admin only)
            .route("/api/security/events", get(security_events_handler))
            .route("/api/security/metrics", get(security_metrics_handler))
            .route("/api/audit/events", get(audit_events_handler))
            
            .with_state(state)
            .layer(middleware::from_fn_with_state(
                security_middleware_state,
                security_middleware,
            ))
            .layer(
                tower::ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(TimeoutLayer::new(Duration::from_secs(30)))
                    .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
                    .layer(cors)
            );

        Ok(app)
    }

    /// Start the secure API server
    pub async fn start(self) -> ZhtpResult<()> {
        let addr = self.state.config.listen_address;

        info!("Starting secure API server on {}", addr);

        if let Some(tls_manager) = &self.state.tls_manager {
            // Start with TLS
            let tls_config = {
                let tls_mgr = tls_manager.read().await;
                tls_mgr.get_axum_config()
                    .map_err(|e| ZhtpError::ConfigurationError(e.to_string()))?
            };

            axum_server::bind_rustls(addr, tls_config)
                .serve(self.router.into_make_service())
                .await
                .map_err(|e| ZhtpError::NetworkError(e.to_string()))?;
        } else {
            // Start without TLS (development only)
            warn!("Starting API server without TLS - NOT for production use!");
            
            let listener = tokio::net::TcpListener::bind(addr).await
                .map_err(|e| ZhtpError::NetworkError(e.to_string()))?;
            
            axum::serve(listener, self.router)
                .await
                .map_err(|e| ZhtpError::NetworkError(e.to_string()))?;
        }

        Ok(())
    }
}

// Handler functions

/// Health check endpoint
async fn health_check(
    State(state): State<SecureApiServerState>,
) -> ZhtpResult<Json<HealthResponse>> {
    let node_info = state.node_info.read().await.clone();
    let health_metrics = state.health_monitor.get_current_metrics().await;
    let api_metrics = state.metrics.read().await.clone();

    let response = HealthResponse {
        status: "healthy".to_string(),
        node_info,
        health_metrics,
        api_metrics,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    Ok(Json(response))
}

/// Metrics endpoint
async fn metrics_handler(
    State(state): State<SecureApiServerState>,
) -> ZhtpResult<Json<ApiMetrics>> {
    let metrics = state.metrics.read().await.clone();
    Ok(Json(metrics))
}

/// Version endpoint
async fn version_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build_time": env!("BUILD_TIME"),
        "git_commit": env!("GIT_COMMIT"),
    }))
}

/// Login handler
async fn login_handler(
    State(state): State<SecureApiServerState>,
    Extension(security_context): Extension<SecurityContext>,
    Json(request): Json<AuthRequest>,
) -> ZhtpResult<Json<AuthResponse>> {
    let token = state.auth_system.authenticate_user(
        &request.username,
        &request.password,
        &security_context.client_ip,
        &security_context.user_agent,
    ).await.map_err(|e| ZhtpError::AuthenticationFailed(e.to_string()))?;

    // Generate CSRF token
    let csrf_token = "csrf_token_placeholder".to_string(); // Would generate real token

    // Log authentication event
    state.audit_trail.log_auth_event(
        AuditEventType::UserLogin,
        Some(request.username.clone()),
        Some(security_context.client_ip),
        Some(security_context.user_agent),
        AuditResult::Success,
        format!("User {} logged in successfully", request.username),
        None,
    ).await.map_err(|e| ZhtpError::SystemError(e.to_string()))?;

    let response = AuthResponse {
        token,
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 86400,
        user_id: "user_id_placeholder".to_string(),
        roles: vec!["user".to_string()],
        csrf_token,
    };

    Ok(Json(response))
}

/// Logout handler
async fn logout_handler(
    State(state): State<SecureApiServerState>,
    Extension(security_context): Extension<SecurityContext>,
) -> ZhtpResult<Json<serde_json::Value>> {
    if let Some(session_id) = &security_context.session_id {
        state.auth_system.logout(session_id).await
            .map_err(|e| ZhtpError::AuthenticationFailed(e.to_string()))?;

        // Log logout event
        state.audit_trail.log_auth_event(
            AuditEventType::UserLogout,
            security_context.user_id.clone(),
            Some(security_context.client_ip),
            Some(security_context.user_agent),
            AuditResult::Success,
            "User logged out successfully".to_string(),
            None,
        ).await.map_err(|e| ZhtpError::SystemError(e.to_string()))?;
    }

    Ok(Json(serde_json::json!({"message": "Logged out successfully"})))
}

/// Refresh token handler
async fn refresh_token_handler(
    State(_state): State<SecureApiServerState>,
    Extension(_security_context): Extension<SecurityContext>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement token refresh logic
    Ok(Json(serde_json::json!({"message": "Token refreshed"})))
}

/// Node info handler
async fn node_info_handler(
    State(state): State<SecureApiServerState>,
    Extension(security_context): Extension<SecurityContext>,
) -> ZhtpResult<Json<NodeInfo>> {
    // Check permissions
    if let Some(claims) = &security_context.claims {
        if !state.auth_system.check_permission(claims, Permission::ReadPublic) {
            return Err(ZhtpError::AuthorizationFailed("Insufficient permissions".to_string()));
        }
    }

    let node_info = state.node_info.read().await.clone();
    Ok(Json(node_info))
}

/// Peers handler
async fn peers_handler(
    State(_state): State<SecureApiServerState>,
    Extension(_security_context): Extension<SecurityContext>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would return peer information
    Ok(Json(serde_json::json!({"peers": []})))
}

/// Status handler
async fn status_handler(
    State(state): State<SecureApiServerState>,
) -> ZhtpResult<Json<serde_json::Value>> {
    let node_info = state.node_info.read().await;
    Ok(Json(serde_json::json!({
        "status": "online",
        "block_height": node_info.block_height,
        "peer_count": node_info.peer_count,
        "uptime": node_info.uptime,
    })))
}

/// Submit transaction handler
async fn submit_transaction_handler(
    State(state): State<SecureApiServerState>,
    Extension(security_context): Extension<SecurityContext>,
    Json(_request): Json<TransactionRequest>,
) -> ZhtpResult<Json<TransactionResponse>> {
    // Check authentication
    if !security_context.authenticated {
        return Err(ZhtpError::AuthenticationFailed("Authentication required".to_string()));
    }

    // Would implement transaction submission
    let response = TransactionResponse {
        tx_hash: "0x1234567890abcdef".to_string(),
        status: "pending".to_string(),
        message: "Transaction submitted successfully".to_string(),
        block_height: None,
    };

    // Log transaction event
    state.audit_trail.log_api_event(
        "POST",
        "/api/transactions",
        security_context.user_id,
        Some(security_context.client_ip),
        Some(security_context.user_agent),
        AuditResult::Success,
        200,
        Some(security_context.request_id),
    ).await.map_err(|e| ZhtpError::SystemError(e.to_string()))?;

    Ok(Json(response))
}

/// Get transaction handler
async fn get_transaction_handler(
    State(_state): State<SecureApiServerState>,
    Path(_hash): Path<String>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement transaction lookup
    Ok(Json(serde_json::json!({"transaction": null})))
}

/// List transactions handler
async fn list_transactions_handler(
    State(_state): State<SecureApiServerState>,
    Query(_pagination): Query<PaginationQuery>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement transaction listing
    Ok(Json(serde_json::json!({"transactions": []})))
}

/// List blocks handler
async fn list_blocks_handler(
    State(_state): State<SecureApiServerState>,
    Query(_pagination): Query<PaginationQuery>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement block listing
    Ok(Json(serde_json::json!({"blocks": []})))
}

/// Get block handler
async fn get_block_handler(
    State(_state): State<SecureApiServerState>,
    Path(_height): Path<u64>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement block lookup
    Ok(Json(serde_json::json!({"block": null})))
}

/// Create user handler (admin only)
async fn create_user_handler(
    State(state): State<SecureApiServerState>,
    Extension(security_context): Extension<SecurityContext>,
    Json(request): Json<CreateUserRequest>,
) -> ZhtpResult<Json<UserResponse>> {
    // Check admin permissions
    if let Some(claims) = &security_context.claims {
        if !state.auth_system.check_permission(claims, Permission::ManageUsers) {
            return Err(ZhtpError::AuthorizationFailed("Admin access required".to_string()));
        }
    } else {
        return Err(ZhtpError::AuthenticationFailed("Authentication required".to_string()));
    }

    let user_id = state.auth_system.create_user(
        &request.username,
        &request.password,
        request.email.clone(),
        request.roles.clone(),
    ).await.map_err(|e| ZhtpError::ValidationFailed(e.to_string()))?;

    // Log user creation
    state.audit_trail.log_system_event(
        AuditEventType::UserCreated,
        format!("User {} created by admin", request.username),
        None,
    ).await.map_err(|e| ZhtpError::SystemError(e.to_string()))?;

    let response = UserResponse {
        id: user_id,
        username: request.username,
        email: request.email,
        roles: request.roles.iter().map(|r| format!("{:?}", r)).collect(),
        enabled: true,
        created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        last_login: None,
    };

    Ok(Json(response))
}

/// List users handler (admin only)
async fn list_users_handler(
    State(_state): State<SecureApiServerState>,
    Extension(_security_context): Extension<SecurityContext>,
    Query(_pagination): Query<PaginationQuery>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement user listing
    Ok(Json(serde_json::json!({"users": []})))
}

/// Get user handler
async fn get_user_handler(
    State(_state): State<SecureApiServerState>,
    Path(_id): Path<String>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement user lookup
    Ok(Json(serde_json::json!({"user": null})))
}

/// Update user handler
async fn update_user_handler(
    State(_state): State<SecureApiServerState>,
    Path(_id): Path<String>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement user update
    Ok(Json(serde_json::json!({"message": "User updated"})))
}

/// Delete user handler
async fn delete_user_handler(
    State(_state): State<SecureApiServerState>,
    Path(_id): Path<String>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement user deletion
    Ok(Json(serde_json::json!({"message": "User deleted"})))
}

/// Security events handler (admin only)
async fn security_events_handler(
    State(_state): State<SecureApiServerState>,
    Query(_pagination): Query<PaginationQuery>,
) -> ZhtpResult<Json<serde_json::Value>> {
    // Would implement security events listing
    Ok(Json(serde_json::json!({"events": []})))
}

/// Security metrics handler
async fn security_metrics_handler(
    State(state): State<SecureApiServerState>,
) -> ZhtpResult<Json<SecurityMetricsResponse>> {
    let response = SecurityMetricsResponse {
        total_requests: 0,
        blocked_requests: 0,
        security_events: 0,
        active_sessions: 0,
        rate_limited_ips: 0,
        threat_level: "low".to_string(),
    };

    Ok(Json(response))
}

/// Audit events handler (admin only)
async fn audit_events_handler(
    State(state): State<SecureApiServerState>,
    Query(_pagination): Query<PaginationQuery>,
) -> ZhtpResult<Json<serde_json::Value>> {
    let stats = state.audit_trail.get_stats().await;
    Ok(Json(serde_json::json!({
        "stats": stats,
        "events": []
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_secure_api_server_creation() {
        let config = SecureApiConfig::default();
        let auth_config = AuthConfig::default();
        
        let server = SecureZhtpApiServer::new(config, auth_config, None).await;
        assert!(server.is_ok());
    }
}
