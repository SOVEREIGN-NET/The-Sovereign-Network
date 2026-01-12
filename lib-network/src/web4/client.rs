//! Web4 Client for CLI Deploy
//!
//! Authenticated QUIC client for deploying Web4 content.
//!
//! # Security Model
//!
//! The client uses a two-layer security model:
//! 1. **TLS layer**: SPKI pinning or TOFU for transport security
//! 2. **UHP layer**: Mutual authentication with Dilithium signatures + Kyber KEM
//!
//! Both layers must succeed before any API requests are sent.
//!
//! # Trust Modes
//!
//! - **Pinned**: `--pin-spki <hash>` - Require exact SPKI match
//! - **TOFU**: `--tofu` - Trust on first use, persist to ~/.zhtp/trustdb.json
//! - **Node DID**: `--node-did <did>` - Verify node identity after UHP handshake
//! - **Bootstrap**: `--trust-node` - Dev only, accept any cert (insecure)
//!
//! # AuthContext
//!
//! All mutating requests (POST/PUT/DELETE) include an AuthContext that:
//! - Binds the request to the UHP session
//! - Includes a sequence number for replay protection
//! - Contains a MAC over the request bytes

use anyhow::{anyhow, Result, Context};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::path::{Path, PathBuf};
use tracing::{info, debug, warn};
use uuid::Uuid;

use quinn::{Endpoint, Connection, ClientConfig};

use lib_identity::ZhtpIdentity;
use lib_protocols::wire::{
    ZhtpRequestWire,
    read_response, write_request,
};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod};

use crate::handshake::{HandshakeContext, NonceCache};
use crate::protocols::quic_handshake;

use super::trust::{TrustConfig, ZhtpTrustVerifier};

/// Configuration for Web4Client initialization
///
/// This struct allows explicit configuration of client behavior without
/// relying on environment variables or process IDs.
#[derive(Clone, Debug)]
pub struct Web4ClientConfig {
    /// Allow bootstrap mode for development/testing
    /// When true, accepts any TLS certificate (INSECURE - dev only)
    pub allow_bootstrap: bool,

    /// Custom cache directory for nonce storage.
    /// If None, uses a temporary directory with UUID-based naming.
    pub cache_dir: Option<PathBuf>,

    /// Unique session identifier for cache directory naming.
    /// If not specified, a new UUID is generated.
    pub session_id: Option<String>,
}

impl Default for Web4ClientConfig {
    fn default() -> Self {
        Self {
            allow_bootstrap: false,
            cache_dir: None,
            session_id: None,
        }
    }
}

/// Web4 client for authenticated QUIC communication
pub struct Web4Client {
    /// QUIC endpoint
    endpoint: Endpoint,

    /// Authenticated connection to node
    connection: Option<AuthenticatedConnection>,

    /// Client identity (for signing requests)
    identity: Arc<ZhtpIdentity>,

    /// Handshake context with nonce cache
    handshake_ctx: HandshakeContext,

    /// Trust configuration
    trust_config: TrustConfig,

    /// Trust verifier (stored for DID binding after handshake)
    trust_verifier: Option<Arc<ZhtpTrustVerifier>>,

    /// Client configuration
    config: Web4ClientConfig,
}

/// Connection with completed UHP+Kyber handshake
struct AuthenticatedConnection {
    /// QUIC connection
    quic_conn: Connection,

    /// Master key for symmetric encryption (from UHP handshake)
    master_key: [u8; 32],

    /// Application-layer MAC key (derived from master_key)
    app_key: [u8; 32],

    /// Peer's verified DID (from UHP handshake)
    peer_did: String,

    /// Session ID
    session_id: [u8; 16],

    /// Request sequence counter (for replay protection)
    sequence: AtomicU64,
}

impl AuthenticatedConnection {
    /// Get next sequence number
    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    /// Derive application-layer MAC key from master key
    fn derive_app_key(master_key: &[u8; 32], session_id: &[u8; 16], peer_did: &str, client_did: &str) -> [u8; 32] {
        // HKDF-style derivation using BLAKE3
        let mut input = Vec::new();
        input.extend_from_slice(b"zhtp-web4-app-mac");
        input.extend_from_slice(master_key);
        input.extend_from_slice(session_id);
        input.extend_from_slice(peer_did.as_bytes());
        input.extend_from_slice(client_did.as_bytes());
        lib_crypto::hash_blake3(&input)
    }
}

impl Web4Client {
    /// Create a new Web4 client with the given identity, trust config, and explicit config
    pub async fn new_with_trust_and_config(
        identity: ZhtpIdentity,
        trust_config: TrustConfig,
        config: Web4ClientConfig,
    ) -> Result<Self> {
        // Create QUIC endpoint (client-only, no listening)
        let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

        // Determine cache directory and session ID
        let session_id = config.session_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
        let cache_dir = if let Some(dir) = config.cache_dir.as_ref() {
            dir.clone()
        } else {
            // Use temp directory with UUID-based naming (not process ID)
            std::env::temp_dir().join(format!("web4_client_{}", session_id))
        };

        std::fs::create_dir_all(&cache_dir)?;
        // Derive network epoch from genesis hash (uses environment-appropriate fallback)
        let network_epoch = crate::handshake::NetworkEpoch::from_global_or_fail()?;
        let nonce_cache = NonceCache::open(&cache_dir.join("nonces"), 3600, 10_000, network_epoch)
            .context("Failed to create nonce cache")?;
        let handshake_ctx = HandshakeContext::new(nonce_cache);

        info!(
            node_id = ?identity.node_id,
            did = %identity.did,
            trust_mode = ?if trust_config.bootstrap_mode { "bootstrap" }
                         else if trust_config.allow_tofu { "tofu" }
                         else if trust_config.pin_spki.is_some() { "pinned" }
                         else { "strict" },
            "Web4 client initialized"
        );

        Ok(Self {
            endpoint,
            connection: None,
            identity: Arc::new(identity),
            handshake_ctx,
            trust_config,
            trust_verifier: None,
            config,
        })
    }

    /// Create a new Web4 client with the given identity and trust config (uses default config)
    pub async fn new_with_trust(identity: ZhtpIdentity, trust_config: TrustConfig) -> Result<Self> {
        Self::new_with_trust_and_config(identity, trust_config, Web4ClientConfig::default()).await
    }

    /// Create a new Web4 client with default trust (strict - requires pin or TOFU)
    ///
    /// This will fail to connect unless trust is established via:
    /// - `--pin-spki <hash>`
    /// - `--tofu` (with trustdb)
    /// - Or existing trustdb entry
    pub async fn new(identity: ZhtpIdentity) -> Result<Self> {
        let trustdb_path = TrustConfig::default_trustdb_path()?;
        let trust_config = TrustConfig {
            trustdb_path: Some(trustdb_path),
            ..Default::default()
        };
        Self::new_with_trust(identity, trust_config).await
    }

    /// Create a new Web4 client in bootstrap mode with explicit config (accepts any cert - DEV ONLY)
    ///
    /// WARNING: Bootstrap mode provides NO certificate verification.
    /// Use only for development or when connecting to known local nodes.
    pub async fn new_bootstrap_with_config(
        identity: ZhtpIdentity,
        config: Web4ClientConfig,
    ) -> Result<Self> {
        if !config.allow_bootstrap {
            return Err(anyhow!(
                "Bootstrap mode requires Web4ClientConfig::allow_bootstrap to be true"
            ));
        }
        warn!("Web4 client created in BOOTSTRAP MODE - NO TLS VERIFICATION");
        Self::new_with_trust_and_config(identity, TrustConfig::bootstrap(), config).await
    }

    /// Create a new Web4 client in bootstrap mode (accepts any cert - DEV ONLY)
    ///
    /// Deprecated: Use `new_bootstrap_with_config()` with explicit config instead.
    /// This method is maintained for backwards compatibility.
    ///
    /// WARNING: Bootstrap mode provides NO certificate verification.
    /// Use only for development or when connecting to known local nodes.
    #[deprecated(since = "1.1.0", note = "Use new_bootstrap_with_config with explicit config")]
    pub async fn new_bootstrap(identity: ZhtpIdentity) -> Result<Self> {
        warn!("Web4 client created in BOOTSTRAP MODE - NO TLS VERIFICATION");
        let config = Web4ClientConfig {
            allow_bootstrap: true,
            ..Default::default()
        };
        Self::new_bootstrap_with_config(identity, config).await
    }

    /// Create a new Web4 client with TOFU (Trust On First Use)
    ///
    /// The first connection to a new node will be accepted and stored.
    /// Subsequent connections require the same certificate.
    pub async fn new_tofu(identity: ZhtpIdentity) -> Result<Self> {
        let trustdb_path = TrustConfig::default_trustdb_path()?;
        Self::new_with_trust(identity, TrustConfig::with_tofu(trustdb_path)).await
    }

    /// Create a new Web4 client with SPKI pinning
    ///
    /// Only accepts connections to nodes with the exact SPKI hash.
    pub async fn new_pinned(identity: ZhtpIdentity, spki_sha256: String) -> Result<Self> {
        Self::new_with_trust(identity, TrustConfig::with_pin(spki_sha256)).await
    }

    /// Load identity from a keystore directory
    pub async fn from_keystore(keystore_path: &Path) -> Result<Self> {
        let identity = Self::load_identity_from_keystore(keystore_path)?;
        Self::new(identity).await
    }

    /// Load identity from keystore with specific trust config
    pub async fn from_keystore_with_trust(keystore_path: &Path, trust_config: TrustConfig) -> Result<Self> {
        let identity = Self::load_identity_from_keystore(keystore_path)?;
        Self::new_with_trust(identity, trust_config).await
    }

    fn load_identity_from_keystore(keystore_path: &Path) -> Result<ZhtpIdentity> {
        if !keystore_path.exists() {
            return Err(anyhow!("Keystore not found at {:?}", keystore_path));
        }

        let identity_path = keystore_path.join("identity.json");
        if identity_path.exists() {
            let identity_data = std::fs::read_to_string(&identity_path)?;
            let identity: ZhtpIdentity = serde_json::from_str(&identity_data)
                .context("Failed to parse identity.json")?;
            return Ok(identity);
        }

        Err(anyhow!("No identity.json found in keystore at {:?}", keystore_path))
    }

    /// Get the verified peer DID from the current connection
    pub fn peer_did(&self) -> Option<&str> {
        self.connection.as_ref().map(|c| c.peer_did.as_str())
    }

    /// Check if client is in bootstrap mode
    pub fn is_bootstrap_mode(&self) -> bool {
        self.trust_config.bootstrap_mode
    }

    /// Get the client's identity DID
    pub fn identity_did(&self) -> &str {
        &self.identity.did
    }

    /// Connect to a ZHTP node
    pub async fn connect(&mut self, addr: &str) -> Result<()> {
        let socket_addr: SocketAddr = addr.parse()
            .context("Invalid server address")?;

        info!("Connecting to ZHTP node at {}", socket_addr);

        if self.trust_config.bootstrap_mode {
            Self::ensure_bootstrap_allowed()?;
            warn!(
                "BOOTSTRAP MODE ENABLED - TLS certificates are not verified. Set ZHTP_ALLOW_BOOTSTRAP=1 intentionally."
            );
        }

        // Create trust verifier for this connection
        let verifier = Arc::new(ZhtpTrustVerifier::new(
            addr.to_string(),
            self.trust_config.clone(),
        )?);
        self.trust_verifier = Some(Arc::clone(&verifier));

        // Configure QUIC client with trust verifier
        let client_config = Self::configure_client(verifier)?;
        self.endpoint.set_default_client_config(client_config);

        // Establish QUIC connection (TLS handshake happens here)
        let connection = self.endpoint
            .connect(socket_addr, "zhtp-node")?
            .await
            .context("QUIC connection failed")?;

        info!("QUIC/TLS connection established");

        // Perform UHP+Kyber handshake
        let handshake_result = quic_handshake::handshake_as_initiator(
            &connection,
            &self.identity,
            &self.handshake_ctx,
        ).await.context("UHP+Kyber handshake failed")?;

        let peer_did = handshake_result.verified_peer.identity.did.clone();

        // Verify node DID matches trust configuration
        if let Some(ref verifier) = self.trust_verifier {
            verifier.verify_node_did(&peer_did)?;
            // Bind DID to trustdb for future connections
            if let Err(e) = verifier.bind_node_did(&peer_did) {
                warn!("Failed to bind node DID to trustdb: {}", e);
            }
        }

        // Derive application-layer MAC key
        let app_key = AuthenticatedConnection::derive_app_key(
            &handshake_result.master_key,
            &handshake_result.session_id,
            &peer_did,
            &self.identity.did,
        );

        info!(
            peer_did = %peer_did,
            session_id = ?hex::encode(&handshake_result.session_id[..8]),
            "Authenticated with node (PQC encryption active)"
        );

        self.connection = Some(AuthenticatedConnection {
            quic_conn: connection,
            master_key: handshake_result.master_key,
            app_key,
            peer_did,
            session_id: handshake_result.session_id,
            sequence: AtomicU64::new(0),
        });

        Ok(())
    }

    /// Ensure bootstrap mode is explicitly enabled via environment variable
    fn ensure_bootstrap_allowed() -> Result<()> {
        match std::env::var("ZHTP_ALLOW_BOOTSTRAP") {
            Ok(val) if val == "1" || val.eq_ignore_ascii_case("true") => Ok(()),
            _ => Err(anyhow!(
                "Bootstrap mode requires ZHTP_ALLOW_BOOTSTRAP environment variable to be set to \
                 an explicit enabling value. This mode is insecure and should only be used for \
                 development. Set ZHTP_ALLOW_BOOTSTRAP=1 or ZHTP_ALLOW_BOOTSTRAP=true to proceed \
                 at your own risk."
            ))
        }
    }

    /// Configure QUIC client with trust verifier
    fn configure_client(verifier: Arc<ZhtpTrustVerifier>) -> Result<ClientConfig> {
        // Install crypto provider for rustls 0.23+
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        // Configure ALPN for control plane operations (UHP handshake required)
        // This tells the server to expect UHP handshake before API requests
        crypto.alpn_protocols = crate::constants::client_control_plane_alpns();

        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        ));

        // Configure transport
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
        config.transport_config(Arc::new(transport));

        Ok(config)
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Send a request and receive response (internal - handles auth context)
    async fn send_request(&self, request: ZhtpRequest, require_auth: bool) -> Result<ZhtpResponse> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to node"))?;

        // Determine if this request needs authentication
        let is_mutation = matches!(request.method, ZhtpMethod::Post | ZhtpMethod::Put | ZhtpMethod::Delete);

        // Create wire request with auth context for mutations
        let wire_request = if is_mutation || require_auth {
            let seq = conn.next_sequence();
            ZhtpRequestWire::new_authenticated(
                request,
                conn.session_id,
                self.identity.did.clone(),
                seq,
                &conn.app_key,
            )
        } else {
            ZhtpRequestWire::new(request)
        };

        let request_id = wire_request.request_id;

        debug!(
            request_id = %wire_request.request_id_hex(),
            uri = %wire_request.request.uri,
            has_auth = wire_request.auth_context.is_some(),
            "Sending request"
        );

        // Open bidirectional stream
        let (mut send, mut recv) = conn.quic_conn.open_bi().await
            .context("Failed to open QUIC stream")?;

        // Send request
        write_request(&mut send, &wire_request).await
            .context("Failed to send request")?;

        // Finish sending
        send.finish()
            .context("Failed to finish send stream")?;

        // Read response
        let wire_response = read_response(&mut recv).await
            .context("Failed to read response")?;

        // Verify request ID matches
        if wire_response.request_id != request_id {
            return Err(anyhow!(
                "Response request_id mismatch: expected {}, got {}",
                hex::encode(request_id),
                wire_response.request_id_hex()
            ));
        }

        debug!(
            request_id = %wire_response.request_id_hex(),
            status = wire_response.status,
            "Received response"
        );

        Ok(wire_response.response)
    }

    /// Send a request (public API - auto-detects auth requirement)
    pub async fn request(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        self.send_request(request, false).await
    }

    /// Upload a blob and get its content ID
    pub async fn put_blob(&self, content: Vec<u8>, content_type: &str) -> Result<String> {
        let request = ZhtpRequest::post(
            "/api/v1/web4/content/blob".to_string(),
            content,
            content_type.to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to upload blob: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        // Parse content ID from response
        let result: serde_json::Value = serde_json::from_slice(&response.body)
            .context("Invalid JSON response")?;

        result.get("content_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Response missing content_id"))
    }

    /// Upload a manifest and get its content ID
    pub async fn put_manifest(&self, manifest: &serde_json::Value) -> Result<String> {
        let body = serde_json::to_vec(manifest)?;

        let request = ZhtpRequest::post(
            "/api/v1/web4/content/manifest".to_string(),
            body,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to upload manifest: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        let result: serde_json::Value = serde_json::from_slice(&response.body)?;

        result.get("manifest_cid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Response missing manifest_cid"))
    }

    /// Register a new domain
    pub async fn register_domain(
        &self,
        domain: &str,
        manifest_cid: &str,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "domain": domain,
            "manifest_cid": manifest_cid,
            "owner": self.identity.did.clone(),
        });

        let request = ZhtpRequest::post(
            "/api/v1/web4/domains/register".to_string(),
            serde_json::to_vec(&body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to register domain: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Publish/update a domain to point to new manifest
    pub async fn publish_domain(
        &self,
        domain: &str,
        manifest_cid: &str,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "domain": domain,
            "manifest_cid": manifest_cid,
        });

        let request = ZhtpRequest::post(
            format!("/api/v1/web4/domains/{}/publish", domain),
            serde_json::to_vec(&body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to publish domain: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Get domain info (no auth required for read)
    pub async fn get_domain(&self, domain: &str) -> Result<Option<serde_json::Value>> {
        let request = ZhtpRequest::get(
            format!("/api/v1/web4/domains/{}", domain),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, false).await?;

        if response.status.code() == 404 {
            return Ok(None);
        }

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to get domain: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        let result = serde_json::from_slice(&response.body)?;
        Ok(Some(result))
    }

    /// List all domains owned by the current identity
    pub async fn list_domains(&self) -> Result<Vec<serde_json::Value>> {
        let request = ZhtpRequest::get(
            format!("/api/v1/web4/domains?owner={}", self.identity.did),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, false).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to list domains: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        let result: serde_json::Value = serde_json::from_slice(&response.body)?;

        // Extract domains array from response
        if let Some(domains) = result.get("domains").and_then(|d| d.as_array()) {
            Ok(domains.clone())
        } else {
            Ok(Vec::new())
        }
    }

    // ========================================================================
    // Domain Versioning API
    // ========================================================================

    /// Get domain version status
    pub async fn get_domain_status(&self, domain: &str) -> Result<serde_json::Value> {
        let request = ZhtpRequest::get(
            format!("/api/v1/web4/domains/status/{}", domain),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, false).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to get domain status: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Get domain version history
    pub async fn get_domain_history(&self, domain: &str, limit: Option<usize>) -> Result<serde_json::Value> {
        let url = if let Some(limit) = limit {
            format!("/api/v1/web4/domains/history/{}?limit={}", domain, limit)
        } else {
            format!("/api/v1/web4/domains/history/{}", domain)
        };

        let request = ZhtpRequest::get(
            url,
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, false).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to get domain history: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Update domain with new manifest (atomic compare-and-swap)
    pub async fn update_domain(
        &self,
        domain: &str,
        new_manifest_cid: &str,
        expected_previous_cid: &str,
    ) -> Result<serde_json::Value> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let body = serde_json::json!({
            "domain": domain,
            "new_manifest_cid": new_manifest_cid,
            "expected_previous_manifest_cid": expected_previous_cid,
            "signature": "", // TODO: Sign with identity
            "timestamp": timestamp,
        });

        let request = ZhtpRequest::post(
            "/api/v1/web4/domains/update".to_string(),
            serde_json::to_vec(&body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to update domain: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Rollback domain to a previous version
    pub async fn rollback_domain(&self, domain: &str, to_version: u64) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "to_version": to_version,
        });

        let request = ZhtpRequest::post(
            format!("/api/v1/web4/domains/{}/rollback", domain),
            serde_json::to_vec(&body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to rollback domain: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Resolve domain to manifest (optionally at specific version)
    pub async fn resolve_domain(&self, domain: &str, version: Option<u64>) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "domain": domain,
            "version": version,
        });

        let request = ZhtpRequest::post(
            "/api/v1/web4/domains/resolve".to_string(),
            serde_json::to_vec(&body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, false).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to resolve domain: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Upload a blob with automatic chunking for large files
    ///
    /// Files smaller than `chunk_size` are uploaded directly.
    /// Larger files are split into chunks and assembled on the server.
    ///
    /// # Arguments
    /// * `content` - The file content to upload
    /// * `content_type` - MIME type
    /// * `chunk_size` - Size of each chunk (default: 1MB)
    ///
    /// # Returns
    /// The content ID (CID) of the uploaded blob
    pub async fn put_blob_chunked(
        &self,
        content: Vec<u8>,
        content_type: &str,
        chunk_size: Option<usize>,
    ) -> Result<String> {
        let chunk_size = chunk_size.unwrap_or(1024 * 1024); // Default 1MB chunks

        // Small files: upload directly
        if content.len() <= chunk_size {
            return self.put_blob(content, content_type).await;
        }

        info!(
            total_size = content.len(),
            chunk_size = chunk_size,
            num_chunks = (content.len() + chunk_size - 1) / chunk_size,
            "Starting chunked upload"
        );

        // Calculate total hash for integrity
        let total_hash = hex::encode(&lib_crypto::hash_blake3(&content)[..16]);

        // Initiate chunked upload session
        let session = self.initiate_chunked_upload(
            content.len(),
            chunk_size,
            content_type,
            &total_hash,
        ).await?;

        let upload_id = session.get("upload_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing upload_id in session response"))?
            .to_string();

        debug!(upload_id = %upload_id, "Chunked upload session created");

        // Upload each chunk
        let mut chunk_cids = Vec::new();
        for (i, chunk) in content.chunks(chunk_size).enumerate() {
            let chunk_hash = hex::encode(&lib_crypto::hash_blake3(chunk)[..16]);

            debug!(
                chunk_index = i,
                chunk_size = chunk.len(),
                chunk_hash = %chunk_hash,
                "Uploading chunk"
            );

            let cid = self.upload_chunk(&upload_id, i, chunk.to_vec(), &chunk_hash).await?;
            chunk_cids.push(cid);
        }

        // Finalize upload - assemble chunks into blob
        let final_cid = self.finalize_chunked_upload(&upload_id, &chunk_cids, &total_hash).await?;

        info!(
            upload_id = %upload_id,
            cid = %final_cid,
            "Chunked upload completed"
        );

        Ok(final_cid)
    }

    /// Initiate a chunked upload session
    async fn initiate_chunked_upload(
        &self,
        total_size: usize,
        chunk_size: usize,
        content_type: &str,
        total_hash: &str,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "total_size": total_size,
            "chunk_size": chunk_size,
            "content_type": content_type,
            "total_hash": total_hash,
            "num_chunks": (total_size + chunk_size - 1) / chunk_size,
        });

        let request = ZhtpRequest::post(
            "/api/v1/web4/content/upload/init".to_string(),
            serde_json::to_vec(&body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to initiate chunked upload: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Upload a single chunk
    async fn upload_chunk(
        &self,
        upload_id: &str,
        chunk_index: usize,
        chunk_data: Vec<u8>,
        chunk_hash: &str,
    ) -> Result<String> {
        // Include metadata in headers via query params
        let uri = format!(
            "/api/v1/web4/content/upload/{}/chunk/{}?hash={}",
            upload_id, chunk_index, chunk_hash
        );

        let request = ZhtpRequest::post(
            uri,
            chunk_data,
            "application/octet-stream".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to upload chunk {}: {} {}",
                chunk_index,
                response.status.code(),
                response.status_message
            ));
        }

        let result: serde_json::Value = serde_json::from_slice(&response.body)?;

        result.get("chunk_cid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Response missing chunk_cid"))
    }

    /// Finalize chunked upload - assemble chunks into final blob
    async fn finalize_chunked_upload(
        &self,
        upload_id: &str,
        chunk_cids: &[String],
        total_hash: &str,
    ) -> Result<String> {
        let body = serde_json::json!({
            "upload_id": upload_id,
            "chunk_cids": chunk_cids,
            "total_hash": total_hash,
        });

        let request = ZhtpRequest::post(
            format!("/api/v1/web4/content/upload/{}/finalize", upload_id),
            serde_json::to_vec(&body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, true).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to finalize chunked upload: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        let result: serde_json::Value = serde_json::from_slice(&response.body)?;

        result.get("content_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Response missing content_id"))
    }

    /// Resume a chunked upload
    ///
    /// Queries the server for upload status and continues from where it left off.
    pub async fn resume_chunked_upload(
        &self,
        upload_id: &str,
        content: Vec<u8>,
        chunk_size: usize,
    ) -> Result<String> {
        // Get upload status
        let status = self.get_upload_status(upload_id).await?;

        let total_chunks = status.get("num_chunks")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("Missing num_chunks"))? as usize;

        let uploaded_chunks: Vec<usize> = status.get("uploaded_chunks")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as usize)).collect())
            .unwrap_or_default();

        let total_hash = status.get("total_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing total_hash"))?;

        info!(
            upload_id = %upload_id,
            total_chunks = total_chunks,
            uploaded = uploaded_chunks.len(),
            remaining = total_chunks - uploaded_chunks.len(),
            "Resuming chunked upload"
        );

        // Upload missing chunks
        let mut chunk_cids: Vec<(usize, String)> = Vec::new();

        // Get existing CIDs
        if let Some(existing) = status.get("chunk_cids").and_then(|v| v.as_object()) {
            for (idx_str, cid) in existing {
                if let (Ok(idx), Some(cid_str)) = (idx_str.parse::<usize>(), cid.as_str()) {
                    chunk_cids.push((idx, cid_str.to_string()));
                }
            }
        }

        for (i, chunk) in content.chunks(chunk_size).enumerate() {
            if uploaded_chunks.contains(&i) {
                continue; // Already uploaded
            }

            let chunk_hash = hex::encode(&lib_crypto::hash_blake3(chunk)[..16]);
            let cid = self.upload_chunk(upload_id, i, chunk.to_vec(), &chunk_hash).await?;
            chunk_cids.push((i, cid));
        }

        // Sort by index and extract CIDs
        chunk_cids.sort_by_key(|(idx, _)| *idx);
        let ordered_cids: Vec<String> = chunk_cids.into_iter().map(|(_, cid)| cid).collect();

        // Finalize
        self.finalize_chunked_upload(upload_id, &ordered_cids, total_hash).await
    }

    /// Get status of a chunked upload
    async fn get_upload_status(&self, upload_id: &str) -> Result<serde_json::Value> {
        let request = ZhtpRequest::get(
            format!("/api/v1/web4/content/upload/{}/status", upload_id),
            Some(self.identity.id.clone()),
        )?;

        let response = self.send_request(request, false).await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to get upload status: {} {}",
                response.status.code(),
                response.status_message
            ));
        }

        serde_json::from_slice(&response.body)
            .context("Invalid JSON response")
    }

    /// Close the connection
    pub async fn close(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.quic_conn.close(0u32.into(), b"done");
            info!("Connection closed");
        }
    }
}

impl Drop for Web4Client {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.quic_conn.close(0u32.into(), b"client dropped");
        }
    }
}
