//! ZhtpClient - Core QUIC client for all control-plane operations
//!
//! This client provides authenticated QUIC transport for all API calls.
//! It handles connection establishment, UHP handshake, and request/response framing.

use anyhow::{anyhow, Result, Context};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, debug, warn};

use quinn::{Endpoint, Connection, ClientConfig};

use lib_identity::ZhtpIdentity;
use lib_protocols::wire::{
    ZhtpRequestWire, ZhtpResponseWire,
    read_response, write_request,
};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod};

use crate::handshake::{HandshakeContext, NonceCache};
use crate::protocols::quic_handshake;
use crate::web4::trust::{TrustConfig, ZhtpTrustVerifier};

/// Configuration for ZhtpClient initialization
///
/// This struct allows explicit configuration of client behavior without
/// relying on environment variables, enabling safe operation in containerized
/// and WASM environments.
#[derive(Clone, Debug)]
pub struct ZhtpClientConfig {
    /// Allow bootstrap mode for development/testing
    /// When true, accepts any TLS certificate (INSECURE - dev only)
    pub allow_bootstrap: bool,
}

impl Default for ZhtpClientConfig {
    fn default() -> Self {
        Self {
            allow_bootstrap: false,
        }
    }
}

/// Authenticated QUIC client for ZHTP control-plane operations
///
/// This is the only transport allowed for mutating operations.
/// All CLI commands must use this client.
pub struct ZhtpClient {
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

    /// Trust verifier
    trust_verifier: Option<Arc<ZhtpTrustVerifier>>,

    /// Client configuration
    config: ZhtpClientConfig,
}

/// Connection with completed UHP+Kyber handshake
struct AuthenticatedConnection {
    /// QUIC connection
    quic_conn: Connection,

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
    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    /// Derive application-layer MAC key from master key
    ///
    /// MUST match server-side derivation in quic_api_dispatcher.rs.
    /// Label: "zhtp-web4-app-mac"
    /// Order: server_did (peer from client's view) then client_did
    fn derive_app_key(master_key: &[u8; 32], session_id: &[u8; 16], peer_did: &str, client_did: &str) -> [u8; 32] {
        let mut input = Vec::new();
        input.extend_from_slice(b"zhtp-web4-app-mac"); // Must match server
        input.extend_from_slice(master_key);
        input.extend_from_slice(session_id);
        input.extend_from_slice(peer_did.as_bytes());  // Server's DID
        input.extend_from_slice(client_did.as_bytes()); // Client's DID
        *blake3::hash(&input).as_bytes()
    }
}

impl ZhtpClient {
    /// Create a new ZHTP client with trust configuration and explicit config
    pub async fn new_with_config(
        identity: ZhtpIdentity,
        trust_config: TrustConfig,
        config: ZhtpClientConfig,
    ) -> Result<Self> {
        // Install rustls crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Create QUIC endpoint
        let endpoint = Endpoint::client("0.0.0.0:0".parse()?)
            .context("Failed to create QUIC endpoint")?;

        // Configure transport
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
        let transport = Arc::new(transport);

        // Create nonce cache
        let nonce_db_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zhtp")
            .join("client_nonce_cache");

        // Safely get parent directory, defaulting to current dir if path is malformed
        if let Some(parent) = nonce_db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let nonce_cache = NonceCache::open(&nonce_db_path, 3600, 10_000)
            .context("Failed to open nonce cache")?;

        let handshake_ctx = HandshakeContext::new(nonce_cache);

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

    /// Create a new ZHTP client with trust configuration (uses default config)
    pub async fn new(identity: ZhtpIdentity, trust_config: TrustConfig) -> Result<Self> {
        Self::new_with_config(identity, trust_config, ZhtpClientConfig::default()).await
    }

    /// Create client in bootstrap mode with explicit config (DEV ONLY - no TLS verification)
    pub async fn new_bootstrap_with_config(identity: ZhtpIdentity, config: ZhtpClientConfig) -> Result<Self> {
        if !config.allow_bootstrap {
            return Err(anyhow!(
                "Bootstrap mode requires ZhtpClientConfig::allow_bootstrap to be true"
            ));
        }
        warn!("ZHTP client in BOOTSTRAP MODE - NO TLS VERIFICATION");
        Self::new_with_config(identity, TrustConfig::bootstrap(), config).await
    }

    /// Create client in bootstrap mode (DEV ONLY - no TLS verification)
    ///
    /// Deprecated: Use `new_bootstrap_with_config()` with explicit config instead.
    /// This method is maintained for backwards compatibility.
    #[deprecated(since = "1.1.0", note = "Use new_bootstrap_with_config with explicit config")]
    pub async fn new_bootstrap(identity: ZhtpIdentity) -> Result<Self> {
        warn!("ZHTP client in BOOTSTRAP MODE - NO TLS VERIFICATION");
        let config = ZhtpClientConfig {
            allow_bootstrap: true,
        };
        Self::new_bootstrap_with_config(identity, config).await
    }

    /// Create client with TOFU (Trust On First Use)
    pub async fn new_tofu(identity: ZhtpIdentity) -> Result<Self> {
        let trustdb_path = TrustConfig::default_trustdb_path()?;
        Self::new(identity, TrustConfig::with_tofu(trustdb_path)).await
    }

    /// Create client with SPKI pinning
    pub async fn new_pinned(identity: ZhtpIdentity, spki_sha256: String) -> Result<Self> {
        Self::new(identity, TrustConfig::with_pin(spki_sha256)).await
    }

    /// Get the client's identity DID
    pub fn identity_did(&self) -> &str {
        &self.identity.did
    }

    /// Get the identity
    pub fn identity(&self) -> &ZhtpIdentity {
        &self.identity
    }

    /// Get the verified peer DID from current connection
    pub fn peer_did(&self) -> Option<&str> {
        self.connection.as_ref().map(|c| c.peer_did.as_str())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Check if in bootstrap mode
    pub fn is_bootstrap_mode(&self) -> bool {
        self.trust_config.bootstrap_mode
    }

    /// Connect to a ZHTP node
    pub async fn connect(&mut self, addr: &str) -> Result<()> {
        let socket_addr: SocketAddr = addr.parse()
            .context("Invalid server address")?;

        info!("Connecting to ZHTP node at {}", socket_addr);

        if self.trust_config.bootstrap_mode {
            if !self.config.allow_bootstrap {
                return Err(anyhow!(
                    "Bootstrap mode requires ZhtpClientConfig::allow_bootstrap to be true"
                ));
            }
            warn!("BOOTSTRAP MODE - TLS certificates not verified");
        }

        // Create trust verifier
        let verifier = Arc::new(ZhtpTrustVerifier::new(
            addr.to_string(),
            self.trust_config.clone(),
        )?);
        self.trust_verifier = Some(Arc::clone(&verifier));

        // Configure QUIC client
        let client_config = Self::configure_client(verifier)?;
        self.endpoint.set_default_client_config(client_config);

        // Establish QUIC connection
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
            app_key,
            peer_did,
            session_id: handshake_result.session_id,
            sequence: AtomicU64::new(0),
        });

        Ok(())
    }

    fn configure_client(verifier: Arc<ZhtpTrustVerifier>) -> Result<ClientConfig> {
        // Install crypto provider
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

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
        config.transport_config(Arc::new(transport));

        Ok(config)
    }

    /// Send a request and receive response
    pub async fn request(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to node"))?;

        // Mutations always require auth
        let is_mutation = matches!(request.method, ZhtpMethod::Post | ZhtpMethod::Put | ZhtpMethod::Delete);

        let wire_request = if is_mutation {
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

    /// Send a GET request
    pub async fn get(&self, path: &str) -> Result<ZhtpResponse> {
        let request = ZhtpRequest::get(path.to_string(), Some(self.identity.id.clone()))?;
        self.request(request).await
    }

    /// Send a POST request with JSON body
    pub async fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<ZhtpResponse> {
        let request = ZhtpRequest::post(
            path.to_string(),
            serde_json::to_vec(body)?,
            "application/json".to_string(),
            Some(self.identity.id.clone()),
        )?;
        self.request(request).await
    }

    /// Send a DELETE request
    pub async fn delete(&self, path: &str) -> Result<ZhtpResponse> {
        let request = ZhtpRequest::delete(path.to_string(), Some(self.identity.id.clone()))?;
        self.request(request).await
    }

    /// Close the connection gracefully
    pub async fn close(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.quic_conn.close(0u32.into(), b"client closed");
        }
    }

    /// Parse JSON response body
    pub fn parse_json<T: serde::de::DeserializeOwned>(response: &ZhtpResponse) -> Result<T> {
        if !response.status.is_success() {
            return Err(anyhow!(
                "Request failed: {} {}",
                response.status.code(),
                response.status_message
            ));
        }
        serde_json::from_slice(&response.body)
            .context("Failed to parse response JSON")
    }
}

impl Drop for ZhtpClient {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.quic_conn.close(0u32.into(), b"client dropped");
        }
    }
}
