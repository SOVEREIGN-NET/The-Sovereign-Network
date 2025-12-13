//! Web4 Client for CLI Deploy
//!
//! Authenticated QUIC client for deploying Web4 content.
//!
//! # Usage
//!
//! ```rust,ignore
//! let client = Web4Client::new(identity).await?;
//! client.connect("127.0.0.1:9334").await?;
//!
//! // Upload content
//! let cid = client.put_blob(content).await?;
//!
//! // Register domain
//! client.register_domain("myapp.zhtp", manifest_cid).await?;
//! ```

use anyhow::{anyhow, Result, Context};
use std::net::SocketAddr;
use std::sync::Arc;
use std::path::Path;
use tracing::{info, debug};

use quinn::{Endpoint, Connection, ClientConfig};
use rustls::pki_types::CertificateDer;

use lib_identity::ZhtpIdentity;
use lib_protocols::wire::{
    ZhtpRequestWire, ZhtpResponseWire,
    read_response, write_request,
};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse};

use crate::handshake::{HandshakeContext, NonceCache};
use crate::protocols::quic_handshake;

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
}

/// Connection with completed UHP+Kyber handshake
struct AuthenticatedConnection {
    /// QUIC connection
    quic_conn: Connection,

    /// Master key for symmetric encryption
    #[allow(dead_code)]
    master_key: [u8; 32],

    /// Peer's verified identity
    #[allow(dead_code)]
    peer_did: String,

    /// Session ID
    #[allow(dead_code)]
    session_id: [u8; 16],
}

impl Web4Client {
    /// Create a new Web4 client with the given identity
    pub async fn new(identity: ZhtpIdentity) -> Result<Self> {
        // Create QUIC endpoint (client-only, no listening)
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

        // Configure client TLS (allow self-signed for dev)
        let client_config = Self::configure_client()?;
        endpoint.set_default_client_config(client_config);

        // Create nonce cache in temp directory (for CLI single-use)
        let temp_dir = std::env::temp_dir().join(format!("web4_client_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir)?;
        let nonce_cache = NonceCache::open(&temp_dir.join("nonces"), 3600, 10_000)
            .context("Failed to create nonce cache")?;
        let handshake_ctx = HandshakeContext::new(nonce_cache);

        info!(
            node_id = ?identity.node_id,
            did = %identity.did,
            "Web4 client initialized"
        );

        Ok(Self {
            endpoint,
            connection: None,
            identity: Arc::new(identity),
            handshake_ctx,
        })
    }

    /// Load identity from a keystore directory
    ///
    /// Expects the keystore to contain identity.json or similar files
    pub async fn from_keystore(keystore_path: &Path) -> Result<Self> {
        // For now, create a new ephemeral identity if keystore doesn't exist
        // In production, this would load from encrypted keystore
        if !keystore_path.exists() {
            return Err(anyhow!("Keystore not found at {:?}", keystore_path));
        }

        // Try to load identity.json from keystore
        let identity_path = keystore_path.join("identity.json");
        if identity_path.exists() {
            let identity_data = std::fs::read_to_string(&identity_path)?;
            let identity: ZhtpIdentity = serde_json::from_str(&identity_data)
                .context("Failed to parse identity.json")?;
            return Self::new(identity).await;
        }

        Err(anyhow!("No identity.json found in keystore at {:?}", keystore_path))
    }

    /// Configure QUIC client (allow self-signed certs for development)
    fn configure_client() -> Result<ClientConfig> {
        // Create crypto config that allows self-signed certs
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        ));

        // Configure transport
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
        config.transport_config(Arc::new(transport));

        Ok(config)
    }

    /// Connect to a ZHTP node
    pub async fn connect(&mut self, addr: &str) -> Result<()> {
        let socket_addr: SocketAddr = addr.parse()
            .context("Invalid server address")?;

        info!("Connecting to ZHTP node at {}", socket_addr);

        // Establish QUIC connection
        let connection = self.endpoint
            .connect(socket_addr, "zhtp-node")?
            .await
            .context("QUIC connection failed")?;

        info!("QUIC connection established");

        // Perform UHP+Kyber handshake
        let handshake_result = quic_handshake::handshake_as_initiator(
            &connection,
            &self.identity,
            &self.handshake_ctx,
        ).await.context("UHP+Kyber handshake failed")?;

        info!(
            peer_did = %handshake_result.peer_identity.did,
            session_id = ?hex::encode(&handshake_result.session_id[..8]),
            "Authenticated with node (PQC encryption active)"
        );

        self.connection = Some(AuthenticatedConnection {
            quic_conn: connection,
            master_key: handshake_result.master_key,
            peer_did: handshake_result.peer_identity.did.clone(),
            session_id: handshake_result.session_id,
        });

        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Send a request and receive response
    pub async fn request(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to node"))?;

        // Wrap request in wire envelope
        let wire_request = ZhtpRequestWire::new(request);
        let request_id = wire_request.request_id;

        debug!(
            request_id = %wire_request.request_id_hex(),
            uri = %wire_request.request.uri,
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

    /// Upload a blob and get its content ID
    pub async fn put_blob(&self, content: Vec<u8>, content_type: &str) -> Result<String> {
        let request = ZhtpRequest::post(
            "/api/v1/web4/content/blob".to_string(),
            content,
            content_type.to_string(),
            Some(self.identity.id.clone()),
        )?;

        let response = self.request(request).await?;

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

        let response = self.request(request).await?;

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

        let response = self.request(request).await?;

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

        let response = self.request(request).await?;

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

    /// Get domain info
    pub async fn get_domain(&self, domain: &str) -> Result<Option<serde_json::Value>> {
        let request = ZhtpRequest::get(
            format!("/api/v1/web4/domains/{}", domain),
            Some(self.identity.id.clone()),
        )?;

        let response = self.request(request).await?;

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

/// Skip server certificate verification (for development with self-signed certs)
///
/// WARNING: This should only be used in development. Production should use proper CA verification.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept all certificates in development
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
