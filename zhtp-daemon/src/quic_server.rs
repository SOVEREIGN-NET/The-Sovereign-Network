//! QUIC Gateway Server
//!
//! Accepts native ZHTP connections over QUIC and transparently forwards requests
//! to backend validators via the existing `BackendPool` / `Web4Client` infrastructure.
//!
//! Supports two connection modes:
//! - **Public** (`zhtp-public/1`): No UHP handshake; wire-format ZHTP requests are
//!   read directly, forwarded, and responses written back.
//! - **ControlPlane** (`zhtp-uhp/1` or `zhtp-uhp/2`): Full UHP v2 handshake as
//!   responder.  Incoming requests are authenticated (v2 MAC + monotonic counter)
//!   before forwarding.  The gateway strips `auth_context` and attaches a signed
//!   `ForwardedClientContext` for the backend.

use anyhow::{anyhow, Context, Result};
use quinn::{Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use lib_identity::ZhtpIdentity;
use lib_network::handshake::HandshakeContext;
use lib_network::protocols::quic_handshake;
use lib_network::protocols::types::session::V2Session;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::wire::{read_request, write_response, ZhtpResponseWire};

use crate::service::ZhtpDaemonService;

/// Idle timeout while waiting for the next bidirectional stream.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum time allowed for the UHP v2 handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Parsed connection mode from the negotiated ALPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionMode {
    Public,
    ControlPlane,
    Mesh,
}

impl ConnectionMode {
    fn from_alpn(alpn: Option<&[u8]>) -> Self {
        match alpn {
            Some(b"zhtp-public/1") => ConnectionMode::Public,
            Some(b"zhtp-uhp/1") | Some(b"zhtp-uhp/2") => ConnectionMode::ControlPlane,
            Some(b"zhtp-mesh/1") => ConnectionMode::Mesh,
            // Legacy / HTTP-compat identifiers map to public read-only.
            Some(b"zhtp-http/1") | Some(b"zhtp/1.0") | Some(b"h3") => ConnectionMode::Public,
            _ => ConnectionMode::Public,
        }
    }
}

/// Self-signed TLS certificate material.
struct SelfSignedCert {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// QUIC server that proxies native ZHTP traffic to backend validators.
#[derive(Clone)]
pub struct QuicGatewayServer {
    service: Arc<ZhtpDaemonService>,
    identity: Arc<ZhtpIdentity>,
    endpoint: Endpoint,
}

impl QuicGatewayServer {
    /// Create a new QUIC gateway endpoint.
    ///
    /// If `cert_path` / `key_path` do not exist a fresh self-signed certificate
    /// is generated and persisted.
    pub async fn new(
        bind_addr: SocketAddr,
        service: Arc<ZhtpDaemonService>,
        identity: Arc<ZhtpIdentity>,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self> {
        // rustls 0.23+ requires a crypto provider to be installed.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = load_or_generate_cert(cert_path, key_path)
            .with_context(|| "Failed to load or generate TLS certificate")?;

        let mut rustls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert], cert.key)
            .context("Failed to build rustls ServerConfig")?;

        rustls_config.alpn_protocols = lib_network::constants::server_alpns();

        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .context("Failed to create Quinn crypto config")?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.max_concurrent_uni_streams(10u32.into());
        transport.max_idle_timeout(Some(Duration::from_secs(300).try_into().unwrap()));
        server_config.transport_config(Arc::new(transport));

        let endpoint = Endpoint::server(server_config, bind_addr)
            .with_context(|| format!("Failed to bind QUIC endpoint to {}", bind_addr))?;

        info!("🔐 QUIC gateway listening on {}", endpoint.local_addr()?);

        Ok(Self {
            service,
            identity,
            endpoint,
        })
    }

    /// Run the accept loop until the endpoint is closed.
    pub async fn run(&self) -> Result<()> {
        info!("🌐 QUIC gateway accept loop started");
        loop {
            match self.endpoint.accept().await {
                Some(incoming) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(connection) => {
                                if let Err(e) = this.handle_connection(connection).await {
                                    debug!("QUIC connection handler ended: {}", e);
                                }
                            }
                            Err(e) => {
                                warn!("QUIC incoming connection failed: {}", e);
                            }
                        }
                    });
                }
                None => {
                    info!("QUIC endpoint closed");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Dispatch an established connection based on ALPN.
    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let peer_addr = connection.remote_address();

        let alpn = connection
            .handshake_data()
            .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hd| hd.protocol.clone());

        let mode = ConnectionMode::from_alpn(alpn.as_deref());

        info!(
            "📡 QUIC connection from {} (mode: {:?}, alpn: {:?})",
            peer_addr,
            mode,
            alpn.as_ref().map(|a| String::from_utf8_lossy(a))
        );

        match mode {
            ConnectionMode::Public => self.handle_public_connection(connection, peer_addr).await,
            ConnectionMode::ControlPlane => {
                self.handle_control_plane_connection(connection, peer_addr)
                    .await
            }
            ConnectionMode::Mesh => {
                warn!("Mesh connections are not supported on gateway");
                connection.close(0u32.into(), b"mesh not supported");
                Ok(())
            }
        }
    }

    // ------------------------------------------------------------------
    // Public mode (no UHP handshake)
    // ------------------------------------------------------------------

    async fn handle_public_connection(
        &self,
        connection: Connection,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        loop {
            match timeout(CLIENT_IDLE_TIMEOUT, connection.accept_bi()).await {
                Ok(Ok((send, recv))) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle_public_stream(recv, send, peer_addr).await {
                            debug!("Public stream from {} ended: {}", peer_addr, e);
                        }
                    });
                }
                Ok(Err(quinn::ConnectionError::ApplicationClosed(_))) => {
                    debug!("Public connection closed by {}", peer_addr);
                    break;
                }
                Ok(Err(quinn::ConnectionError::TimedOut)) => {
                    debug!("Public connection timed out from {}", peer_addr);
                    break;
                }
                Ok(Err(e)) => {
                    debug!("Public connection error from {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    debug!("Public connection idle timeout from {}", peer_addr);
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_public_stream(
        &self,
        mut recv: quinn::RecvStream,
        mut send: quinn::SendStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let wire_request = read_request(&mut recv)
            .await
            .context("Failed to read public ZHTP wire request")?;

        debug!(
            request_id = %wire_request.request_id_hex(),
            uri = %wire_request.request.uri,
            method = ?wire_request.request.method,
            "Public ZHTP request"
        );

        let response = self
            .forward_request(wire_request.request, peer_addr)
            .await
            .unwrap_or_else(|e| {
                warn!("Forward failed: {}", e);
                ZhtpResponse::error(ZhtpStatus::BadGateway, format!("Gateway forward error: {}", e))
            });

        let wire_response = ZhtpResponseWire::success(wire_request.request_id, response);
        write_response(&mut send, &wire_response)
            .await
            .context("Failed to write public ZHTP wire response")?;

        send.finish().ok();
        Ok(())
    }

    // ------------------------------------------------------------------
    // ControlPlane mode (UHP v2 handshake + authenticated streams)
    // ------------------------------------------------------------------

    async fn handle_control_plane_connection(
        &self,
        connection: Connection,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        info!(
            "🔐 ControlPlane connection from {} — starting UHP v2 handshake",
            peer_addr
        );

        let (_identity, handshake_result) = self
            .perform_uhp_handshake(&connection, &peer_addr)
            .await?;

        let peer_did = handshake_result.verified_peer.identity.did.clone();
        let session_key = handshake_result.session_key;
        let transcript_hash = handshake_result.handshake_hash;
        let session_id = handshake_result.session_id;

        let v2_keys = lib_network::handshake::security::derive_v2_session_keys(
            &session_key,
            &transcript_hash,
        )
        .context("Failed to derive v2 session keys")?;

        let v2_session = V2Session::new(session_id, v2_keys.mac_key, peer_did.clone(), None);

        info!(
            peer_did = %peer_did,
            session_id = %hex::encode(&session_id[..8]),
            "✅ UHP v2 authenticated from {}",
            peer_addr
        );

        let session = Arc::new(v2_session);

        loop {
            match timeout(CLIENT_IDLE_TIMEOUT, connection.accept_bi()).await {
                Ok(Ok((send, recv))) => {
                    let this = self.clone();
                    let session = session.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this
                            .handle_control_plane_stream(recv, send, &session, peer_addr)
                            .await
                        {
                            debug!(
                                "ControlPlane stream from {} ended: {}",
                                peer_addr, e
                            );
                        }
                    });
                }
                Ok(Err(quinn::ConnectionError::ApplicationClosed(_))) => {
                    debug!("ControlPlane connection closed by {}", peer_addr);
                    break;
                }
                Ok(Err(quinn::ConnectionError::TimedOut)) => {
                    debug!("ControlPlane connection timed out from {}", peer_addr);
                    break;
                }
                Ok(Err(e)) => {
                    debug!("ControlPlane connection error from {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    debug!("ControlPlane idle timeout from {}", peer_addr);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn perform_uhp_handshake(
        &self,
        connection: &Connection,
        _peer_addr: &SocketAddr,
    ) -> Result<(
        ZhtpIdentity,
        lib_network::protocols::quic_handshake::QuicHandshakeResult,
    )> {
        let nonce_cache =
            lib_network::handshake::get_or_init_global_nonce_cache(3600, 100_000)
                .context("Failed to get global nonce cache")?;
        let handshake_ctx = HandshakeContext::new(nonce_cache.clone());

        let result = timeout(
            HANDSHAKE_TIMEOUT,
            quic_handshake::handshake_as_responder(
                connection,
                &self.identity,
                &handshake_ctx,
            ),
        )
        .await
        .context("UHP handshake timed out")?
        .context("UHP handshake failed")?;

        Ok(((*self.identity).clone(), result))
    }

    async fn handle_control_plane_stream(
        &self,
        mut recv: quinn::RecvStream,
        mut send: quinn::SendStream,
        session: &V2Session,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        use lib_network::handshake::security::{verify_v2_mac, CanonicalRequest};

        let wire_request = read_request(&mut recv)
            .await
            .context("Failed to read authenticated v2 request")?;

        let auth_ctx = match &wire_request.auth_context {
            Some(ctx) => ctx,
            None => {
                warn!("V2 request missing auth_context — rejecting");
                let err = ZhtpResponseWire::error(
                    wire_request.request_id,
                    ZhtpStatus::Unauthorized,
                    "V2 requires authentication context".into(),
                );
                write_response(&mut send, &err).await?;
                send.finish().ok();
                return Ok(());
            }
        };

        // Verify DID matches session.
        if auth_ctx.client_did != session.peer_did() {
            warn!(
                expected = %session.peer_did(),
                received = %auth_ctx.client_did,
                "Client DID mismatch"
            );
            let err = ZhtpResponseWire::error(
                wire_request.request_id,
                ZhtpStatus::Unauthorized,
                "Invalid client identity".into(),
            );
            write_response(&mut send, &err).await?;
            send.finish().ok();
            return Ok(());
        }

        // Verify session_id matches.
        if auth_ctx.session_id != *session.session_id() {
            warn!("Session ID mismatch in v2 request");
            let err = ZhtpResponseWire::error(
                wire_request.request_id,
                ZhtpStatus::Unauthorized,
                "Invalid session".into(),
            );
            write_response(&mut send, &err).await?;
            send.finish().ok();
            return Ok(());
        }

        // Build canonical request and verify MAC.
        let method_byte = method_to_byte(wire_request.request.method);
        let canonical = CanonicalRequest {
            method: method_byte,
            path: wire_request.request.uri.clone(),
            body: wire_request.request.body.clone(),
        };

        if !verify_v2_mac(
            session.mac_key(),
            &canonical,
            auth_ctx.sequence,
            session.session_id(),
            &auth_ctx.request_mac,
        ) {
            warn!("V2 MAC verification failed");
            let err = ZhtpResponseWire::error(
                wire_request.request_id,
                ZhtpStatus::Unauthorized,
                "MAC verification failed".into(),
            );
            write_response(&mut send, &err).await?;
            send.finish().ok();
            return Ok(());
        }

        // Validate counter (replay protection).
        if let Err(e) = session.validate_counter(auth_ctx.sequence) {
            warn!("Counter validation failed: {}", e);
            let err = ZhtpResponseWire::error(
                wire_request.request_id,
                ZhtpStatus::Unauthorized,
                "Invalid counter — possible replay".into(),
            );
            write_response(&mut send, &err).await?;
            send.finish().ok();
            return Ok(());
        }

        // Forward the request (auth_context is intentionally dropped).
        let mut request = wire_request.request;
        request.requester =
            lib_identity::did::parse_did_to_identity_id(session.peer_did()).ok();
        request
            .headers
            .custom
            .insert("peer_addr".to_string(), peer_addr.to_string());
        request
            .headers
            .custom
            .insert("peer_addr_source".to_string(), "quic".to_string());

        let response = self
            .forward_request(request, peer_addr)
            .await
            .unwrap_or_else(|e| {
                warn!("Forward failed: {}", e);
                ZhtpResponse::error(
                    ZhtpStatus::BadGateway,
                    format!("Gateway forward error: {}", e),
                )
            });

        let wire_response = ZhtpResponseWire::success(wire_request.request_id, response);
        write_response(&mut send, &wire_response)
            .await
            .context("Failed to write v2 wire response")?;
        send.finish().ok();

        Ok(())
    }

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    /// Forward a `ZhtpRequest` to a backend via the service layer.
    async fn forward_request(
        &self,
        request: ZhtpRequest,
        peer_addr: SocketAddr,
    ) -> Result<ZhtpResponse> {
        self.service
            .forward_zhtp_request(request, Some(peer_addr.to_string()))
            .await
    }
}

// ------------------------------------------------------------------
// Certificate management
// ------------------------------------------------------------------

fn load_or_generate_cert(cert_path: &Path, key_path: &Path) -> Result<SelfSignedCert> {
    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read(cert_path).context("Failed to read certificate file")?;
        let key_pem = std::fs::read(key_path).context("Failed to read key file")?;

        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .next()
            .ok_or_else(|| anyhow!("No certificate found in PEM file"))?
            .context("Failed to parse certificate PEM")?;

        let key_der = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("Failed to parse private key PEM")?
            .ok_or_else(|| anyhow!("No private key found in PEM file"))?;

        return Ok(SelfSignedCert {
            cert: cert_der,
            key: key_der,
        });
    }

    let subject_alt_names = vec![
        "zhtp-gateway".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "*.local".to_string(),
        "*".to_string(),
    ];

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(subject_alt_names)
            .context("Failed to generate self-signed certificate")?;

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    std::fs::write(cert_path, cert.pem()).context("Failed to write certificate file")?;
    std::fs::write(key_path, signing_key.serialize_pem()).context("Failed to write key file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set private key permissions")?;
    }

    let cert_der = rustls_pemfile::certs(&mut cert.pem().as_bytes())
        .next()
        .ok_or_else(|| anyhow!("No certificate found in generated PEM"))?
        .context("Failed to parse generated certificate")?;

    let key_der = rustls_pemfile::private_key(&mut signing_key.serialize_pem().as_bytes())
        .context("Failed to parse generated key PEM")?
        .ok_or_else(|| anyhow!("No private key found in generated PEM"))?;

    Ok(SelfSignedCert {
        cert: cert_der,
        key: key_der,
    })
}

// ------------------------------------------------------------------
// Utilities
// ------------------------------------------------------------------

fn method_to_byte(method: lib_protocols::types::ZhtpMethod) -> u8 {
    use lib_protocols::types::ZhtpMethod;
    match method {
        ZhtpMethod::Get => 0,
        ZhtpMethod::Post => 1,
        ZhtpMethod::Put => 2,
        ZhtpMethod::Delete => 3,
        ZhtpMethod::Patch => 4,
        ZhtpMethod::Head => 5,
        ZhtpMethod::Options => 6,
        _ => 255,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_mode_from_alpn_public() {
        assert_eq!(ConnectionMode::from_alpn(Some(b"zhtp-public/1")), ConnectionMode::Public);
    }

    #[test]
    fn connection_mode_from_alpn_control_plane_v1() {
        assert_eq!(ConnectionMode::from_alpn(Some(b"zhtp-uhp/1")), ConnectionMode::ControlPlane);
    }

    #[test]
    fn connection_mode_from_alpn_control_plane_v2() {
        assert_eq!(ConnectionMode::from_alpn(Some(b"zhtp-uhp/2")), ConnectionMode::ControlPlane);
    }

    #[test]
    fn connection_mode_from_alpn_mesh() {
        assert_eq!(ConnectionMode::from_alpn(Some(b"zhtp-mesh/1")), ConnectionMode::Mesh);
    }

    #[test]
    fn connection_mode_from_alpn_legacy_http() {
        assert_eq!(ConnectionMode::from_alpn(Some(b"zhtp-http/1")), ConnectionMode::Public);
        assert_eq!(ConnectionMode::from_alpn(Some(b"h3")), ConnectionMode::Public);
    }

    #[test]
    fn connection_mode_from_alpn_unknown_defaults_to_public() {
        assert_eq!(ConnectionMode::from_alpn(Some(b"unknown/1")), ConnectionMode::Public);
        assert_eq!(ConnectionMode::from_alpn(None), ConnectionMode::Public);
    }

    #[test]
    fn method_to_byte_maps_correctly() {
        use lib_protocols::types::ZhtpMethod;
        assert_eq!(method_to_byte(ZhtpMethod::Get), 0);
        assert_eq!(method_to_byte(ZhtpMethod::Post), 1);
        assert_eq!(method_to_byte(ZhtpMethod::Put), 2);
        assert_eq!(method_to_byte(ZhtpMethod::Delete), 3);
        assert_eq!(method_to_byte(ZhtpMethod::Patch), 4);
        assert_eq!(method_to_byte(ZhtpMethod::Head), 5);
        assert_eq!(method_to_byte(ZhtpMethod::Options), 6);
        assert_eq!(method_to_byte(ZhtpMethod::Trace), 255);
    }

    #[test]
    fn load_or_generate_cert_creates_valid_certificate() {
        let tmp = std::env::temp_dir().join(format!("zhtp-test-certs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let cert_path = tmp.join("test-cert.pem");
        let key_path = tmp.join("test-key.pem");

        // First call should generate
        let cert1 = load_or_generate_cert(&cert_path, &key_path).unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Second call should load existing
        let cert2 = load_or_generate_cert(&cert_path, &key_path).unwrap();
        assert_eq!(cert1.cert.as_ref(), cert2.cert.as_ref());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
