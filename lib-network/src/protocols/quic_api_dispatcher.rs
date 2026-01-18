//! QUIC API Request Dispatcher
//!
//! Routes incoming ZHTP API requests over QUIC to handlers.
//!
//! This module provides the server-side counterpart to Web4Client,
//! accepting authenticated QUIC connections and dispatching wire
//! protocol requests to the existing ZHTP handler infrastructure.
//!
//! # Protocol Flow
//!
//! 1. Accept QUIC connection
//! 2. Perform UHP v2 handshake (verify client identity)
//! 3. For each bidirectional stream:
//!    - Read ZhtpRequestWire (length-prefixed CBOR)
//!    - Dispatch to appropriate handler
//!    - Write ZhtpResponseWire back
//!
//! # Security
//!
//! - All requests are authenticated via UHP handshake
//! - Client identity is verified before processing any requests
//! - Request authorization checked per-request based on client identity

use anyhow::{anyhow, Result, Context};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn};

use quinn::{Endpoint, Connection};

use lib_identity::ZhtpIdentity;
use lib_protocols::wire::{
    ZhtpRequestWire, ZhtpResponseWire,
    read_request, write_response,
};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

/// Verified principal from UHP handshake + AuthContext validation
#[derive(Debug, Clone)]
pub struct VerifiedPrincipal {
    /// Client's verified DID (from UHP handshake)
    pub client_did: String,
    /// Node's DID (our identity)
    pub node_did: String,
    /// Session ID (UHP v2, 32 bytes)
    pub session_id: [u8; 32],
    /// Request sequence number (for audit)
    pub sequence: Option<u64>,
}

use crate::handshake::HandshakeContext;
use crate::protocols::quic_handshake;

/// Handler function type for processing ZHTP requests
///
/// Handlers receive a VerifiedPrincipal for all requests.
/// For mutations (POST/PUT/DELETE), the principal is guaranteed to have
/// a valid AuthContext that was verified against the handshake session.
pub type RequestHandler = Arc<
    dyn Fn(ZhtpRequest, VerifiedPrincipal) -> futures::future::BoxFuture<'static, ZhtpResponse>
        + Send
        + Sync
>;

/// QUIC API Dispatcher - accepts connections and routes requests to handlers
pub struct QuicApiDispatcher {
    /// QUIC endpoint (shared with mesh protocol)
    endpoint: Arc<Endpoint>,

    /// Server identity (for handshake)
    identity: Arc<ZhtpIdentity>,

    /// Handshake context with nonce cache
    handshake_ctx: HandshakeContext,

    /// Request handler
    handler: Option<RequestHandler>,

    /// Active connections
    connections: Arc<RwLock<Vec<ActiveConnection>>>,

    /// Shutdown signal sender
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,

    /// Accept loop task handle
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

/// Active authenticated connection
struct ActiveConnection {
    /// Remote address
    peer_addr: SocketAddr,

    /// Peer's verified DID
    peer_did: String,

    /// QUIC connection
    #[allow(dead_code)]
    connection: Connection,
}

impl QuicApiDispatcher {
    /// Create a new dispatcher sharing an endpoint with the mesh protocol
    pub fn new(
        endpoint: Arc<Endpoint>,
        identity: Arc<ZhtpIdentity>,
        handshake_ctx: HandshakeContext,
    ) -> Self {
        Self {
            endpoint,
            identity,
            handshake_ctx,
            handler: None,
            connections: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx: None,
            accept_task: None,
        }
    }

    /// Set the request handler
    pub fn set_handler(&mut self, handler: RequestHandler) {
        self.handler = Some(handler);
    }

    /// Start accepting API connections
    ///
    /// This runs alongside the mesh message receiver.
    /// Connections are differentiated by the initial message type.
    pub async fn start(&mut self) -> Result<()> {
        if self.handler.is_none() {
            return Err(anyhow!("No request handler set"));
        }

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        info!("QUIC API dispatcher starting...");

        let endpoint = Arc::clone(&self.endpoint);
        let identity = Arc::clone(&self.identity);
        let handshake_ctx = self.handshake_ctx.clone();
        let handler = self.handler.clone().unwrap();
        let connections = Arc::clone(&self.connections);

        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Check for shutdown signal
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("QUIC API dispatcher received shutdown signal");
                            break;
                        }
                    }
                    // Accept new connections
                    incoming = endpoint.accept() => {
                        match incoming {
                            Some(conn) => {
                                let id = Arc::clone(&identity);
                                let ctx = handshake_ctx.clone();
                                let h = Arc::clone(&handler);
                                let conns = Arc::clone(&connections);

                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(conn, id, ctx, h, conns).await {
                                        warn!("Connection handling failed: {}", e);
                                    }
                                });
                            }
                            None => {
                                // Endpoint closed
                                info!("QUIC endpoint closed");
                                break;
                            }
                        }
                    }
                }
            }
            info!("QUIC API dispatcher stopped");
        });

        self.accept_task = Some(accept_task);
        Ok(())
    }

    /// Stop the dispatcher gracefully
    ///
    /// Signals the accept loop to stop and waits for it to complete.
    pub async fn stop(&mut self) {
        info!("QUIC API dispatcher stopping...");

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        // Wait for accept task to complete
        if let Some(task) = self.accept_task.take() {
            // Give it a reasonable timeout
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                task
            ).await {
                Ok(_) => info!("QUIC API dispatcher stopped cleanly"),
                Err(_) => {
                    warn!("QUIC API dispatcher shutdown timed out");
                }
            }
        }

        // Close all active connections
        let mut conns = self.connections.write().await;
        for conn in conns.drain(..) {
            conn.connection.close(0u32.into(), b"dispatcher shutdown");
        }
    }

    /// Get active connection count
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Check if dispatcher is running
    pub fn is_running(&self) -> bool {
        self.accept_task.as_ref().map(|t| !t.is_finished()).unwrap_or(false)
    }
}

/// Handle a single incoming connection
async fn handle_connection(
    incoming: quinn::Incoming,
    identity: Arc<ZhtpIdentity>,
    handshake_ctx: HandshakeContext,
    handler: RequestHandler,
    connections: Arc<RwLock<Vec<ActiveConnection>>>,
) -> Result<()> {
    let connection = incoming.await
        .context("Failed to accept connection")?;

    let peer_addr = connection.remote_address();
    info!("New API connection from {}", peer_addr);

    // Perform UHP v2 handshake
    let handshake_result = quic_handshake::handshake_as_responder(
        &connection,
        &identity,
        &handshake_ctx,
    ).await.context("Handshake failed")?;

    let peer_did = handshake_result.verified_peer.identity.did.clone();

    info!(
        peer_did = %peer_did,
        peer_addr = %peer_addr,
        "API client authenticated"
    );

    // Track connection
    {
        let mut conns = connections.write().await;
        conns.push(ActiveConnection {
            peer_addr,
            peer_did: peer_did.clone(),
            connection: connection.clone(),
        });
    }

    // Extract session info for auth verification
    let session_id = handshake_result.session_id;
    let session_key = handshake_result.session_key;
    let node_did = identity.did.clone();

    // Derive application-layer MAC key (same derivation as client)
    let app_key = derive_app_key(&session_key, &session_id, &peer_did, &node_did);

    // Handle streams
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let h = Arc::clone(&handler);
                let client_did = peer_did.clone();
                let server_did = node_did.clone();
                let sid = session_id;
                let key = app_key;

                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv, h, client_did, server_did, sid, key).await {
                        debug!("Stream handling error: {}", e);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("Client {} closed connection", peer_addr);
                break;
            }
            Err(e) => {
                warn!("Connection error from {}: {}", peer_addr, e);
                break;
            }
        }
    }

    // Remove from active connections
    {
        let mut conns = connections.write().await;
        conns.retain(|c| c.peer_addr != peer_addr);
    }

    Ok(())
}

/// Handle a single bidirectional stream (one request-response)
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    handler: RequestHandler,
    client_did: String,
    node_did: String,
    session_id: [u8; 32],
    app_key: [u8; 32],
) -> Result<()> {
    // Read request
    let wire_request = read_request(&mut recv).await
        .context("Failed to read request")?;

    let request_id = wire_request.request_id;
    let is_mutation = matches!(
        wire_request.request.method,
        ZhtpMethod::Post | ZhtpMethod::Put | ZhtpMethod::Delete
    );

    debug!(
        request_id = %wire_request.request_id_hex(),
        uri = %wire_request.request.uri,
        method = ?wire_request.request.method,
        client_did = %client_did,
        is_mutation = is_mutation,
        has_auth = wire_request.auth_context.is_some(),
        "Received API request"
    );

    // For mutations, AuthContext is REQUIRED
    if is_mutation && wire_request.auth_context.is_none() {
        warn!(
            request_id = %wire_request.request_id_hex(),
            uri = %wire_request.request.uri,
            "Mutation request rejected: missing AuthContext"
        );
        let response = ZhtpResponseWire::error(
            request_id,
            ZhtpStatus::Unauthorized,
            "AuthContext required for mutations".to_string(),
        );
        write_response(&mut send, &response).await?;
        send.finish()?;
        return Ok(());
    }

    // Verify auth context if present
    let sequence = if let Some(ref auth_ctx) = wire_request.auth_context {
        // Verify session ID matches
        if auth_ctx.session_id != session_id {
            warn!(
                request_id = %wire_request.request_id_hex(),
                "Auth context session ID mismatch"
            );
            let response = ZhtpResponseWire::error(
                request_id,
                ZhtpStatus::Unauthorized,
                "Session ID mismatch".to_string(),
            );
            write_response(&mut send, &response).await?;
            send.finish()?;
            return Ok(());
        }

        // Verify client DID matches handshake identity
        if auth_ctx.client_did != client_did {
            warn!(
                request_id = %wire_request.request_id_hex(),
                auth_did = %auth_ctx.client_did,
                handshake_did = %client_did,
                "Auth context DID mismatch"
            );
            let response = ZhtpResponseWire::error(
                request_id,
                ZhtpStatus::Unauthorized,
                "Client DID mismatch".to_string(),
            );
            write_response(&mut send, &response).await?;
            send.finish()?;
            return Ok(());
        }

        // Compute canonical request hash for MAC verification
        let request_hash = ZhtpRequestWire::compute_canonical_request_hash(
            &wire_request.request,
            &wire_request.request_id,
            wire_request.timestamp_ms,
        );

        if !auth_ctx.verify(&app_key, &request_hash) {
            warn!(
                request_id = %wire_request.request_id_hex(),
                "Auth context MAC verification failed"
            );
            let response = ZhtpResponseWire::error(
                request_id,
                ZhtpStatus::Unauthorized,
                "Request MAC verification failed".to_string(),
            );
            write_response(&mut send, &response).await?;
            send.finish()?;
            return Ok(());
        }

        debug!(
            request_id = %wire_request.request_id_hex(),
            sequence = auth_ctx.sequence,
            "Auth context verified"
        );

        Some(auth_ctx.sequence)
    } else {
        // No auth context - allowed for GET requests only
        debug!(
            request_id = %wire_request.request_id_hex(),
            "GET request without auth context - allowed"
        );
        None
    };

    // Create verified principal
    let principal = VerifiedPrincipal {
        client_did,
        node_did,
        session_id,
        sequence,
    };

    // Dispatch to handler with verified principal
    let response = handler(wire_request.request, principal).await;

    // Wrap response
    let wire_response = ZhtpResponseWire::success(request_id, response);

    debug!(
        request_id = %wire_response.request_id_hex(),
        status = wire_response.status,
        "Sending API response"
    );

    // Send response
    write_response(&mut send, &wire_response).await
        .context("Failed to write response")?;

    // Finish stream
    send.finish()
        .context("Failed to finish stream")?;

    Ok(())
}

/// Derive application-layer MAC key from session key
///
/// This must match the derivation in Web4Client.
fn derive_app_key(session_key: &[u8; 32], session_id: &[u8; 32], peer_did: &str, node_did: &str) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"zhtp-web4-app-mac");
    input.extend_from_slice(session_key);
    input.extend_from_slice(session_id);
    // Note: peer_did is client_did from server's perspective, node_did is server's DID
    // The order must match the client: peer_did (server from client's view) then client_did
    // From server's perspective: client is peer, so we swap order
    input.extend_from_slice(node_did.as_bytes()); // server's DID (client sees this as peer)
    input.extend_from_slice(peer_did.as_bytes()); // client's DID
    lib_crypto::hash_blake3(&input)
}

/// Create a handler that routes requests to the ZHTP router
pub fn create_router_handler<F>(
    router: Arc<F>,
) -> RequestHandler
where
    F: Fn(ZhtpRequest) -> futures::future::BoxFuture<'static, ZhtpResponse> + Send + Sync + 'static,
{
    Arc::new(move |request, _principal| {
        let r = Arc::clone(&router);
        Box::pin(async move {
            r(request).await
        })
    })
}

/// Create a handler that includes principal info for authorization
pub fn create_authorized_handler<F>(
    handler: Arc<F>,
) -> RequestHandler
where
    F: Fn(ZhtpRequest, VerifiedPrincipal) -> futures::future::BoxFuture<'static, ZhtpResponse> + Send + Sync + 'static,
{
    Arc::new(move |request, principal| {
        let h = Arc::clone(&handler);
        Box::pin(async move {
            h(request, principal).await
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests would require a running QUIC endpoint
    // Unit tests for individual functions can be added here
}
