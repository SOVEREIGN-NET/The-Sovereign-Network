//! QUIC Transport Adapter for UHP v2
//!
//! Runs the Unified Handshake Protocol (UHP) v2 over a QUIC bidirectional stream.
//! QUIC provides transport security only; all identity, authentication, and PQC
//! live exclusively in UHP v2.
//!
//! # Security Properties
//!
//! - **Mutual Authentication**: Dilithium5 signatures via UHP
//! - **PQC**: Kyber1024 KEM via UHP v2
//! - **Replay Protection**: Nonce cache via UHP
//! - **Transport Binding**: QUIC channel binding baked into UHP context
//!
//! QUIC does NOT negotiate PQC or identity; it only transports UHP messages.

use anyhow::{Result, Context as AnyhowContext, anyhow};
use lib_identity::ZhtpIdentity;
use crate::handshake::{
    HandshakeContext, HandshakeCapabilities, HandshakeSessionInfo,
    HandshakeResult, VerifiedPeer, PqcCapability,
};
use quinn::Connection;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Handshake timeout for QUIC connections (30 seconds)
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

fn export_quic_channel_binding(conn: &Connection) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 32];
    conn.export_keying_material(&mut out, &[], b"zhtp-uhp-channel-binding")
        .map_err(|_| anyhow!("Failed to export QUIC channel binding"))?;
    Ok(out)
}

struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    async fn finish(&mut self) -> Result<()> {
        self.send.finish().context("Failed to finish handshake stream")
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.send).poll_write(cx, data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.send).poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.send).poll_shutdown(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// Result of a successful QUIC UHP v2 handshake
#[derive(Debug, Clone)]
pub struct QuicHandshakeResult {
    /// Verified peer identity and negotiated capabilities
    pub verified_peer: VerifiedPeer,

    /// UHP session key (single source of truth)
    pub session_key: [u8; 32],

    /// UHP session ID (32 bytes, v2)
    pub session_id: [u8; 32],

    /// UHP transcript hash (protocol-level, not transport)
    pub handshake_hash: [u8; 32],

    /// Timestamp when handshake completed
    pub completed_at: u64,
}

/// Perform QUIC handshake as initiator (client side)
pub async fn handshake_as_initiator(
    conn: &Connection,
    identity: &ZhtpIdentity,
    ctx: &HandshakeContext,
) -> Result<QuicHandshakeResult> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let channel_binding = export_quic_channel_binding(conn)?;
        let ctx = ctx.for_client_with_transport(channel_binding, "quic");

        let (send, recv) = conn.open_bi().await
            .context("Failed to open handshake stream")?;
        let mut stream = QuicStream { send, recv };

        debug!(
            local_node_id = ?identity.node_id,
            peer_addr = %conn.remote_address(),
            "QUIC: starting UHP v2 handshake as initiator"
        );

        let capabilities = create_quic_capabilities();
        let result = crate::handshake::core::handshake_as_initiator(
            &mut stream,
            &ctx,
            identity,
            capabilities,
        ).await.context("UHP v2 handshake failed")?;

        stream.finish().await?;

        let session_info = result.session_info.clone();
        let completed_at = result.completed_at;

        info!(
            session_id = ?hex::encode(&result.session_id[..8]),
            peer = %result.peer_identity.to_compact_string(),
            "QUIC UHP v2 handshake completed as initiator"
        );

        Ok(QuicHandshakeResult {
            verified_peer: VerifiedPeer::new(
                result.peer_identity,
                result.capabilities,
                session_info,
            ),
            session_key: result.session_key,
            session_id: result.session_id,
            handshake_hash: result.handshake_hash,
            completed_at,
        })
    })
    .await
    .map_err(|_| anyhow!("QUIC handshake timeout (30s)"))?
}

/// Perform QUIC handshake as responder (server side)
pub async fn handshake_as_responder(
    conn: &Connection,
    identity: &ZhtpIdentity,
    ctx: &HandshakeContext,
) -> Result<QuicHandshakeResult> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let channel_binding = export_quic_channel_binding(conn)?;
        let ctx = ctx.for_server_with_transport(channel_binding, "quic");

        let (send, recv) = conn.accept_bi().await
            .context("Failed to accept handshake stream")?;
        let mut stream = QuicStream { send, recv };

        debug!(
            local_node_id = ?identity.node_id,
            peer_addr = %conn.remote_address(),
            "QUIC: starting UHP v2 handshake as responder"
        );

        let capabilities = create_quic_capabilities();
        let result = crate::handshake::core::handshake_as_responder(
            &mut stream,
            &ctx,
            identity,
            capabilities,
        ).await.context("UHP v2 handshake failed")?;

        stream.finish().await?;

        let session_info = result.session_info.clone();
        let completed_at = result.completed_at;

        info!(
            session_id = ?hex::encode(&result.session_id[..8]),
            peer = %result.peer_identity.to_compact_string(),
            "QUIC UHP v2 handshake completed as responder"
        );

        Ok(QuicHandshakeResult {
            verified_peer: VerifiedPeer::new(
                result.peer_identity,
                result.capabilities,
                session_info,
            ),
            session_key: result.session_key,
            session_id: result.session_id,
            handshake_hash: result.handshake_hash,
            completed_at,
        })
    })
    .await
    .map_err(|_| anyhow!("QUIC handshake timeout (30s)"))?
}

fn create_quic_capabilities() -> HandshakeCapabilities {
    HandshakeCapabilities {
        protocols: vec!["quic".to_string()],
        max_throughput: 100_000_000,
        max_message_size: 10_485_760,
        encryption_methods: vec![
            "chacha20-poly1305".to_string(),
            "aes-256-gcm".to_string(),
        ],
        pqc_capability: PqcCapability::Kyber1024Dilithium5,
        dht_capable: true,
        relay_capable: true,
        storage_capacity: 0,
        web4_capable: true,
        custom_features: vec![],
    }
}
