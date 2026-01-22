//! Unified message framing for UHP (Unified Handshake Protocol) transports
//!
//! Provides consistent length-prefixed message serialization across all transports:
//! - TCP (bootstrap and core handshakes)
//! - QUIC (modern mesh protocol)
//! - WiFi Direct
//! - Bluetooth
//!
//! Message format: [u32 BE length][payload bytes]
//!
//! This module eliminates duplication of message framing logic across
//! multiple protocol implementations.

use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{trace, debug};

/// Maximum allowed handshake message size (1 MB)
/// Prevents memory exhaustion attacks during handshake
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 1_048_576;

/// Send a length-prefixed message over async stream
///
/// Format: [u32 BE length][payload]
///
/// # Arguments
/// * `stream` - Async writable stream (TCP, QUIC, etc.)
/// * `data` - Message payload to send
///
/// # Errors
/// * Message exceeds MAX_HANDSHAKE_MESSAGE_SIZE
/// * I/O errors from underlying stream
pub async fn send_framed<S>(stream: &mut S, data: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    trace!("send_framed: preparing to send {} bytes", data.len());

    // Validate message size (DoS protection)
    if data.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
        return Err(anyhow!(
            "Message too large: {} > {}",
            data.len(),
            MAX_HANDSHAKE_MESSAGE_SIZE
        ));
    }

    // Write length prefix (big-endian u32)
    let len = data.len() as u32;
    trace!("send_framed: writing 4-byte length prefix: {} (0x{:08x})", len, len);
    stream.write_u32(len).await?;
    trace!("send_framed: length prefix written successfully");

    // Write payload
    trace!("send_framed: writing {} byte payload...", data.len());
    stream.write_all(data).await?;
    trace!("send_framed: payload written successfully");

    // Flush to ensure delivery
    trace!("send_framed: flushing stream...");
    stream.flush().await?;
    debug!("send_framed: successfully sent {} bytes (4 + {})", 4 + data.len(), data.len());

    Ok(())
}

/// Receive a length-prefixed message from async stream
///
/// Format: [u32 BE length][payload]
///
/// # Arguments
/// * `stream` - Async readable stream (TCP, QUIC, etc.)
///
/// # Returns
/// Deserialized message bytes
///
/// # Errors
/// * Length prefix exceeds MAX_HANDSHAKE_MESSAGE_SIZE
/// * I/O errors from underlying stream
/// * Unexpected EOF
pub async fn recv_framed<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    trace!("recv_framed: waiting for 4-byte length prefix...");

    // Read length prefix byte-by-byte for debugging
    let mut len_buf = [0u8; 4];
    for i in 0..4 {
        trace!("recv_framed: reading byte {} of length prefix...", i);
        match stream.read_exact(&mut len_buf[i..i+1]).await {
            Ok(_) => {
                trace!("recv_framed: byte {} = 0x{:02x}", i, len_buf[i]);
            }
            Err(e) => {
                debug!("recv_framed: failed to read byte {} of length prefix: {}", i, e);
                return Err(anyhow!("Failed to read length prefix byte {}: {}", i, e));
            }
        }
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    debug!("recv_framed: length prefix complete: {} bytes (0x{:08x})", len, len);

    trace!("recv_framed: got length prefix: {} bytes (0x{:08x})", len, len);

    // Validate message size (DoS protection)
    if len > MAX_HANDSHAKE_MESSAGE_SIZE {
        debug!("recv_framed: message too large: {} > {}", len, MAX_HANDSHAKE_MESSAGE_SIZE);
        return Err(anyhow!(
            "Message too large: {} > {}",
            len,
            MAX_HANDSHAKE_MESSAGE_SIZE
        ));
    }

    if len == 0 {
        debug!("recv_framed: received zero-length message");
        return Ok(Vec::new());
    }

    // Read payload
    trace!("recv_framed: reading {} byte payload...", len);
    let mut data = vec![0u8; len];
    match stream.read_exact(&mut data).await {
        Ok(_) => {
            debug!("recv_framed: successfully received {} bytes (4 + {})", 4 + len, len);
            trace!("recv_framed: payload first 16 bytes: {:02x?}", &data[..std::cmp::min(16, data.len())]);
        }
        Err(e) => {
            debug!("recv_framed: failed to read payload ({} bytes): {}", len, e);
            return Err(anyhow!("Failed to read {} byte payload: {}", len, e));
        }
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_send_recv_roundtrip() -> Result<()> {
        let message = b"Hello, Handshake!";
        let mut buffer = Vec::new();

        // Send message to buffer
        {
            let mut cursor = Cursor::new(&mut buffer);
            send_framed(&mut cursor, message).await?;
        }

        // Receive message from buffer
        {
            let mut cursor = Cursor::new(buffer);
            let received = recv_framed(&mut cursor).await?;
            assert_eq!(received, message);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_message_too_large() {
        let oversized = vec![0u8; MAX_HANDSHAKE_MESSAGE_SIZE + 1];
        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);

        let result = send_framed(&mut cursor, &oversized).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }
}
