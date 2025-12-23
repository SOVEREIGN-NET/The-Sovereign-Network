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
    stream.write_u32(len).await?;

    // Write payload
    stream.write_all(data).await?;

    // Flush to ensure delivery
    stream.flush().await?;

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
    // Read length prefix (big-endian u32)
    let len = stream.read_u32().await? as usize;

    // Validate message size (DoS protection)
    if len > MAX_HANDSHAKE_MESSAGE_SIZE {
        return Err(anyhow!(
            "Message too large: {} > {}",
            len,
            MAX_HANDSHAKE_MESSAGE_SIZE
        ));
    }

    // Read payload
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;

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
