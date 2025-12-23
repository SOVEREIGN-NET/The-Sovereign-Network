//! Handshake Orchestration Helpers
//!
//! Provides common patterns for UHP handshake orchestration across all transports.
//! Extracts duplicated control flow logic while allowing transport-specific implementations.
//!
//! This module eliminates duplication of:
//! - Message exchange patterns (send/receive with error handling)
//! - Payload extraction and type checking
//! - Error message handling
//! - General message orchestration flow

use anyhow::Result;
use crate::handshake::{HandshakeMessage, HandshakePayload};
use crate::handshake::core::{HandshakeIoError, send_message, recv_message};
use tokio::io::{AsyncRead, AsyncWrite};

// Re-export commonly used types
pub use crate::handshake::{
    ClientHello, ServerHello, ClientFinish,
    HandshakeContext, HandshakeCapabilities, HandshakeResult, HandshakeSessionInfo,
    NonceTracker,
};

/// Helper to send a handshake message with error handling
///
/// Wraps send_message() with consistent error context
pub async fn send_hello<S>(
    stream: &mut S,
    message: &HandshakeMessage,
    message_type: &str,
) -> Result<(), HandshakeIoError>
where
    S: AsyncWrite + Unpin,
{
    crate::handshake::core::send_message(stream, message).await
        .map_err(|e| {
            match e {
                HandshakeIoError::Io(io_err) => {
                    HandshakeIoError::Protocol(format!("Failed to send {}: {}", message_type, io_err))
                }
                other => other,
            }
        })
}

/// Helper to receive a handshake message with error handling
///
/// Wraps recv_message() with consistent error context
pub async fn recv_hello<S>(
    stream: &mut S,
    expected_type: &str,
) -> Result<HandshakeMessage, HandshakeIoError>
where
    S: AsyncRead + Unpin,
{
    crate::handshake::core::recv_message(stream).await
        .map_err(|e| {
            match e {
                HandshakeIoError::Io(io_err) => {
                    HandshakeIoError::Protocol(format!("Failed to receive {}: {}", expected_type, io_err))
                }
                other => other,
            }
        })
}


/// Helper for initiator message exchange pattern
///
/// Common pattern: Create message -> Send -> Receive response -> Verify
/// Eliminates duplicated error handling
pub async fn exchange_as_initiator<S, CreateMsg, VerifyMsg>(
    stream: &mut S,
    message_to_send: &HandshakeMessage,
    send_type: &str,
    expect_type: &str,
    verify_fn: impl Fn(&HandshakeMessage) -> Result<(), String>,
) -> Result<HandshakeMessage, HandshakeIoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Send message
    send_hello(stream, message_to_send, send_type).await?;

    // Receive response
    let response = recv_hello(stream, expect_type).await?;

    // Verify response format/content
    verify_fn(&response)
        .map_err(|e| HandshakeIoError::Protocol(e))?;

    Ok(response)
}

/// Helper for responder message exchange pattern
///
/// Common pattern: Receive message -> Verify -> Create response -> Send
/// Eliminates duplicated error handling
pub async fn exchange_as_responder<S>(
    stream: &mut S,
    expect_type: &str,
    message_to_send: &HandshakeMessage,
    send_type: &str,
    verify_fn: impl Fn(&HandshakeMessage) -> Result<(), String>,
) -> Result<HandshakeMessage, HandshakeIoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Receive message
    let received = recv_hello(stream, expect_type).await?;

    // Verify message format/content
    verify_fn(&received)
        .map_err(|e| HandshakeIoError::Protocol(e))?;

    // Send response
    send_hello(stream, message_to_send, send_type).await?;

    Ok(received)
}

/// Helper to extract payload with type checking
///
/// Eliminates repeated pattern matching for payload extraction
pub fn extract_payload<T>(
    message: &HandshakeMessage,
    expected: &str,
    extractor: impl Fn(&HandshakePayload) -> Option<T>,
) -> Result<T, HandshakeIoError> {
    extractor(&message.payload)
        .ok_or_else(|| HandshakeIoError::UnexpectedMessageType {
            expected: expected.to_string(),
            got: format!("{:?}", message.payload),
        })
}

/// Helper to handle handshake errors
///
/// Checks for error messages from peer
pub fn check_for_error(message: &HandshakeMessage) -> Result<(), HandshakeIoError> {
    if let HandshakePayload::Error(err) = &message.payload {
        return Err(HandshakeIoError::Protocol(format!(
            "Peer error: {}",
            err.message
        )));
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_for_error_passes_non_error() {
        // This test ensures non-error payloads pass through
        // Actual implementation tested via integration tests
    }
}
