//! UHP-over-GATT adapter using `GattStream` for fragmentation/reassembly.
//!
//! This provides a small framing layer (length-prefixed) and optional
//! verification hook so callers can reject unverified peers before
//! processing payloads. It is platform-agnostic and can be plugged
//! into the platform BLE handlers.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use futures::FutureExt;

use super::gatt_stream::GattStream;

/// Optional verifier called on each incoming payload before it is returned.
pub type VerificationHook = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Minimal UHP framing for BLE GATT transport.
pub struct GattUhpAdapter {
    stream: GattStream,
    verifier: Option<VerificationHook>,
}

impl GattUhpAdapter {
    /// Create a new adapter around an existing GattStream.
    pub fn new(stream: GattStream, verifier: Option<VerificationHook>) -> Self {
        Self { stream, verifier }
    }

    /// Send a single UHP payload (length-prefixed).
    pub async fn send_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let len = (payload.len() as u32).to_be_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(payload).await?;
        self.stream.flush().await
    }

    /// Receive the next UHP payload, verifying if a hook is provided.
    pub async fn recv_frame(&mut self) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await?;

        if let Some(verify) = &self.verifier {
            if !verify(&payload) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "UHP verification failed",
                ));
            }
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn round_trip_fragmented_payload() -> io::Result<()> {
        // A <-> B pipes
        let (a_tx, b_rx) = mpsc::unbounded_channel();
        let (b_tx, a_rx) = mpsc::unbounded_channel();

        // Sender fn from A to B
        let send_a = Arc::new(move |chunk: Vec<u8>| {
            let tx = a_tx.clone();
            async move {
                tx.send(chunk)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            }
            .boxed()
        });

        // Sender fn from B to A
        let send_b = Arc::new(move |chunk: Vec<u8>| {
            let tx = b_tx.clone();
            async move {
                tx.send(chunk)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            }
            .boxed()
        });

        let stream_a = GattStream::new(247, send_a, a_rx);
        let stream_b = GattStream::new(247, send_b, b_rx);

        let mut adapter_a = GattUhpAdapter::new(stream_a, None);
        let mut adapter_b = GattUhpAdapter::new(stream_b, None);

        let payload = vec![0xAB; 600]; // force fragmentation
        adapter_a.send_frame(&payload).await?;
        let received = adapter_b.recv_frame().await?;

        assert_eq!(payload, received);
        Ok(())
    }

    #[tokio::test]
    async fn verifier_rejects_payload() {
        let (tx, rx) = mpsc::unbounded_channel();
        let sender = Arc::new(move |chunk: Vec<u8>| {
            let tx = tx.clone();
            async move {
                tx.send(chunk)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            }
            .boxed()
        });

        let stream = GattStream::new(247, sender, rx);
        let verifier: VerificationHook = Arc::new(|payload| payload.first() == Some(&0x01));
        let mut adapter = GattUhpAdapter::new(stream, Some(verifier));

        // Good frame
        adapter.send_frame(&[0x01, 0x02]).await.unwrap();
        assert!(adapter.recv_frame().await.is_ok());

        // Bad frame should fail verification
        adapter.send_frame(&[0xFF, 0x00]).await.unwrap();
        let err = adapter.recv_frame().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
