//! Test-friendly mock BLE link that simulates a GATT connection without hardware.
//!
//! It wires two `GattUhpAdapter` instances together using in-memory channels, so
//! tests can exercise fragmentation, reassembly, and optional verification hooks.

use std::io;
use std::sync::Arc;

use futures::FutureExt;
use tokio::sync::mpsc;

use super::gatt_adapter::{GattUhpAdapter, VerificationHook};
use super::gatt_stream::GattStream;

/// Bidirectional mock GATT link (central <-> peripheral).
pub struct MockGattLink {
    pub central: GattUhpAdapter,
    pub peripheral: GattUhpAdapter,
}

impl MockGattLink {
    /// Create a new mock link.
    ///
    /// - `mtu`: ATT MTU to use for fragmentation logic.
    /// - `central_verifier`: optional verification hook applied on payloads received by the central.
    /// - `peripheral_verifier`: optional verification hook applied on payloads received by the peripheral.
    pub fn new(
        mtu: u16,
        central_verifier: Option<VerificationHook>,
        peripheral_verifier: Option<VerificationHook>,
    ) -> Self {
        // Channels for inbound fragments to each side
        let (central_in_tx, central_in_rx) = mpsc::unbounded_channel();
        let (peripheral_in_tx, peripheral_in_rx) = mpsc::unbounded_channel();

        // Central sends to peripheral
        let central_sender = Arc::new(move |chunk: Vec<u8>| {
            let tx = peripheral_in_tx.clone();
            async move {
                tx.send(chunk)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            }
            .boxed()
        });

        // Peripheral sends to central
        let peripheral_sender = Arc::new(move |chunk: Vec<u8>| {
            let tx = central_in_tx.clone();
            async move {
                tx.send(chunk)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            }
            .boxed()
        });

        let central_stream = GattStream::new(mtu, central_sender, central_in_rx);
        let peripheral_stream = GattStream::new(mtu, peripheral_sender, peripheral_in_rx);

        Self {
            central: GattUhpAdapter::new(central_stream, central_verifier),
            peripheral: GattUhpAdapter::new(peripheral_stream, peripheral_verifier),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_link_round_trip() -> io::Result<()> {
        let mut link = MockGattLink::new(247, None, None);

        // Central -> Peripheral (force fragmentation)
        let large = vec![0xAB; 600];
        link.central.send_frame(&large).await?;
        let received = link.peripheral.recv_frame().await?;
        assert_eq!(received, large);

        // Peripheral -> Central (small frame)
        let small = vec![0x01, 0x02, 0x03];
        link.peripheral.send_frame(&small).await?;
        let round_trip = link.central.recv_frame().await?;
        assert_eq!(round_trip, small);

        Ok(())
    }

    #[tokio::test]
    async fn mock_link_verifier_rejects_unverified_payload() {
        let verifier: VerificationHook = Arc::new(|payload| payload.first() == Some(&0xAA));
        let mut link = MockGattLink::new(247, Some(verifier), None);

        // Allowed payload
        link.peripheral
            .send_frame(&[0xAA, 0xBB, 0xCC])
            .await
            .unwrap();
        link.central.recv_frame().await.unwrap();

        // Rejected payload
        link.peripheral
            .send_frame(&[0x00, 0x11])
            .await
            .unwrap();
        let err = link.central.recv_frame().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
