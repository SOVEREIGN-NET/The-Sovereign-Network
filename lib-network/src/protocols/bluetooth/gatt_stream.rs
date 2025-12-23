//! GATT stream wrapper with fragmentation/reassembly for UHP over BLE.
//! Implements `AsyncRead`/`AsyncWrite` with a pluggable fragment sender.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::anyhow;
use futures::future::BoxFuture;
use rand::random;
use std::io;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::UnboundedReceiver,
};

use crate::protocols::bluetooth::gatt::{fragment_large_message, FragmentReassembler};

#[cfg(test)]
use futures::FutureExt;

type SendFn =
    std::sync::Arc<dyn Fn(Vec<u8>) -> BoxFuture<'static, io::Result<()>> + Send + Sync>;

/// Stream abstraction over BLE GATT notifications/write-without-response.
pub struct GattStream {
    mtu: u16,
    sender: SendFn,
    incoming: UnboundedReceiver<Vec<u8>>,
    reassembler: FragmentReassembler,
    read_buf: Vec<u8>,
    write_fut: Option<Pin<Box<dyn futures::Future<Output = io::Result<usize>> + Send>>>,
}

impl GattStream {
    /// Create a new GATT stream.
    ///
    /// - `mtu`: negotiated ATT MTU (247 bytes typical).
    /// - `sender`: async fn that transmits a single fragment to the peer.
    /// - `incoming`: receiver delivering raw notification fragments from the peer.
    pub fn new(mtu: u16, sender: SendFn, incoming: UnboundedReceiver<Vec<u8>>) -> Self {
        Self {
            mtu,
            sender,
            incoming,
            reassembler: FragmentReassembler::new(),
            read_buf: Vec::new(),
            write_fut: None,
        }
    }
}

impl AsyncWrite for GattStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_fut.is_none() {
            let mtu = self.mtu;
            let sender = self.sender.clone();
            let data = buf.to_vec();
            let fut = async move {
                let message_id = random::<u64>();
                let fragments = fragment_large_message(message_id, &data, mtu);

                for fragment in fragments {
                    sender(fragment).await?;
                }
                Ok(data.len())
            };
            self.write_fut = Some(Box::pin(fut));
        }

        if let Some(fut) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(res) => {
                    self.write_fut = None;
                    Poll::Ready(res)
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for GattStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data, drain into the caller's buffer first.
        if !self.read_buf.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.read_buf.len());
            let drained: Vec<u8> = self.read_buf.drain(..to_copy).collect();
            buf.put_slice(&drained);
            return Poll::Ready(Ok(()));
        }

        // Otherwise, keep polling for incoming fragments until a full message is assembled.
        loop {
            match Pin::new(&mut self.incoming).poll_recv(cx) {
                Poll::Ready(Some(fragment)) => {
                    if let Some(message) = self
                        .reassembler
                        .add_fragment(fragment)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                    {
                        self.read_buf = message;
                        // Now that we have data, re-enter and drain on next loop iteration.
                        if !self.read_buf.is_empty() {
                            let to_copy = std::cmp::min(buf.remaining(), self.read_buf.len());
                            let drained: Vec<u8> = self.read_buf.drain(..to_copy).collect();
                            buf.put_slice(&drained);
                            return Poll::Ready(Ok(()));
                        }
                    }
                    // Otherwise continue polling for more fragments.
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        anyhow!("GattStream incoming channel closed"),
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_gatt_stream_round_trip() -> io::Result<()> {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let captured = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let captured_clone = captured.clone();

        let sender: SendFn = std::sync::Arc::new(move |chunk: Vec<u8>| {
            let tx = incoming_tx.clone();
            let captured_clone = captured_clone.clone();
            async move {
                captured_clone.lock().await.push(chunk.clone());
                tx.send(chunk)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            }
            .boxed()
        });

        let mut stream = GattStream::new(247, sender, incoming_rx);
        let payload = vec![0xAB; 600]; // Force fragmentation across MTU

        stream.write_all(&payload).await?;

        let mut received = vec![0u8; payload.len()];
        stream.read_exact(&mut received).await?;
        assert_eq!(received, payload);

        // Ensure fragments were captured (should be >1 for 600 bytes at MTU 247)
        let sent = captured.lock().await;
        assert!(sent.len() >= 3);
        Ok(())
    }
}
