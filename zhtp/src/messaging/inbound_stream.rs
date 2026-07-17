//! Streaming handler for `GET /api/v1/msg/inbound`.
//!
//! After the QUIC handler authenticates the request and writes the initial
//! `ZhtpResponseWire` (status 200, empty body), it hands the send stream to
//! `run_inbound_stream`. We then:
//!
//! 1. Resolve the canonical recipient DID against the chain identity registry
//!    (same logic as `handle_receive`).
//! 2. Peek existing deposits for this DID as the first batch of frames
//!    (does not remove — client must POST `/api/v1/msg/ack`).
//! 3. Register an mpsc subscriber and write each subsequent envelope as a
//!    `[u32 BE length][envelope bytes]` frame.
//! 4. On any write error (client disconnect, transport failure) we unregister
//!    the subscriber and return.
//!
//! Wire framing: each frame is `[4 bytes BE length][payload bytes]`. No
//! sub-framing of envelopes; one frame == one bincode-serialized MessageEnvelope.
//!
//! Deposits remain until client ack. Disconnect mid-stream does not lose
//! already-peeked mail — it is still in the store.

use anyhow::Result;
use quinn::SendStream;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// Resolve the authenticated requester's key_id to a canonical chain DID.
/// Mirrors the logic in `handle_receive`. Tries:
/// 1. `did:zhtp:{key_id_hex}` direct registry lookup.
/// 2. Registry scan: `blake3(public_key) == key_id`.
/// 3. Registry scan: `blake3(public_key || kyber_public_key) == key_id`.
async fn resolve_recipient_did(requester_key_id: &str) -> Option<String> {
    let blockchain_arc =
        crate::runtime::blockchain_provider::get_global_blockchain().await.ok()?;
    let blockchain = blockchain_arc.read().await;

    // #58: sled-first direct-match + Dilithium / Dilithium+Kyber resolution via
    // the facade, which reads durable `identity_metadata` so this survives a
    // restart (the in-memory `identity_registry` is empty then). Falls back to
    // the raw key_id DID suffix when no identity matches, as before.
    let key_id_did = format!("did:zhtp:{}", requester_key_id);
    Some(
        blockchain
            .did_by_device_key_id(requester_key_id)
            .unwrap_or(key_id_did),
    )
}

/// Write a single framed envelope to the send stream.
async fn write_frame(send: &mut SendStream, envelope: &[u8]) -> Result<()> {
    let len = envelope.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(envelope).await?;
    Ok(())
}

/// Run the inbound stream until the peer disconnects or a write fails.
/// `requester_key_id` is the hex-encoded `request.requester.0` (32 bytes).
pub async fn run_inbound_stream(
    mut send: SendStream,
    requester_key_id: String,
) -> Result<()> {
    let recipient_did = match resolve_recipient_did(&requester_key_id).await {
        Some(d) => d,
        None => {
            warn!(
                "msg/inbound: could not resolve recipient DID for key_id={}",
                requester_key_id
            );
            let _ = send.finish();
            return Ok(());
        }
    };

    info!("msg/inbound: stream opened for {}", recipient_did);

    let provider = crate::runtime::messaging_provider::get_global_messaging_provider();

    // 1. Peek existing deposits (MSG-R1: do not remove without client ack).
    if let Ok(deposits) = provider.get_deposits().await {
        let deliveries = deposits.peek_for_recipient(&recipient_did);
        let mut count = 0usize;
        for delivery in deliveries {
            if write_frame(&mut send, &delivery.envelope).await.is_err() {
                info!(
                    "msg/inbound: client disconnected during initial peek for {}",
                    recipient_did
                );
                return Ok(());
            }
            count += 1;
        }
        if count > 0 {
            info!(
                "msg/inbound: peeked {} envelopes from deposit store for {}",
                count, recipient_did
            );
        }
    }

    // 2. Register a live subscriber. This replaces any previous subscriber for
    // this DID (the prior stream's sender is dropped, its read loop will exit).
    // The `id` is what makes the cleanup at step 4 safe — without it, a stale
    // stream exiting after a fresh registration would remove the live entry
    // by key and the new subscriber would die microseconds after registering.
    let (sub_id, mut rx) = provider.register_subscriber(recipient_did.clone()).await;

    info!(
        "msg/inbound: subscriber registered for {} (id={})",
        recipient_did, sub_id
    );

    // 3. Push frames until the peer disconnects or a write fails.
    while let Some(envelope) = rx.recv().await {
        if write_frame(&mut send, &envelope).await.is_err() {
            info!("msg/inbound: write failed (client gone) for {}", recipient_did);
            break;
        }
    }

    // 4. Cleanup. The id-aware unregister is a no-op if the entry has
    // already been superseded by a newer registration — exactly the
    // case that bit us when stale streams from prior sessions were
    // removing the live one's entry.
    provider.unregister_subscriber(&recipient_did, sub_id).await;
    let _ = send.finish();
    info!(
        "msg/inbound: stream closed for {} (id={})",
        recipient_did, sub_id
    );
    Ok(())
}
