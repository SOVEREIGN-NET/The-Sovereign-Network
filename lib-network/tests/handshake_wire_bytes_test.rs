//! UHP-v2 wire-byte capture for `ClientHello`.
//!
//! Companion to `quic_handshake_roundtrip_test.rs`. That test proves the
//! canonical initiator and responder round-trip cleanly. This test goes
//! one level deeper and dumps the exact `ClientHello` bytes the canonical
//! initiator emits on the wire — so any **alternative** initiator
//! implementation (e.g. the hand-rolled `handshake_with_transcript` in
//! the mobile-side `quinn-ffi`) can be made byte-identical by running an
//! equivalent capture on its side and diffing.
//!
//! Why this matters: production reports
//! `"UHP v2 handshake failed: Protocol error: Failed to read length
//! prefix byte 0: connection lost"` occur when the server-side
//! `handshake_as_responder` cannot parse what the wire delivered and
//! closes the bidi stream. The canonical pair round-trips in CI, so
//! whatever the wire actually contained from the mobile side wasn't
//! what `handshake_as_initiator` would have produced — i.e. a divergent
//! reimplementation. Pinning the canonical byte sequence here makes the
//! divergence diagnosable from a hex diff instead of guesswork.
//!
//! Run:
//!   `cargo test --profile dev-release -p lib-network --test
//!    handshake_wire_bytes_test -- --nocapture`
//!
//! The `--nocapture` is the point — the test prints the hex so the
//! mobile team can capture an equivalent dump from quinn-ffi and run
//! `diff` against it.

use lib_network::handshake::core::{handshake_as_initiator, handshake_as_responder};
use lib_network::handshake::{HandshakeCapabilities, HandshakeContext, NonceCache, PqcCapability};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tempfile::tempdir;
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// Build the same `HandshakeCapabilities` shape the QUIC adapter uses
/// in production (see `lib-network/src/protocols/quic_handshake.rs`,
/// `create_quic_capabilities`). Keep this in sync with the production
/// constructor — that is the entire point of the test. If you change
/// one, change the other and re-bless the hex.
fn quic_capabilities_shape() -> HandshakeCapabilities {
    let mut caps = HandshakeCapabilities::default();
    caps.protocols = vec!["quic".to_string()];
    caps.pqc_capability = PqcCapability::Kyber1024Dilithium5;
    caps
}

fn make_identity(device: &str) -> lib_identity::ZhtpIdentity {
    lib_identity::ZhtpIdentity::new_unified(
        lib_identity::IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        device,
        None,
    )
    .expect("identity")
}

/// The fixed channel-binding bytes both sides share for this test. The
/// production QUIC adapter exports a binding from the QUIC connection's
/// keying material via `Connection::export_keying_material`; here we
/// substitute a constant so the captured `ClientHello` bytes are bit-
/// deterministic across runs (different bindings → different signed
/// transcripts → different captured bytes).
const TEST_CHANNEL_BINDING: [u8; 32] = [0xAA; 32];

fn make_context() -> (HandshakeContext, tempfile::TempDir) {
    let tmp = tempdir().expect("tempdir");
    let path = tmp.path().join("nonce_cache");
    let epoch = lib_network::handshake::NetworkEpoch::from_chain_id(0);
    let cache = NonceCache::open(&path, 3600, 10_000, epoch).expect("nonce cache");
    // Match the in-tree `test_happy_path_handshake` shape: a single
    // shared context with a fixed channel binding. `handshake_as_initiator`
    // and `handshake_as_responder` each apply `with_roles` internally,
    // so we don't pre-assign roles here.
    let ctx = HandshakeContext::new(cache).with_channel_binding(TEST_CHANNEL_BINDING.to_vec());
    (ctx, tmp)
}

/// AsyncRead+AsyncWrite wrapper that tees every byte it reads into a
/// shared `Vec`. Used to capture the bytes the responder pulls off the
/// wire, which by construction is exactly what the initiator put on it.
struct CapturingRead {
    inner: DuplexStream,
    captured: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for CapturingRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        if after > before {
            if let Ok(mut guard) = this.captured.lock() {
                guard.extend_from_slice(&buf.filled()[before..after]);
            }
        }
        res
    }
}

impl AsyncWrite for CapturingRead {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Drive the canonical initiator and responder to a successful
/// roundtrip while tee-ing the responder's read stream into a captured
/// `Vec`. Print the captured bytes (4-byte length prefix + ClientHello
/// payload) as hex so any alternative implementation can do the same
/// and diff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_client_hello_bytes_for_diff() {
    let client_identity = make_identity("test-client");
    let server_identity = make_identity("test-server");
    let (ctx, _nonce_dir) = make_context();
    let client_ctx = ctx.clone();
    let server_ctx = ctx.clone();
    let caps = quic_capabilities_shape();

    let (mut client_stream, server_inner) = duplex(16 * 1024 * 1024);
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let mut server_stream = CapturingRead {
        inner: server_inner,
        captured: Arc::clone(&captured),
    };

    let client_caps = caps.clone();
    let server_caps = caps.clone();

    let (client_result, server_result) = tokio::try_join!(
        async {
            handshake_as_initiator(
                &mut client_stream,
                &client_ctx,
                &client_identity,
                client_caps,
            )
            .await
        },
        async {
            handshake_as_responder(
                &mut server_stream,
                &server_ctx,
                &server_identity,
                server_caps,
            )
            .await
        }
    )
    .expect("canonical pair should round-trip");

    assert_eq!(
        client_result.session_key, server_result.session_key,
        "session keys must match"
    );

    let bytes = captured.lock().expect("captured mutex").clone();

    // The responder reads ClientHello first (length prefix + body) and
    // then ClientFinish (length prefix + body) on the same stream. Cut
    // the ClientHello off at the first message boundary.
    assert!(
        bytes.len() >= 4,
        "captured at least a length prefix ({} bytes)",
        bytes.len()
    );
    let hello_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    assert!(
        bytes.len() >= 4 + hello_len,
        "captured at least the full ClientHello (need {} got {})",
        4 + hello_len,
        bytes.len()
    );
    let client_hello = &bytes[..4 + hello_len];

    eprintln!("\n=== canonical ClientHello on the wire ===");
    eprintln!("client DID:    {}", client_identity.did);
    eprintln!("payload bytes: {}", hello_len);
    eprintln!("wire bytes (length-prefix + body), hex, 32 bytes per row:");
    for (i, chunk) in client_hello.chunks(32).enumerate() {
        eprintln!("  {:04x}: {}", i * 32, hex::encode(chunk));
    }
    eprintln!("=== end ClientHello ===\n");
    eprintln!(
        "To diff against quinn-ffi's `handshake_with_transcript` output:"
    );
    eprintln!(
        "  1. Build the mobile-side equivalent that logs the same first {} bytes",
        4 + hello_len
    );
    eprintln!("  2. Compare hex side-by-side (e.g. `diff <(echo …) <(echo …)`)");
    eprintln!("  3. First differing offset is the divergence point.\n");

    // Sanity check: ClientHello is well below 16 MB so the length-prefix
    // high byte should be 0x00. If this ever changes the responder's
    // first-byte log will report something other than `first_byte=0`
    // and the production diagnostic loses its meaning.
    assert_eq!(
        client_hello[0], 0,
        "ClientHello length-prefix high byte must be 0 for sub-16MB"
    );
}
