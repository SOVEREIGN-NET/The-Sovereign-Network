//! UHP v2 handshake round-trip test over a real QUIC connection.
//!
//! Pairs `lib_network::protocols::quic_handshake::handshake_as_initiator`
//! against `lib_network::protocols::quic_handshake::handshake_as_responder`
//! on a real quinn `Connection`. This is the path the lib-client FFI uses
//! when the mobile app makes an authenticated request.
//!
//! Why this test exists: the core handshake (`handshake_as_initiator` /
//! `handshake_as_responder` in `lib_network::handshake::core`) passes its
//! existing roundtrip test against `tokio::io::duplex` streams, so the
//! protocol-level message exchange is provably correct. The reported
//! production failure ("Failed to read length prefix byte 0: connection
//! lost", "UHP+Kyber handshake failed" mid-flight) lives one layer up, in
//! the QUIC adapter — channel-binding export, stream framing, finish
//! semantics. This test exercises exactly that layer with the same two
//! functions the mobile/server pair use on the wire.
//!
//! If this test fails locally, the bug is reproducible in lib-network's CI
//! without any mobile build round-trip.

use lib_network::constants::ALPN_CONTROL_PLANE_V2;
use lib_network::handshake::{HandshakeContext, NonceCache};
use lib_network::protocols::quic_handshake::{handshake_as_initiator, handshake_as_responder};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls;
use quinn::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use quinn::rustls::DigitallySignedStruct;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

/// Accept-any cert verifier — TEST ONLY. The whole point of this test is to
/// exercise the UHP-v2 layer, not TLS PKI. The UHP-v2 handshake itself is
/// what carries identity/authentication, so the TLS cert is just transport.
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn install_rustls_provider_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn build_server_endpoint() -> (Endpoint, SocketAddr) {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server tls config");
    crypto.alpn_protocols = vec![ALPN_CONTROL_PLANE_V2.to_vec()];
    let server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto).expect("server quic config"),
    ));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = Endpoint::server(server_config, bind).expect("server endpoint");
    let addr = endpoint.local_addr().expect("local addr");
    (endpoint, addr)
}

fn build_client_endpoint() -> Endpoint {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN_CONTROL_PLANE_V2.to_vec()];
    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).expect("client quic config"),
    ));
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut endpoint = Endpoint::client(bind).expect("client endpoint");
    endpoint.set_default_client_config(client_config);
    endpoint
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

/// Build a fresh `HandshakeContext` backed by a temp nonce cache. The
/// `TempDir` is returned so the caller can keep it alive in a binding for
/// the duration of the test, and the directory is cleaned up on Drop —
/// no leaked files on disk between runs.
fn make_context() -> (HandshakeContext, tempfile::TempDir) {
    let tmp = tempdir().expect("tempdir");
    let path = tmp.path().join("nonce_cache");
    let epoch = lib_network::handshake::NetworkEpoch::from_chain_id(0);
    let cache = NonceCache::open(&path, 3600, 10_000, epoch).expect("nonce cache");
    (HandshakeContext::new(cache), tmp)
}

/// End-to-end: initiator ↔ responder over a real QUIC bidi stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_handshake_roundtrip_succeeds() {
    install_rustls_provider_once();

    let client_identity = make_identity("test-client");
    let server_identity = make_identity("test-server");
    let client_did = client_identity.did.clone();
    let server_did = server_identity.did.clone();
    // Keep the TempDir bound for the whole test so its Drop runs at the
    // end and the nonce-cache files get cleaned up between runs.
    let (ctx, _nonce_dir) = make_context();

    let (server_endpoint, server_addr) = build_server_endpoint();
    let client_endpoint = build_client_endpoint();

    // Server task: accept one connection and run the responder.
    let server_ctx = ctx.clone();
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server got incoming");
        let conn = incoming.await.expect("server accepted QUIC handshake");
        handshake_as_responder(&conn, &server_identity, &server_ctx).await
    });

    // Client side: connect and run the initiator.
    let conn = client_endpoint
        .connect(server_addr, "localhost")
        .expect("client.connect")
        .await
        .expect("client QUIC handshake");

    let client_result =
        tokio::time::timeout(Duration::from_secs(30), async {
            handshake_as_initiator(&conn, &client_identity, &ctx).await
        })
        .await
        .expect("client handshake didn't deadline")
        .expect("client handshake should succeed");

    let server_result =
        tokio::time::timeout(Duration::from_secs(30), server_handle)
            .await
            .expect("server task didn't deadline")
            .expect("server task didn't panic")
            .expect("server handshake should succeed");

    // Session keys must match. If they don't, transcript or PQC derivation
    // diverged between the two sides.
    assert_eq!(
        client_result.session_key, server_result.session_key,
        "session keys must match between initiator and responder"
    );
    assert_eq!(
        client_result.session_id, server_result.session_id,
        "session IDs must match"
    );

    // DIDs must round-trip — initiator sees server's DID, responder sees
    // client's DID.
    assert_eq!(
        client_result.verified_peer.identity.did, server_did,
        "initiator must see server's DID"
    );
    assert_eq!(
        server_result.verified_peer.identity.did, client_did,
        "responder must see client's DID"
    );
}

// (Earlier draft had a second test asserting `HandshakeCapabilities::default()`
// shape — removed per review: the QUIC adapters use `create_quic_capabilities()`
// internally, not the bare `Default` impl, so the assertion didn't actually
// guard against capability drift on the QUIC path.)
