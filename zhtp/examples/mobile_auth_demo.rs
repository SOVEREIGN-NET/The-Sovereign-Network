//! mobile_auth_demo — Issue #1877 end-to-end CLI demo
//!
//! Exercises the full mobile-to-web authentication delegation flow against a
//! running ZHTP node using real Dilithium5 post-quantum keys.
//!
//! ## Wire protocol
//!
//! The ZHTP network is QUIC-only. This client uses `quinn` to dial the node's
//! QUIC endpoint (mesh_port, default 9334), then frames each API call as
//! native ZHTP wire format on a fresh bidirectional QUIC stream:
//!
//! ```text
//!   magic 4B  | version 1B | length 4B BE | payload (CBOR-serialized ZhtpRequest)
//!   "ZHTP"    | 0x01       | u32          | ...
//! ```
//!
//! See `zhtp/src/server/zhtp/serialization.rs` for the format definition.

use anyhow::{anyhow, Context, Result};
use lib_crypto::post_quantum::dilithium::{dilithium5_keypair, dilithium5_sign};
use lib_protocols::types::{ZhtpHeaders, ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls;
use quinn::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use quinn::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use quinn::rustls::DigitallySignedStruct;
use quinn::{ClientConfig, Connection, Endpoint};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_NODE_ADDR: &str = "127.0.0.1:9334";
const ZHTP_MAGIC: &[u8; 4] = b"ZHTP";
const ZHTP_VERSION: u8 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// QUIC client setup (skip TLS verification — testing only)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>],
        _: &ServerName<'_>, _: &[u8], _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct,
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

fn create_client_config() -> ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![
        b"zhtp-public/1".to_vec(),
        b"zhtp-http/1".to_vec(),
    ];
    ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()))
}

async fn connect_quic(addr: SocketAddr) -> Result<(Endpoint, Connection)> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(create_client_config());
    let connection = endpoint
        .connect(addr, "zhtp-node")?
        .await
        .context("Failed to connect to ZHTP node over QUIC")?;
    Ok((endpoint, connection))
}

// ─────────────────────────────────────────────────────────────────────────────
// Native ZHTP framing
// ─────────────────────────────────────────────────────────────────────────────

fn build_request(method: ZhtpMethod, uri: &str, body: Vec<u8>, bearer: Option<&str>) -> ZhtpRequest {
    let mut headers = ZhtpHeaders::new()
        .with_content_type("application/json".to_string())
        .with_content_length(body.len() as u64);
    if let Some(token) = bearer {
        headers.authorization = Some(format!("Bearer {}", token));
    }
    ZhtpRequest {
        method,
        uri: uri.to_string(),
        version: "ZHTP/1.0".to_string(),
        headers,
        body,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        requester: None,
        auth_proof: None,
    }
}

fn frame_message(payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(9 + payload.len());
    msg.extend_from_slice(ZHTP_MAGIC);
    msg.push(ZHTP_VERSION);
    msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    msg.extend_from_slice(payload);
    msg
}

fn parse_response_frame(data: &[u8]) -> Result<ZhtpResponse> {
    if data.len() < 9 {
        return Err(anyhow!("response too short: {} bytes", data.len()));
    }
    if &data[0..4] != ZHTP_MAGIC {
        return Err(anyhow!(
            "invalid ZHTP magic in response: {:?}",
            &data[..4.min(data.len())]
        ));
    }
    if data[4] != ZHTP_VERSION {
        return Err(anyhow!("unsupported ZHTP version: {}", data[4]));
    }
    let length = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    if data.len() < 9 + length {
        return Err(anyhow!(
            "incomplete response: need {} bytes, got {}",
            9 + length,
            data.len()
        ));
    }
    let payload = &data[9..9 + length];
    // Server may respond in any of the 3 formats. Try CBOR first (default),
    // then JSON, then bincode.
    if let Ok(r) = ciborium::from_reader::<ZhtpResponse, _>(payload) {
        return Ok(r);
    }
    if let Ok(r) = serde_json::from_slice::<ZhtpResponse>(payload) {
        return Ok(r);
    }
    let r: ZhtpResponse = bincode::deserialize(payload)
        .with_context(|| format!("failed to deserialize response payload ({} bytes)", payload.len()))?;
    Ok(r)
}

async fn send_request(conn: &Connection, request: ZhtpRequest) -> Result<ZhtpResponse> {
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi failed")?;

    // Serialize the request as CBOR (server auto-detects format)
    let mut payload = Vec::new();
    ciborium::into_writer(&request, &mut payload).context("CBOR serialize ZhtpRequest")?;
    let frame = frame_message(&payload);

    send.write_all(&frame).await?;
    send.finish()?;

    let raw = recv.read_to_end(16 * 1024 * 1024).await?;
    parse_response_frame(&raw)
}

fn body_json(resp: &ZhtpResponse) -> Result<Value> {
    if resp.body.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&resp.body)
        .with_context(|| format!("body is not JSON: {}", String::from_utf8_lossy(&resp.body)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let node_addr_str = std::env::var("NODE_ADDR").unwrap_or_else(|_| DEFAULT_NODE_ADDR.to_string());
    let node_addr: SocketAddr = node_addr_str
        .parse()
        .with_context(|| format!("invalid NODE_ADDR: {}", node_addr_str))?;

    println!("\n=== AUTH-1877 Mobile Auth Demo (QUIC + native ZHTP framing) ===");
    println!("Node: {}\n", node_addr);

    let (_endpoint, conn) = connect_quic(node_addr)
        .await
        .with_context(|| format!("could not connect to {} over QUIC", node_addr))?;
    println!("    QUIC connected: {}\n", conn.remote_address());

    // ── Step 1: challenge ───────────────────────────────────────────────────
    print!("[1/7] POST /challenge ... ");
    let body1 = serde_json::to_vec(&json!({
        "capabilities": [
            { "type": "read_balance" },
            { "type": "read_identity" }
        ]
    }))?;
    let resp1 = send_request(
        &conn,
        build_request(ZhtpMethod::Post, "/api/v1/auth/mobile/challenge", body1, None),
    )
    .await
    .context("POST /challenge failed")?;
    if !matches!(resp1.status, ZhtpStatus::Ok | ZhtpStatus::Created) {
        anyhow::bail!(
            "challenge endpoint returned {:?}: {}",
            resp1.status,
            String::from_utf8_lossy(&resp1.body)
        );
    }
    let challenge = body_json(&resp1)?;
    let session_id = challenge["session_id"].as_str().context("missing session_id")?;
    let challenge_nonce = challenge["challenge_nonce"]
        .as_str()
        .context("missing challenge_nonce")?;
    let qr_payload = challenge["qr_payload"].as_str().unwrap_or("");
    println!("OK");
    println!("    session_id      = {}", session_id);
    println!("    challenge_nonce = {}…", &challenge_nonce[..16]);
    println!(
        "    qr_payload      = {}…",
        &qr_payload[..40.min(qr_payload.len())]
    );

    // ── Step 2: keypair ─────────────────────────────────────────────────────
    print!("[2/7] Generate Dilithium5 keypair ... ");
    let (pk_bytes, sk_bytes) = dilithium5_keypair();
    let public_key_hex = hex::encode(&pk_bytes);
    println!("OK");
    println!(
        "    pk_bytes = {} bytes, pk_hex[..16] = {}…",
        pk_bytes.len(),
        &public_key_hex[..16]
    );

    // ── Step 3: sign nonce ──────────────────────────────────────────────────
    print!("[3/7] Sign challenge nonce with Dilithium5 ... ");
    let nonce_bytes = hex::decode(challenge_nonce).context("challenge_nonce not valid hex")?;
    let signature_bytes =
        dilithium5_sign(&nonce_bytes, &sk_bytes).context("Dilithium5 signing failed")?;
    let signature_hex = hex::encode(&signature_bytes);
    println!("OK");
    println!(
        "    sig_bytes = {} bytes, sig_hex[..16] = {}…",
        signature_bytes.len(),
        &signature_hex[..16]
    );

    // ── Step 4: verify ──────────────────────────────────────────────────────
    print!("[4/7] POST /verify (submit Dilithium5 signature) ... ");
    let identity_hex = hex::encode([0xabu8; 32]);
    let body4 = serde_json::to_vec(&json!({
        "session_id":     session_id,
        "public_key_hex": public_key_hex,
        "signature_hex":  signature_hex,
        "identity_hex":   identity_hex,
    }))?;
    let resp4 = send_request(
        &conn,
        build_request(ZhtpMethod::Post, "/api/v1/auth/mobile/verify", body4, None),
    )
    .await
    .context("POST /verify failed")?;
    if !matches!(resp4.status, ZhtpStatus::Ok | ZhtpStatus::Created) {
        anyhow::bail!(
            "verify endpoint returned {:?}: {}",
            resp4.status,
            String::from_utf8_lossy(&resp4.body)
        );
    }
    let verify_res = body_json(&resp4)?;
    let access_token = verify_res["access_token"]
        .as_str()
        .context("missing access_token")?;
    let expires_at = verify_res["access_expires_at"].as_u64().unwrap_or(0);
    println!("OK");
    println!("    access_token = {}…", &access_token[..16]);
    println!("    expires_at   = {} (unix)", expires_at);

    // ── Step 5: validate Bearer ─────────────────────────────────────────────
    print!("[5/7] GET /session (validate Bearer) ... ");
    let resp5 = send_request(
        &conn,
        build_request(
            ZhtpMethod::Get,
            "/api/v1/auth/mobile/session",
            Vec::new(),
            Some(access_token),
        ),
    )
    .await
    .context("GET /session failed")?;
    if !matches!(resp5.status, ZhtpStatus::Ok) {
        anyhow::bail!(
            "session endpoint rejected Bearer ({:?}): {}",
            resp5.status,
            String::from_utf8_lossy(&resp5.body)
        );
    }
    let session_info = body_json(&resp5)?;
    println!("OK");
    println!(
        "    granted_capabilities = {:?}",
        session_info["granted_capabilities"]
    );

    // ── Step 6: poll events ─────────────────────────────────────────────────
    print!("[6/7] GET /session/events (poll event log) ... ");
    let path6 = format!(
        "/api/v1/auth/session/events?session_id={}&since=0",
        session_id
    );
    let resp6 = send_request(
        &conn,
        build_request(ZhtpMethod::Get, &path6, Vec::new(), Some(access_token)),
    )
    .await
    .context("GET /session/events failed")?;
    if !matches!(resp6.status, ZhtpStatus::Ok) {
        anyhow::bail!(
            "events endpoint returned {:?}: {}",
            resp6.status,
            String::from_utf8_lossy(&resp6.body)
        );
    }
    let events_res = body_json(&resp6)?;
    let empty: Vec<Value> = Vec::new();
    let events = events_res["events"].as_array().unwrap_or(&empty);
    println!("OK ({} event(s))", events.len());
    for e in events {
        println!(
            "    seq={} event={}",
            e["seq"].as_u64().unwrap_or(0),
            e["event"].as_str().unwrap_or("?")
        );
    }

    // ── Step 7: signout ─────────────────────────────────────────────────────
    print!("[7/7] POST /signout (revoke session) ... ");
    let resp7 = send_request(
        &conn,
        build_request(
            ZhtpMethod::Post,
            "/api/v1/auth/mobile/signout",
            Vec::new(),
            Some(access_token),
        ),
    )
    .await
    .context("POST /signout failed")?;
    if !matches!(resp7.status, ZhtpStatus::Ok | ZhtpStatus::NoContent) {
        anyhow::bail!(
            "signout returned {:?}: {}",
            resp7.status,
            String::from_utf8_lossy(&resp7.body)
        );
    }
    println!("OK");

    println!("\n=== Demo complete — all 7 steps passed ===\n");
    Ok(())
}
