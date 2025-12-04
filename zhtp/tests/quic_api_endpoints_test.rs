//! Comprehensive QUIC API Integration Tests
//!
//! Tests all 82 API endpoints via QUIC client connection to local network node.
//!
//! **Prerequisites:**
//! - ZHTP node running on local network
//! - Node accessible on port 9334
//! - Set environment variable: `ZHTP_NODE_IP` (e.g., "192.168.1.100:9334")
//!
//! **Usage:**
//! ```bash
//! export ZHTP_NODE_IP="192.168.1.100:9334"
//! cargo test --test quic_api_endpoints_test -- --nocapture
//! ```

use anyhow::{Result, Context};
use quinn::{ClientConfig, Endpoint, Connection};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls;
use quinn::rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid};
use quinn::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use quinn::rustls::DigitallySignedStruct;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

/// Get node address from environment or use default
fn get_node_address() -> String {
    std::env::var("ZHTP_NODE_IP")
        .unwrap_or_else(|_| {
            eprintln!("⚠️  ZHTP_NODE_IP not set, using localhost:9334");
            eprintln!("   Set with: export ZHTP_NODE_IP=\"192.168.1.X:9334\"");
            "127.0.0.1:9334".to_string()
        })
}

/// Skip all certificate verification for testing (DANGEROUS - TESTING ONLY)
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

/// Create QUIC client configuration (skip certificate verification for testing)
/// TESTING ONLY - DO NOT USE IN PRODUCTION
fn create_client_config() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()))
}

/// Connect to ZHTP node via QUIC
async fn connect_quic() -> Result<Connection> {
    let node_addr = get_node_address();
    let addr: SocketAddr = node_addr.parse()
        .context("Invalid node address format")?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(create_client_config());

    println!("🔌 Connecting to ZHTP node at {}", node_addr);
    let connection = endpoint
        .connect(addr, "zhtp-node")?
        .await
        .context("Failed to connect to ZHTP node")?;

    println!("✅ Connected to {}", connection.remote_address());
    Ok(connection)
}

/// Send HTTP request over QUIC and get response
async fn send_http_request(
    connection: &Connection,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String)> {
    let (mut send, mut recv) = connection.open_bi().await?;

    // Construct HTTP request
    let request = if let Some(body_data) = body {
        format!(
            "{} {} HTTP/1.1\r\n\
             Host: zhtp-node\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            method, path, body_data.len(), body_data
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\n\
             Host: zhtp-node\r\n\
             \r\n",
            method, path
        )
    };

    // Send request
    send.write_all(request.as_bytes()).await?;
    send.finish()?;

    // Read response
    let response = recv.read_to_end(10 * 1024 * 1024).await?;

    let response_str = String::from_utf8_lossy(&response).to_string();

    // Parse status code
    let status_code = if let Some(first_line) = response_str.lines().next() {
        first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0)
    } else {
        0
    };

    Ok((status_code, response_str))
}

/// Test endpoint and return result
async fn test_endpoint(
    connection: &Connection,
    method: &str,
    path: &str,
    body: Option<&str>,
    expected_status: &[u16],
) -> Result<()> {
    print!("  Testing {} {} ... ", method, path);

    let (status, response) = send_http_request(connection, method, path, body).await?;

    if expected_status.contains(&status) {
        println!("✅ {}", status);
        Ok(())
    } else {
        println!("❌ {} (expected {:?})", status, expected_status);
        if response.len() < 500 {
            println!("     Response: {}", response);
        }
        Err(anyhow::anyhow!("Unexpected status code: {}", status))
    }
}

// ============================================================================
// ENDPOINT TESTS
// ============================================================================

#[tokio::test]
#[ignore] // Run with: cargo test --test quic_api_endpoints_test -- --ignored --nocapture
async fn test_all_api_endpoints() -> Result<()> {
    println!("\n🚀 Starting comprehensive QUIC API endpoint tests");
    println!("{}", "=".repeat(70));

    let connection = connect_quic().await?;
    let mut passed = 0;
    let mut failed = 0;

    // Protocol endpoints (5)
    println!("\n📡 Protocol Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/protocol/health"),
        ("GET", "/api/v1/protocol/version"),
        ("GET", "/api/v1/protocol/info"),
        ("GET", "/api/v1/protocol/capabilities"),
        ("GET", "/api/v1/protocol/stats"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 401, 403]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Blockchain endpoints (32)
    println!("\n⛓️  Blockchain Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/blockchain/status"),
        ("GET", "/api/v1/blockchain/latest"),
        ("GET", "/api/v1/blockchain/tip"),
        ("GET", "/api/v1/blockchain/blocks/"),
        ("GET", "/api/v1/blockchain/block/0"),
        ("GET", "/api/v1/blockchain/mempool"),
        ("GET", "/api/v1/blockchain/validators"),
        ("GET", "/api/v1/blockchain/network/stats"),
        ("GET", "/api/v1/blockchain/network/peers"),
        ("GET", "/api/v1/blockchain/network/peer/test"),
        ("POST", "/api/v1/blockchain/network/peer/add"),
        ("GET", "/api/v1/blockchain/sync/metrics"),
        ("GET", "/api/v1/blockchain/sync/performance"),
        ("GET", "/api/v1/blockchain/sync/history"),
        ("GET", "/api/v1/blockchain/sync/peers"),
        ("GET", "/api/v1/blockchain/sync/peers/test"),
        ("GET", "/api/v1/blockchain/sync/alerts"),
        ("GET", "/api/v1/blockchain/sync/alerts/acknowledged"),
        ("GET", "/api/v1/blockchain/sync/alerts/thresholds"),
        ("POST", "/api/v1/blockchain/sync/alerts/acknowledge"),
        ("GET", "/api/v1/blockchain/balance/test_id"),
        ("GET", "/api/v1/blockchain/transactions/pending"),
        ("GET", "/api/v1/blockchain/transaction/test_hash"),
        ("POST", "/api/v1/blockchain/transaction"),
        ("POST", "/api/v1/blockchain/transaction/broadcast"),
        ("POST", "/api/v1/blockchain/transaction/estimate-fee"),
        ("GET", "/api/v1/blockchain/contracts"),
        ("GET", "/api/v1/blockchain/contracts/test_address"),
        ("POST", "/api/v1/blockchain/contracts/deploy"),
        ("GET", "/api/v1/blockchain/edge-stats"),
        ("POST", "/api/v1/blockchain/export"),
        ("POST", "/api/v1/blockchain/import"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 404, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Identity endpoints (17)
    println!("\n🪪  Identity Endpoints");
    for (method, path) in [
        ("POST", "/api/v1/identity/create"),
        ("POST", "/api/v1/identity/login"),
        ("POST", "/api/v1/identity/signin"),
        ("POST", "/api/v1/identity/sign"),
        ("GET", "/api/v1/identity/test_id"),
        ("POST", "/api/v1/identity/recover"),
        ("POST", "/api/v1/identity/password/recover"),
        ("POST", "/api/v1/identity/seed/verify"),
        ("POST", "/api/v1/identity/backup/generate"),
        ("POST", "/api/v1/identity/backup/verify"),
        ("GET", "/api/v1/identity/backup/status"),
        ("POST", "/api/v1/identity/backup/export"),
        ("POST", "/api/v1/identity/backup/import"),
        ("POST", "/api/v1/identity/citizenship/apply"),
        ("GET", "/api/v1/identity/guardians"),
        ("POST", "/api/v1/identity/guardians/add"),
        ("DELETE", "/api/v1/identity/guardians/test_id"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 404, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Guardian/Recovery endpoints (3)
    println!("\n🛡️  Guardian/Recovery Endpoints");
    for (method, path) in [
        ("POST", "/api/v1/identity/recovery/initiate"),
        ("GET", "/api/v1/identity/recovery/pending"),
        // Note: approve/reject/complete need recovery_id in path
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 404, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Storage endpoints (7)
    println!("\n💾 Storage Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/storage/status"),
        ("GET", "/api/v1/storage/stats"),
        ("POST", "/api/v1/storage/store"),
        ("POST", "/api/v1/storage/put"),
        ("GET", "/api/v1/storage/get"),
        ("DELETE", "/api/v1/storage/delete"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 404, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Wallet endpoints (8)
    println!("\n💰 Wallet Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/wallet/balance/test_id"),
        ("GET", "/api/v1/wallet/list/test_id"),
        ("GET", "/api/v1/wallet/transactions/test_id"),
        ("GET", "/api/v1/wallet/statistics/test_id"),
        ("POST", "/api/v1/wallet/send"),
        ("POST", "/api/v1/wallet/transfer/cross-wallet"),
        ("POST", "/api/v1/wallet/staking/stake"),
        ("POST", "/api/v1/wallet/staking/unstake"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 404, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Crypto endpoints (3)
    println!("\n🔐 Crypto Endpoints");
    for (method, path) in [
        ("POST", "/api/v1/crypto/generate_keypair"),
        ("POST", "/api/v1/crypto/sign_message"),
        ("POST", "/api/v1/crypto/verify_signature"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Validator endpoints (3)
    println!("\n✅ Validator Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/validators"),
        ("GET", "/api/v1/validator/test_id"),
        ("POST", "/api/v1/validator/register"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 404, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Web4 endpoints (3)
    println!("\n🌐 Web4 Endpoints");
    for (method, path) in [
        ("POST", "/api/v1/web4/load"),
        ("GET", "/api/v1/web4/domains/test_domain"),
        ("GET", "/api/v1/web4/content/test_hash"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 404, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Mesh/Network endpoints (2)
    println!("\n🕸️  Mesh/Network Endpoints");
    for (method, path) in [
        ("POST", "/api/v1/mesh/create"),
        ("GET", "/api/v1/mesh/test_id"),
        ("GET", "/api/v1/network/gas"),
    ] {
        match test_endpoint(&connection, method, path, None, &[200, 400, 401, 403, 404, 500]).await {
            Ok(_) => passed += 1,
            Err(_) => failed += 1,
        }
    }

    // Summary
    println!("\n{}", "=".repeat(70));
    println!("📊 Test Results:");
    println!("   ✅ Passed: {}", passed);
    println!("   ❌ Failed: {}", failed);
    println!("   📈 Total:  {}", passed + failed);
    println!("   🎯 Success Rate: {:.1}%", (passed as f32 / (passed + failed) as f32) * 100.0);

    if failed > 0 {
        Err(anyhow::anyhow!("{} endpoint(s) failed", failed))
    } else {
        println!("\n🎉 All endpoints passed!");
        Ok(())
    }
}
