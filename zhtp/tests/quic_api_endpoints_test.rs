//! Comprehensive QUIC API Integration Tests
//!
//! Tests all implemented API endpoints via QUIC client connection to local network node.
//!
//! **Prerequisites:**
//! - ZHTP node running on local network
//! - Node accessible on port 9334
//! - Set environment variable: `ZHTP_NODE_IP` (e.g., "192.168.1.100:9334")
//!
//! **Usage:**
//! ```bash
//! export ZHTP_NODE_IP="192.168.1.100:9334"
//! cargo test --test quic_api_endpoints_test -- --ignored --nocapture
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

/// Get mock request body for POST endpoints
fn get_mock_body(path: &str) -> Option<String> {
    match path {
        // Blockchain endpoints
        "/api/v1/blockchain/transaction" => Some(r#"{"from":"test_from","to":"test_to","amount":100,"fee":10,"signature":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string()),
        "/api/v1/blockchain/transaction/estimate-fee" => Some(r#"{"transaction_size":250,"amount":1000,"priority":"normal"}"#.to_string()),
        "/api/v1/blockchain/transaction/broadcast" => Some(r#"{"transaction_data":"0000"}"#.to_string()),
        "/api/v1/blockchain/contracts/deploy" => Some(r#"{"name":"TestContract","contract_type":"token","code":"test code","initial_state":{}}"#.to_string()),
        // Import expects binary data, empty body will fail - skip in test
        // "/api/v1/blockchain/import" => Some(r#"{}"#.to_string()),

        // Identity endpoints (using valid 64-char hex IDs)
        "/api/v1/identity/create" => Some(r#"{"display_name":"Test User","password":"test_password_123"}"#.to_string()),
        "/api/v1/identity/login" => Some(r#"{"identity_id":"0000000000000000000000000000000000000000000000000000000000000000","password":"test_password"}"#.to_string()),
        "/api/v1/identity/signin" => Some(r#"{"identity_id":"0000000000000000000000000000000000000000000000000000000000000000","password":"test_password"}"#.to_string()),
        "/api/v1/identity/sign" => Some(r#"{"identity_id":"0000000000000000000000000000000000000000000000000000000000000000","message":"test_message"}"#.to_string()),
        "/api/v1/identity/recover" => Some(r#"{"recovery_phrase":"word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20"}"#.to_string()),
        "/api/v1/identity/password/recover" => Some(r#"{"recovery_phrase":"word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20","new_password":"new_password_123"}"#.to_string()),
        "/api/v1/identity/seed/verify" => Some(r#"{"identity_id":"0000000000000000000000000000000000000000000000000000000000000000","seed_phrase":"test seed phrase"}"#.to_string()),
        "/api/v1/identity/backup/generate" => Some(r#"{"identity_id":"0000000000000000000000000000000000000000000000000000000000000000","session_token":"test_token"}"#.to_string()),
        "/api/v1/identity/backup/verify" => Some(r#"{"identity_id":"0000000000000000000000000000000000000000000000000000000000000000","recovery_phrase":"word1 word2 word3"}"#.to_string()),
        "/api/v1/identity/backup/export" => Some(r#"{"identity_id":"0000000000000000000000000000000000000000000000000000000000000000","passphrase":"test_passphrase"}"#.to_string()),
        "/api/v1/identity/backup/import" => Some(r#"{"backup_data":"test_backup","password":"test_password"}"#.to_string()),
        "/api/v1/identity/citizenship/apply" => Some(r#"{"identity_id":"test_id"}"#.to_string()),

        // Storage endpoints
        "/api/v1/storage/store" => Some(r#"{"data":"test_data_content","metadata":{"key":"test_key"}}"#.to_string()),
        "/api/v1/storage/put" => Some(r#"{"key":"test_key","value":"test_value"}"#.to_string()),
        "/api/v1/storage/get" => Some(r#"{"key":"test_key"}"#.to_string()),
        "/api/v1/storage/delete" => Some(r#"{"key":"test_key"}"#.to_string()),

        // Wallet endpoints (using valid 64-char hex IDs)
        "/api/v1/wallet/send" => Some(r#"{"from_identity":"0000000000000000000000000000000000000000000000000000000000000000","to":"test_recipient","amount":100,"wallet_id":"primary"}"#.to_string()),
        "/api/v1/wallet/transfer/cross-wallet" => Some(r#"{"from_wallet":"primary","to_wallet":"savings","amount":100,"identity_id":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string()),
        "/api/v1/wallet/staking/stake" => Some(r#"{"wallet_id":"test_wallet","amount":1000,"identity_id":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string()),
        "/api/v1/wallet/staking/unstake" => Some(r#"{"wallet_id":"test_wallet","amount":500,"identity_id":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string()),

        // Crypto endpoints
        "/api/v1/crypto/generate_keypair" => Some(r#"{}"#.to_string()),
        "/api/v1/crypto/sign_message" => Some(r#"{"message":"test_message","identity_id":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string()),
        "/api/v1/crypto/verify_signature" => Some(r#"{"message":"test_message","signature":"0000000000000000000000000000000000000000000000000000000000000000","public_key":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string()),

        // Web4 endpoints
        "/api/v1/web4/load" => Some(r#"{"url":"test.zhtp"}"#.to_string()),

        // Mesh endpoints
        "/api/v1/mesh/create" => Some(r#"{"mesh_id":"test_mesh","initial_validators":[]}"#.to_string()),

        // DAO endpoints
        "/api/v1/dao/proposal/create" => Some(r#"{"title":"Test Proposal","description":"Test description","proposer_identity_id":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string()),
        "/api/v1/dao/vote/cast" => Some(r#"{"proposal_id":"test_proposal","vote":true,"voter_identity_id":"0000000000000000000000000000000000000000000000000000000000000000"}"#.to_string()),

        // Network endpoints
        "/api/v1/blockchain/network/peer/add" => Some(r#"{"peer_address":"192.168.1.100:9334"}"#.to_string()),
        "/api/v1/blockchain/sync/alerts/acknowledge" => Some(r#"{"alert_id":"test_alert"}"#.to_string()),

        _ => None,
    }
}

/// Test endpoint and return result
async fn test_endpoint(
    connection: &Connection,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<u16> {
    print!("  Testing {} {} ... ", method, path);

    // Use provided body or get mock body for POST endpoints
    let mock_body = if body.is_none() && (method == "POST" || method == "PUT" || method == "DELETE") {
        get_mock_body(path)
    } else {
        None
    };

    let request_body = body.or_else(|| mock_body.as_deref());

    let (status, response) = send_http_request(connection, method, path, request_body).await?;

    // Success: 200-299
    // Client error but endpoint exists: 400-403, 429
    // Fail: 404 (not found), 500+ (server error)
    let is_success = status >= 200 && status < 300;
    let is_client_error = matches!(status, 400 | 401 | 403 | 429);

    if is_success || is_client_error {
        println!("✅ {}", status);
    } else {
        println!("❌ {} FAILED", status);
        if response.len() < 500 {
            println!("     Response: {}", response);
        }
    }

    Ok(status)
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
    let mut results = Vec::new();

    // Protocol endpoints (5)
    println!("\n📡 Protocol Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/protocol/health"),
        ("GET", "/api/v1/protocol/version"),
        ("GET", "/api/v1/protocol/info"),
        ("GET", "/api/v1/protocol/capabilities"),
        ("GET", "/api/v1/protocol/stats"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Blockchain endpoints (21)
    println!("\n⛓️  Blockchain Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/blockchain/status"),
        ("GET", "/api/v1/blockchain/latest"),
        ("GET", "/api/v1/blockchain/tip"),
        ("GET", "/api/v1/blockchain/block/0"),
        ("GET", "/api/v1/blockchain/mempool"),
        ("GET", "/api/v1/blockchain/validators"),
        ("GET", "/api/v1/blockchain/balance/test_id"),
        ("GET", "/api/v1/blockchain/transactions/pending"),
        ("GET", "/api/v1/blockchain/transaction/test_hash"),
        ("GET", "/api/v1/blockchain/export"),
        ("POST", "/api/v1/blockchain/import"),
        ("POST", "/api/v1/blockchain/transaction"),
        ("POST", "/api/v1/blockchain/transaction/broadcast"),
        ("POST", "/api/v1/blockchain/transaction/estimate-fee"),
        ("GET", "/api/v1/blockchain/contracts"),
        ("GET", "/api/v1/blockchain/contracts/test_address"),
        ("POST", "/api/v1/blockchain/contracts/deploy"),
        ("GET", "/api/v1/blockchain/edge-stats"),
        ("GET", "/api/v1/blockchain/blocks/0/10"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Identity endpoints (13)
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
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Storage endpoints (5)
    println!("\n💾 Storage Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/storage/status"),
        ("GET", "/api/v1/storage/stats"),
        ("POST", "/api/v1/storage/store"),
        ("POST", "/api/v1/storage/put"),
        ("POST", "/api/v1/storage/get"),
        ("DELETE", "/api/v1/storage/delete"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Wallet endpoints (8)
    println!("\n💰 Wallet Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/wallet/balance/test_wallet/test_id"),
        ("GET", "/api/v1/wallet/list/test_id"),
        ("GET", "/api/v1/wallet/transactions/test_id"),
        ("GET", "/api/v1/wallet/statistics/test_id"),
        ("POST", "/api/v1/wallet/send"),
        ("POST", "/api/v1/wallet/transfer/cross-wallet"),
        ("POST", "/api/v1/wallet/staking/stake"),
        ("POST", "/api/v1/wallet/staking/unstake"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Crypto endpoints (3)
    println!("\n🔐 Crypto Endpoints");
    for (method, path) in [
        ("POST", "/api/v1/crypto/generate_keypair"),
        ("POST", "/api/v1/crypto/sign_message"),
        ("POST", "/api/v1/crypto/verify_signature"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Validator endpoints (5)
    println!("\n✅ Validator Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/validators"),
        ("GET", "/api/v1/validator/test_id"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Web4 endpoints (12)
    println!("\n🌐 Web4 Endpoints");
    for (method, path) in [
        ("POST", "/api/v1/web4/load"),
        ("GET", "/api/v1/web4/domains/test_domain"),
        ("GET", "/api/v1/web4/statistics"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Network endpoints (19)
    println!("\n🌐 Network Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/network/gas"),
        ("GET", "/api/v1/blockchain/network/peers"),
        ("GET", "/api/v1/blockchain/network/stats"),
        ("GET", "/api/v1/blockchain/sync/metrics"),
        ("GET", "/api/v1/blockchain/sync/performance"),
        ("GET", "/api/v1/blockchain/sync/alerts"),
        ("GET", "/api/v1/blockchain/sync/history"),
        ("GET", "/api/v1/blockchain/sync/peers"),
        ("POST", "/api/v1/blockchain/network/peer/add"),
        ("POST", "/api/v1/blockchain/sync/alerts/acknowledge"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Mesh endpoints (5)
    println!("\n🕸️  Mesh Endpoints");
    for (method, path) in [
        ("POST", "/api/v1/mesh/create"),
        ("GET", "/api/v1/mesh/test_id/status"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // DAO endpoints (14)
    println!("\n🏛️  DAO Endpoints");
    for (method, path) in [
        ("GET", "/api/v1/dao/treasury/status"),
        ("GET", "/api/v1/dao/proposals/list"),
        ("GET", "/api/v1/dao/data"),
        ("POST", "/api/v1/dao/proposal/create"),
        ("POST", "/api/v1/dao/vote/cast"),
    ] {
        let status = test_endpoint(&connection, method, path, None).await?;
        results.push((path, status));
    }

    // Summary
    println!("\n{}", "=".repeat(70));
    println!("📊 Test Results:");

    let total = results.len();
    let success = results.iter().filter(|(_, s)| *s >= 200 && *s < 300).count();
    let client_error = results.iter().filter(|(_, s)| matches!(*s, 400 | 401 | 403 | 429)).count();
    let not_found = results.iter().filter(|(_, s)| *s == 404).count();
    let server_error = results.iter().filter(|(_, s)| *s >= 500).count();

    println!("   ✅ Success (200-299): {}", success);
    println!("   ⚠️  Client Error (400-403, 429): {}", client_error);
    println!("   ❌ Not Found (404): {}", not_found);
    println!("   ❌ Server Error (500+): {}", server_error);
    println!("   📈 Total Tested: {}", total);

    if not_found > 0 || server_error > 0 {
        println!("\n❌ FAILURES FOUND:");
        for (path, status) in &results {
            if *status == 404 || *status >= 500 {
                println!("   {} - {}", status, path);
            }
        }
        Err(anyhow::anyhow!("{} endpoints failed (404 or 500+)", not_found + server_error))
    } else {
        println!("\n🎉 All endpoints reachable!");
        Ok(())
    }
}
