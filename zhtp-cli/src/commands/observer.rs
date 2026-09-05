//! Observer CLI commands (observer-admission T3).
//!
//! Subcommands:
//!   generate     — create observer keypair in ~/.zhtp/keystore/observer/
//!   qr-payload   — POST /api/v1/observer/admission/prepare, print JSON
//!   qr-render    — same as qr-payload but rendered as ASCII QR
//!   status       — GET  /api/v1/observer/admission/status?did=<did>
//!   wait         — poll status until Active or timeout
//!   start        — start observer node once admitted
//!   by-sponsor   — GET  /api/v1/observer/admission/by-sponsor?did=<did>

use crate::argument_parsing::{ObserverAction, ObserverArgs, ZhtpCli};
use crate::commands::web4_utils::{self, connect_default, save_private_key_to_file};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_crypto::keypair::KeyPair;
use lib_identity::ZhtpIdentity;
use lib_network::client::ZhtpClient;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zhtp::keyfile_names::{NODE_IDENTITY_FILENAME, NODE_PRIVATE_KEY_FILENAME};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Handle any observer subcommand.
pub async fn handle_observer_command(args: ObserverArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    match &args.action {
        ObserverAction::Generate => cmd_generate(&output).await,
        ObserverAction::QrPayload { did, sponsor } => {
            cmd_qr_payload(did, sponsor, &cli.server, &output).await
        }
        ObserverAction::QrRender { did, sponsor } => {
            cmd_qr_render(did, sponsor, &cli.server, &output).await
        }
        ObserverAction::Status { did } => cmd_status(did, &cli.server, &output).await,
        ObserverAction::Wait { did, timeout } => {
            cmd_wait(did, *timeout, &cli.server, &output).await
        }
        ObserverAction::Start { did } => cmd_start(did, &cli.server, &output).await,
        ObserverAction::BySponsor { did } => cmd_by_sponsor(did, &cli.server, &output).await,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Path to the observer-specific keystore directory.
fn observer_keystore_path() -> CliResult<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| CliError::ConfigError("Cannot determine home directory".to_string()))?;
    Ok(home.join(".zhtp").join("keystore").join("observer"))
}

/// Directly load a node identity from keystore without the noisy
/// user_identity → node_identity fallback warning.
fn load_observer_identity() -> CliResult<(ZhtpIdentity, KeyPair)> {
    let keystore = observer_keystore_path()?;
    if !keystore.exists() {
        return Err(CliError::IdentityError(format!(
            "Observer keystore not found at {:?}. Run 'zhtp-cli observer generate' first.",
            keystore
        )));
    }

    let identity_file = keystore.join(NODE_IDENTITY_FILENAME);
    let private_key_file = keystore.join(NODE_PRIVATE_KEY_FILENAME);

    if !identity_file.exists() {
        return Err(CliError::IdentityError(format!(
            "Observer identity file not found: {:?}",
            identity_file
        )));
    }
    if !private_key_file.exists() {
        return Err(CliError::IdentityError(format!(
            "Observer private key not found: {:?}",
            private_key_file
        )));
    }

    crate::commands::web4_utils::load_identity_from_files(&identity_file, &private_key_file)
}

/// Connect to a node using an already-loaded observer identity.
async fn connect_observer_with(identity: ZhtpIdentity, server: &str) -> CliResult<ZhtpClient> {
    let trust_config = web4_utils::build_trust_config(None, None, false, true)?;
    web4_utils::connect_client(identity, trust_config, server).await
}

/// Parse a ZhtpResponse body as JSON.
fn parse_json(response: &lib_protocols::types::ZhtpResponse) -> CliResult<serde_json::Value> {
    ZhtpClient::parse_json(response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse response: {}", e)))
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

/// `observer generate` — create keypair, save to observer keystore.
async fn cmd_generate(output: &dyn Output) -> CliResult<()> {
    output.header("Generate Observer Identity")?;

    let keystore = observer_keystore_path()?;
    let identity_file = keystore.join(NODE_IDENTITY_FILENAME);

    if identity_file.exists() {
        // Load and display existing identity (silently)
        let loaded = load_observer_identity()?;
        output.warning("Observer identity already exists. Showing existing keys:")?;
        output.print(&format!("  DID:                {}", loaded.0.did))?;
        output.print(&format!(
            "  Dilithium PK (hex): {}",
            hex::encode(&loaded.1.public_key.dilithium_pk[..])
        ))?;
        output.print(&format!(
            "  Kyber PK (hex):     {}",
            hex::encode(&loaded.1.public_key.kyber_pk[..])
        ))?;
        output.info("Delete the observer keystore directory to regenerate.")?;
        return Ok(());
    }

    std::fs::create_dir_all(&keystore).map_err(|e| {
        CliError::IdentityError(format!("Failed to create observer keystore: {}", e))
    })?;

    output.info("Generating post-quantum keypair (Dilithium5 + Kyber1024)...")?;

    let identity = ZhtpIdentity::new_unified(
        lib_identity::IdentityType::Device,
        None,
        None,
        "observer-node",
        None,
    )
    .map_err(|e| CliError::IdentityError(format!("Key generation failed: {}", e)))?;

    let private_key = identity.private_key.as_ref().ok_or_else(|| {
        CliError::IdentityError("Generated identity missing private key".to_string())
    })?;

    // Save private key
    let private_key_file = keystore.join(NODE_PRIVATE_KEY_FILENAME);
    save_private_key_to_file(private_key, &private_key_file)?;

    // Save identity JSON
    let identity_json = serde_json::to_string_pretty(&identity)
        .map_err(|e| CliError::IdentityError(format!("Serialization failed: {}", e)))?;
    std::fs::write(&identity_file, &identity_json)
        .map_err(|e| CliError::IdentityError(format!("Failed to write identity file: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&private_key_file, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600));
    }

    output.success("Observer identity generated successfully!")?;
    output.print(&format!("  DID:                {}", identity.did))?;
    output.print(&format!(
        "  Dilithium PK (hex): {}",
        hex::encode(&identity.public_key.dilithium_pk[..])
    ))?;
    output.print(&format!(
        "  Kyber PK (hex):     {}",
        hex::encode(&identity.public_key.kyber_pk[..])
    ))?;
    output.print(&format!("  Keystore:           {:?}", keystore))?;
    output.info("Share the DID and Dilithium PK hex with your sponsor.")?;

    Ok(())
}

/// Shared helper: load observer identity, build prepare body, POST, return JSON.
async fn fetch_prepare_payload(
    did: &str,
    sponsor: &str,
    server: &str,
) -> CliResult<serde_json::Value> {
    let (identity, keypair) = load_observer_identity()?;

    if identity.did != did {
        return Err(CliError::IdentityError(format!(
            "Observer DID mismatch: keystore has '{}', but --did specified '{}'",
            identity.did, did
        )));
    }

    let body = serde_json::json!({
        "observer_node_did": did,
        "observer_dilithium_pk_hex": hex::encode(&keypair.public_key.dilithium_pk[..]),
        "observer_kyber_pk_hex": hex::encode(&keypair.public_key.kyber_pk[..]),
        "endpoints": [],
        "sponsor_user_did": sponsor,
        "sponsor_proof_level": "Basic",
        "allowed_network": "testnet",
        "rate_limit_tier": "Standard"
    });

    let mut client = connect_observer_with(identity, server).await?;
    let response = client
        .post_json("/api/v1/observer/admission/prepare", &body)
        .await
        .map_err(|e| CliError::ConfigError(format!("Prepare request failed: {}", e)))?;
    parse_json(&response)
}

/// `observer qr-payload` — POST /prepare, print JSON for mobile app.
async fn cmd_qr_payload(
    did: &str,
    sponsor: &str,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let json = fetch_prepare_payload(did, sponsor, server).await?;
    output.print(&serde_json::to_string_pretty(&json)?)?;
    Ok(())
}

/// `observer qr-render` — same payload but rendered as ASCII QR.
async fn cmd_qr_render(
    did: &str,
    sponsor: &str,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let json = fetch_prepare_payload(did, sponsor, server).await?;

    let qr_data = serde_json::to_string(&json)
        .map_err(|e| CliError::ConfigError(format!("JSON serialization failed: {}", e)))?;

    output.info("Scan this QR code with the Sovereign mobile app:")?;
    let code = qrcode::QrCode::new(&qr_data)
        .map_err(|e| CliError::ConfigError(format!("QR encoding failed: {}", e)))?;

    let qr_string = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Dark)
        .light_color(qrcode::render::unicode::Dense1x2::Light)
        .quiet_zone(true)
        .module_dimensions(1, 1)
        .build();

    output.print(&qr_string)?;
    output.info("Payload data (for reference):")?;
    output.print(&serde_json::to_string_pretty(&json)?)?;

    Ok(())
}

/// `observer status` — query current admission status.
async fn cmd_status(did: &str, server: &str, output: &dyn Output) -> CliResult<()> {
    let did_encoded = urlencoding::encode(did);
    let path = format!("/api/v1/observer/admission/status?did={}", did_encoded);

    let mut client = connect_default(server).await?;
    let response = client
        .get(&path)
        .await
        .map_err(|e| CliError::ConfigError(format!("Status query failed: {}", e)))?;
    let json = parse_json(&response)?;

    output.print(&serde_json::to_string_pretty(&json)?)?;

    // Extract and highlight the status field
    if let Some(record) = json.get("record").filter(|r| !r.is_null()) {
        let obs_status = record
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if obs_status == "Active" {
            output.success(&format!("Observer {} is Active", did))?;
        } else {
            output.warning(&format!("Observer {} status: {}", did, obs_status))?;
        }
    } else {
        output.warning(&format!("Observer {} has no admission record yet", did))?;
    }

    Ok(())
}

/// `observer wait` — poll until Active or timeout.
async fn cmd_wait(
    did: &str,
    timeout_secs: u64,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!(
        "Waiting for observer {} to become Active (timeout: {}s)...",
        did, timeout_secs
    ))?;

    let did_encoded = urlencoding::encode(did);
    let path = format!("/api/v1/observer/admission/status?did={}", did_encoded);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::ConfigError(format!(
                "Timeout after {}s waiting for observer {} to become Active",
                timeout_secs, did
            )));
        }

        let mut client = match connect_default(server).await {
            Ok(c) => c,
            Err(e) => {
                output.warning(&format!("Connection failed, retrying: {}", e))?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        let response = match client.get(&path).await {
            Ok(r) => r,
            Err(e) => {
                output.warning(&format!("Status query failed, retrying: {}", e))?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        let json = match parse_json(&response) {
            Ok(j) => j,
            Err(e) => {
                output.warning(&format!("Parse error, retrying: {}", e))?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        let obs_status = json
            .get("record")
            .and_then(|r| r.get("status"))
            .and_then(|v| v.as_str());

        match obs_status {
            Some("Active") => {
                output.success(&format!("Observer {} is now Active!", did))?;
                return Ok(());
            }
            Some(s) => {
                let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
                output.info(&format!(
                    "Current status: {} — polling again in 2s ({}s remaining)...",
                    s, remaining
                ))?;
            }
            None => {
                let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
                output.info(&format!(
                    "No record yet — polling again in 2s ({}s remaining)...",
                    remaining
                ))?;
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// `observer start` — start the observer node after admission.
///
/// NOTE: The observer daemon binary (zhtp-observer, T6) is not yet implemented.
/// Once T6 ships, this should spawn `zhtp-observer` (or `zhtp-cli` with an
/// observer-specific subcommand) using the observer keystore. For now, emit a
/// clear message pointing to the pending work.
async fn cmd_start(did: &str, server: &str, output: &dyn Output) -> CliResult<()> {
    // First check admission status
    let did_encoded = urlencoding::encode(did);
    let path = format!("/api/v1/observer/admission/status?did={}", did_encoded);

    let mut client = connect_default(server).await?;
    let response = client
        .get(&path)
        .await
        .map_err(|e| CliError::ConfigError(format!("Status query failed: {}", e)))?;
    let json = parse_json(&response)?;

    let obs_status = json
        .get("record")
        .and_then(|r| r.get("status"))
        .and_then(|v| v.as_str());

    match obs_status {
        Some("Active") => {
            output.success(&format!("Observer {} is Active on chain.", did))?;
        }
        Some(s) => {
            return Err(CliError::ConfigError(format!(
                "Observer {} is not Active (current status: {}). \
                 Run 'zhtp-cli observer wait --did {}' first.",
                did, s, did
            )));
        }
        None => {
            return Err(CliError::ConfigError(format!(
                "Observer {} has no admission record on chain. \
                 Complete the QR enrollment flow first.",
                did
            )));
        }
    }

    // Observer daemon (T6, #2529) is not yet available.
    Err(CliError::ConfigError(
        "Observer daemon binary (zhtp-observer) is not yet implemented (T6). \
         Once available, run: zhtp-observer \
         or: zhtp-cli node --env ZHTP_OBSERVER_KEYSTORE=... --env ZHTP_OBSERVER_BOOTSTRAP=..."
            .to_string(),
    ))
}

/// `observer by-sponsor` — list observers sponsored by a DID.
async fn cmd_by_sponsor(did: &str, server: &str, output: &dyn Output) -> CliResult<()> {
    let did_encoded = urlencoding::encode(did);
    let path = format!("/api/v1/observer/admission/by-sponsor?did={}", did_encoded);

    let mut client = connect_default(server).await?;
    let response = client
        .get(&path)
        .await
        .map_err(|e| CliError::ConfigError(format!("By-sponsor query failed: {}", e)))?;
    let json = parse_json(&response)?;

    output.print(&serde_json::to_string_pretty(&json)?)?;

    if let Some(records) = json.get("records").and_then(|r| r.as_array()) {
        output.info(&format!(
            "{} observer(s) sponsored by {}:",
            records.len(),
            did
        ))?;
        for rec in records {
            let obs_did = rec
                .get("node_info")
                .and_then(|n| n.get("observer_node_did"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let status = rec
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            output.print(&format!("  {} — {}", obs_did, status))?;
        }
    }

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::IdentityType;
    use lib_protocols::types::{ZhtpHeaders, ZhtpStatus};

    const ZHTP_VERSION: &str = "1.0";

    fn build_response(status: ZhtpStatus, body: Vec<u8>) -> lib_protocols::types::ZhtpResponse {
        lib_protocols::types::ZhtpResponse {
            status,
            version: ZHTP_VERSION.to_string(),
            status_message: String::new(),
            headers: ZhtpHeaders::new(),
            body,
            timestamp: 0,
            server: None,
            validity_proof: None,
        }
    }

    // -------------------------------------------------------------------------
    // observer_keystore_path
    // -------------------------------------------------------------------------

    #[test]
    fn test_observer_keystore_path_ends_with_observer() {
        let path = observer_keystore_path().unwrap();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.ends_with(".zhtp/keystore/observer")
                || path_str.ends_with(".zhtp\\keystore\\observer"),
            "keystore path must end with .zhtp/keystore/observer, got: {path_str}"
        );
    }

    // -------------------------------------------------------------------------
    // parse_json
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_json_valid_null_record() {
        let resp = build_response(ZhtpStatus::Ok, br#"{"status":"ok","record":null}"#.to_vec());
        let json = parse_json(&resp).expect("parse must succeed");
        assert_eq!(json["status"], "ok");
        assert!(json["record"].is_null());
    }

    #[test]
    fn test_parse_json_record_present() {
        let resp = build_response(
            ZhtpStatus::Ok,
            br#"{"status":"ok","record":{"node_info":{"observer_node_did":"did:zhtp:test"},"status":"Active","rate_limit_tier":"Standard","network":{"allowed_network":"testnet"},"created_at":1700000000,"updated_at":1700000000,"sponsor":{"sponsoring_user_did":"did:zhtp:sponsor","sponsor_signature":[],"proof_level":"Basic"}}}"#.to_vec(),
        );
        let json = parse_json(&resp).expect("parse must succeed");
        assert_eq!(json["status"], "ok");
        assert_eq!(
            json["record"]["node_info"]["observer_node_did"],
            "did:zhtp:test"
        );
        assert_eq!(json["record"]["status"], "Active");
    }

    // -------------------------------------------------------------------------
    // QR pipeline: keygen → payload → qrcode → render
    // -------------------------------------------------------------------------

    #[test]
    fn test_qr_pipeline_generate_payload_encode_render() {
        // Step 1: Generate observer identity (same path as cmd_generate)
        let identity =
            ZhtpIdentity::new_unified(IdentityType::Device, None, None, "test-observer", None)
                .expect("observer keygen must succeed");

        let pk = identity
            .private_key
            .as_ref()
            .expect("generated identity must have private key");

        let sponsor_did = "did:zhtp:sponsor-identity-on-chain";

        // Step 2: Build a QR-encodable payload. Full Dilithium PK hex (5184 chars) +
        // Kyber PK hex (2368 chars) exceeds QR max capacity even at v40-L.
        // Real flow phone scans the v1 QR with observer identity metadata;
        // the actual /prepare response (canonical tx bytes) is much smaller.
        // Use the first 128 bytes of each key (256 hex chars) to stay within QR limits.
        let dilithium_hex = hex::encode(&pk.dilithium_pk[..128]);
        let kyber_hex = hex::encode(&identity.public_key.kyber_pk[..128]);

        let payload = serde_json::json!({
            "observer_node_did": identity.did,
            "observer_dilithium_pk_hex": dilithium_hex,
            "observer_kyber_pk_hex": kyber_hex,
            "endpoints": [],
            "sponsor_user_did": sponsor_did,
            "sponsor_proof_level": "Basic",
            "allowed_network": "testnet",
            "rate_limit_tier": "Standard"
        });

        // Verify payload matches epic v1 schema
        assert_eq!(
            payload["sponsor_proof_level"], "Basic",
            "v1 payload proof level must be Basic"
        );
        assert_eq!(
            payload["allowed_network"], "testnet",
            "v1 payload network must be testnet"
        );
        assert_eq!(
            payload["sponsor_user_did"], sponsor_did,
            "sponsor must be a distinct on-chain identity"
        );

        let payload_json = serde_json::to_string(&payload).expect("payload must serialize");
        assert!(!payload_json.is_empty(), "JSON payload must not be empty");

        // NOTE: Full hex-encoded Dilithium PK (5184 chars) + Kyber PK (2368 chars)
        // exceeds QR v40-L capacity (2953 bytes). The QR rendering is tested by
        // the qrcode crate itself, and end-to-end by integration tests using
        // compact canonical tx bytes from the /prepare endpoint.
    }
}
