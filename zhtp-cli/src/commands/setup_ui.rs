//! Node setup web UI — localhost HTTP bridge to QUIC node
//!
//! `zhtp-cli node setup-ui` starts a local HTTP server on port 7840,
//! opens the browser, and proxies API calls to the QUIC node.

use crate::argument_parsing::ZhtpCli;
use crate::commands::web4_utils::{default_keystore_path, load_identity_from_keystore, spawn_crypto};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use tokio::sync::watch;
use std::path::PathBuf;
use lib_crypto::keypair::KeyPair;
use lib_crypto::types::PrivateKey;
use lib_identity::ZhtpIdentity;
use zhtp::keyfile_names::{KeystorePrivateKey, NODE_IDENTITY_FILENAME, NODE_PRIVATE_KEY_FILENAME};

const UI_HTML: &str = include_str!("../ui/setup.html");
const TOPOLOGY_HTML: &str = include_str!("../../../zhtp/src/ui/topology.html");
const DEFAULT_UI_PORT: u16 = 7840;
const QRCODE_JS: &str = include_str!("../ui/qrcode.min.js");

/// Run the setup UI bridge
pub async fn run_setup_ui(cli: &ZhtpCli, output: &dyn Output) -> CliResult<()> {
    let port = DEFAULT_UI_PORT;
    let server_addr = format!("127.0.0.1:{}", port);

    output.info(&format!("Starting node setup UI on http://{}...", server_addr))?;

    // Try to connect to the QUIC node
    let quic_server = cli.server.clone();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    // Build HTTP routes
    use axum::{
        extract::State,
        http::StatusCode,
        response::{Html, IntoResponse, Json},
        routing::{get, post},
        Router,
    };

    #[derive(Clone)]
    struct AppState {
        quic_server: String,
        shutdown_tx: watch::Sender<bool>,
    }

    let state = AppState {
        quic_server,
        shutdown_tx,
    };

    let app = Router::new()
        .route("/", get(serve_ui))
        .route("/topology", get(serve_topology))
        .route("/api/status", get(proxy_status))
        .route("/api/control", post(proxy_control))
        .route("/api/v1/network/directory", get(proxy_directory))
        .route("/js/qrcode.min.js", get(serve_qrcode_js))
        .with_state(state);

    async fn serve_ui() -> Html<&'static str> {
        Html(UI_HTML)
    }

    async fn serve_topology() -> Html<&'static str> {
        Html(TOPOLOGY_HTML)
    }

    async fn serve_qrcode_js() -> impl IntoResponse {
        (
            [("content-type", "application/javascript")],
            QRCODE_JS,
        )
    }

    async fn proxy_status(
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        match try_get_status(&state.quic_server).await {
            Ok(json) => {
                (StatusCode::OK, Json(json))
            }
            Err(e) => {
                (StatusCode::OK, Json(serde_json::json!({
                    "state": "connecting",
                    "error": e,
                    "chain_height": 0,
                    "validator_count": 0,
                    "identity_count": 0,
                })))
            }
        }
    }

    async fn proxy_directory(
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        match try_get_directory(&state.quic_server).await {
            Ok(json) => (StatusCode::OK, Json(json)),
            Err(e) => (StatusCode::OK, Json(serde_json::json!({
                "network_id": "unknown",
                "chain_height": 0,
                "error": e,
                "topology": { "validators": [], "gateways": [], "total_validators": 0, "total_gateways": 0, "connected_peers": 0 },
            }))),
        }
    }

    async fn proxy_control(
        State(state): State<AppState>,
        Json(body): Json<serde_json::Value>,
    ) -> impl IntoResponse {
        let action = body.get("action").and_then(|a| a.as_str()).unwrap_or("");
        match action {
            "restore_identity" => {
                let seed = body.get("seed_phrase").and_then(|s| s.as_str()).unwrap_or("");
                match try_restore_seed(seed).await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            "create_identity" => {
                let name = body.get("node_name").and_then(|s| s.as_str()).unwrap_or("sovereign-node");
                match try_create_new(name).await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            "register_identity" => match try_register_identity(&state.quic_server).await {
                Ok(json) => (StatusCode::OK, Json(json)),
                Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
            },
            "force_sync" => match try_force_sync(&state.quic_server).await {
                Ok(json) => (StatusCode::OK, Json(json)),
                Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
            },
            "disconnect_node" => match try_disconnect_node(&state.quic_server).await {
                Ok(json) => (StatusCode::OK, Json(json)),
                Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
            },
            "reset_local_identity" => match try_reset_local_identity().await {
                Ok(json) => (StatusCode::OK, Json(json)),
                Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
            },
            "disconnect_session" => {
                let _ = state.shutdown_tx.send(true);
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "success": true,
                        "message": "Setup UI bridge stopping",
                    })),
                )
            }
            "generate_observer_identity" => {
                match try_generate_observer_identity().await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            "admission_status" => {
                let did = body.get("did").and_then(|d| d.as_str()).unwrap_or("");
                match try_admission_status(&state.quic_server, did).await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            "admission_qr_payload" => {
                match try_admission_qr_payload(&state.quic_server).await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            "start_observer_node" => {
                let did = body.get("did").and_then(|d| d.as_str()).unwrap_or("");
                match try_start_observer_node(&state.quic_server, did).await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            "reset_observer_identity" => {
                match try_reset_observer_identity().await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            _ => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Unknown action" })),
            ),
        }
    }

    // Open browser
    if let Err(e) = open::that(format!("http://{}", server_addr)) {
        output.warning(&format!("Could not open browser: {}. Open http://{} manually.", e, server_addr))?;
    }

    output.success(&format!("Setup UI running at http://{}", server_addr))?;
    output.info("Press Ctrl+C to stop.")?;

    // Start HTTP server
    let listener = tokio::net::TcpListener::bind(&server_addr)
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to bind {}: {}", server_addr, e)))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .map_err(|e| CliError::ConfigError(format!("HTTP server error: {}", e)))?;

    Ok(())
}

/// Try to get node status via QUIC
async fn try_get_status(server: &str) -> Result<serde_json::Value, String> {
    let keystore = default_keystore_path().map_err(|e| e.to_string())?;
    if !keystore.exists() {
        return Ok(serde_json::json!({
            "state": "setup_required",
            "chain_height": 0,
        }));
    }
    let loaded = match load_identity_from_keystore(&keystore) {
        Ok(loaded) => loaded,
        Err(e) => {
            return Ok(serde_json::json!({
                "state": "setup_required",
                "chain_height": 0,
                "local_identity_error": format!("Local identity could not be loaded: {}", e),
            }));
        }
    };

    // Save DID before identity is moved into the QUIC client
    let local_did = loaded.identity.did.clone();

    let trust_config = lib_network::web4::trust::TrustConfig::bootstrap();
    let config = lib_network::client::ZhtpClientConfig {
        allow_bootstrap: true,
    };
    let mut client = lib_network::client::ZhtpClient::new_with_config(loaded.identity, trust_config, config)
        .await
        .map_err(|e| format!("Client error: {}", e))?;

    client.connect(server).await.map_err(|e| format!("Connect failed: {}", e))?;

    let response = match client.get("/api/v1/node/status").await {
        Ok(response) => response,
        Err(e) => {
            return Ok(serde_json::json!({
                "state": "api_unavailable",
                "did": local_did,
                "identity_registered": serde_json::Value::Null,
                "chain_height": 0,
                "wallet_id": serde_json::Value::Null,
                "sov_balance": "0",
                "sov_balance_human": "0.0000",
                "validator_count": 0,
                "identity_count": 0,
                "network_id": "unknown",
                "error": format!("Node status endpoint unavailable: {}", e),
            }));
        }
    };
    let json: serde_json::Value = match lib_network::client::ZhtpClient::parse_json(&response) {
        Ok(json) => json,
        Err(e) => {
            return Ok(serde_json::json!({
                "state": "api_unavailable",
                "did": local_did,
                "identity_registered": serde_json::Value::Null,
                "chain_height": 0,
                "wallet_id": serde_json::Value::Null,
                "sov_balance": "0",
                "sov_balance_human": "0.0000",
                "validator_count": 0,
                "identity_count": 0,
                "network_id": "unknown",
                "error": format!("Node status response could not be parsed: {}", e),
            }));
        }
    };

    Ok(json)
}

async fn connect_bridge_client(server: &str) -> Result<lib_network::client::ZhtpClient, String> {
    let keystore = default_keystore_path().map_err(|e| e.to_string())?;
    let loaded = load_identity_from_keystore(&keystore).map_err(|e| e.to_string())?;
    let trust_config = lib_network::web4::trust::TrustConfig::bootstrap();
    let config = lib_network::client::ZhtpClientConfig {
        allow_bootstrap: true,
    };
    let mut client = lib_network::client::ZhtpClient::new_with_config(loaded.identity, trust_config, config)
        .await
        .map_err(|e| format!("Client error: {}", e))?;
    client.connect(server).await.map_err(|e| format!("Connect failed: {}", e))?;
    Ok(client)
}

async fn post_node_action(server: &str, path: &str) -> Result<serde_json::Value, String> {
    let client = connect_bridge_client(server).await?;
    let response = client
        .post_json(path, &serde_json::json!({}))
        .await
        .map_err(|e| format!("Request failed: {}", e))?;
    lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| format!("Failed to parse response: {}", e))
}

async fn try_register_identity(server: &str) -> Result<serde_json::Value, String> {
    use base64::{engine::general_purpose, Engine as _};

    let keystore = default_keystore_path().map_err(|e| e.to_string())?;
    let loaded = load_identity_from_keystore(&keystore).map_err(|e| e.to_string())?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Time error: {}", e))?
        .as_secs();
    let proof_message = format!("ZHTP_REGISTER:{}", timestamp);
    let proof_sig = lib_crypto::sign_message(&loaded.keypair, proof_message.as_bytes())
        .map_err(|e| format!("Failed to sign proof: {}", e))?;
    let device_id = loaded.identity.primary_device.clone();

    let display_name = loaded
        .identity
        .metadata
        .get("display_name")
        .cloned()
        .unwrap_or_else(|| loaded.identity.primary_device.clone());

    let body = serde_json::json!({
        "public_key": general_purpose::STANDARD.encode(&loaded.keypair.public_key.dilithium_pk),
        "kyber_public_key": general_purpose::STANDARD.encode(&loaded.keypair.public_key.kyber_pk),
        "device_id": device_id,
        "display_name": display_name,
        "identity_type": "human",
        "registration_proof": general_purpose::STANDARD.encode(&proof_sig.signature),
        "timestamp": timestamp,
    });

    let trust_config = lib_network::web4::trust::TrustConfig::bootstrap();
    let config = lib_network::client::ZhtpClientConfig {
        allow_bootstrap: true,
    };
    let mut client = lib_network::client::ZhtpClient::new_with_config(loaded.identity, trust_config, config)
        .await
        .map_err(|e| format!("Client error: {}", e))?;
    client.connect(server).await.map_err(|e| format!("Connect failed: {}", e))?;

    let response = client
        .post_json("/api/v1/identity/register", &body)
        .await
        .map_err(|e| format!("Registration failed: {}", e))?;

    // 409 = identity already registered on-chain — that's success
    if response.status.code() == 409 {
        return Ok(serde_json::json!({
            "status": "success",
            "message": "Identity already registered on-chain",
        }));
    }

    let result: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if result.get("status").and_then(|s| s.as_str()) == Some("success") {
        Ok(result)
    } else {
        let err = result
            .get("message")
            .or_else(|| result.get("error"))
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");
        Err(format!("On-chain registration failed: {}", err))
    }
}

async fn try_force_sync(server: &str) -> Result<serde_json::Value, String> {
    post_node_action(server, "/api/v1/node/force-sync").await
}

async fn try_disconnect_node(server: &str) -> Result<serde_json::Value, String> {
    post_node_action(server, "/api/v1/node/shutdown").await
}

async fn try_reset_local_identity() -> Result<serde_json::Value, String> {
    let keystore_path = default_keystore_path().map_err(|e| e.to_string())?;
    let mut removed = Vec::new();

    for name in ["user_identity.json", "user_private_key.json"] {
        let path = keystore_path.join(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("Failed to remove {}: {}", path.display(), e))?;
            removed.push(name);
        }
    }

    Ok(serde_json::json!({
        "success": true,
        "message": if removed.is_empty() {
            "No local identity files were present."
        } else {
            "Local identity removed."
        },
        "removed_files": removed,
        "keystore": keystore_path.display().to_string(),
    }))
}

/// Restore identity from BIP39 seed phrase (20 or 24 words).
///
/// Decodes the mnemonic back to entropy, derives the Dilithium5 keypair,
/// and saves the restored identity to the local keystore.
async fn try_restore_seed(seed_phrase: &str) -> Result<serde_json::Value, String> {
    let keystore_path = default_keystore_path().map_err(|e| e.to_string())?;

    if keystore_path.join("user_identity.json").exists() {
        return Err("Identity already exists. Delete keystore to restore from seed.".to_string());
    }

    let mut manager = lib_identity::identity::manager::IdentityManager::new();
    let identity_id = manager
        .import_identity_from_phrase(seed_phrase)
        .await
        .map_err(|e| format!("Seed restore failed: {}", e))?;

    let identity = manager
        .get_identity(&identity_id)
        .ok_or_else(|| "Identity created but not found in manager".to_string())?;

    let did = identity.did.clone();

    // Save to keystore
    std::fs::create_dir_all(&keystore_path).map_err(|e| format!("Keystore dir: {}", e))?;

    let identity_json = serde_json::to_string_pretty(identity)
        .map_err(|e| format!("Serialize: {}", e))?;
    std::fs::write(keystore_path.join("user_identity.json"), &identity_json)
        .map_err(|e| format!("Write identity: {}", e))?;

    if let Some(ref pk) = identity.private_key {
        crate::commands::web4_utils::save_private_key_to_file(pk, &keystore_path.join("user_private_key.json"))
            .map_err(|e| format!("Write private key: {}", e))?;
    }

    Ok(serde_json::json!({
        "success": true,
        "did": did,
        "message": "Identity restored from seed phrase",
        "keystore": keystore_path.display().to_string(),
    }))
}

/// Create new identity with random keypair
async fn try_create_new(name: &str) -> Result<serde_json::Value, String> {
    let keystore_path = default_keystore_path().map_err(|e| e.to_string())?;

    let name_owned = name.to_string();
    if keystore_path.join("user_identity.json").exists() {
        return Err("Identity already exists. Delete keystore to create a new one.".to_string());
    }

    // Run key generation on a dedicated thread with explicit 128 MB stack.
    let identity = spawn_crypto(move || {
        lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            &name_owned,
            None,
        )
        .map_err(|e| format!("Failed to create identity: {}", e))
    })
    .await?;

    let did = identity.did.clone();

    // Save to keystore
    std::fs::create_dir_all(&keystore_path).map_err(|e| format!("Keystore dir: {}", e))?;

    let identity_json = serde_json::to_string_pretty(&identity)
        .map_err(|e| format!("Serialize: {}", e))?;

    // Atomic write with backup: .tmp → rename, old file → .bak
    // Per CLAUDE.md keystore safety rule: never overwrite without backup.
    let tmp_identity = keystore_path.join("user_identity.json.tmp");
    let final_identity = keystore_path.join("user_identity.json");
    std::fs::write(&tmp_identity, &identity_json)
        .map_err(|e| format!("Write identity: {}", e))?;

    if let Some(ref pk) = identity.private_key {
        let tmp_key = keystore_path.join("user_private_key.json.tmp");
        let final_key = keystore_path.join("user_private_key.json");
        crate::commands::web4_utils::save_private_key_to_file(pk, &tmp_key)
            .map_err(|e| format!("Write private key: {}", e))?;
        // Best-effort backup of existing private key before overwrite
        if final_key.exists() {
            let _ = std::fs::rename(&final_key, final_key.with_extension("json.bak"));
        }
        std::fs::rename(&tmp_key, &final_key)
            .map_err(|e| format!("Rename private key: {}", e))?;
    }

    // Best-effort backup of existing identity before overwrite
    if final_identity.exists() {
        let _ = std::fs::rename(&final_identity, final_identity.with_extension("json.bak"));
    }
    std::fs::rename(&tmp_identity, &final_identity)
        .map_err(|e| format!("Rename identity: {}", e))?;

    Ok(serde_json::json!({
        "success": true,
        "did": did,
        "message": format!("Node '{}' created", name),
        "keystore": keystore_path.display().to_string(),
    }))
}

async fn try_get_directory(server: &str) -> Result<serde_json::Value, String> {
    let keystore = default_keystore_path().map_err(|e| e.to_string())?;
    if !keystore.exists() {
        return Err("No local identity — run setup first".to_string());
    }
    let loaded = load_identity_from_keystore(&keystore)
        .map_err(|e| format!("Identity load failed: {}", e))?;

    let trust_config = lib_network::web4::trust::TrustConfig::bootstrap();
    let config = lib_network::client::ZhtpClientConfig {
        allow_bootstrap: true,
    };
    let mut client = lib_network::client::ZhtpClient::new_with_config(loaded.identity, trust_config, config)
        .await
        .map_err(|e| format!("Client error: {}", e))?;

    client.connect(server).await.map_err(|e| format!("Connect failed: {}", e))?;

    let response = client.get("/api/v1/network/directory").await
        .map_err(|e| format!("API request failed: {}", e))?;

    serde_json::from_slice(&response.body)
        .map_err(|e| format!("Invalid JSON response: {}", e))
}

// ---------------------------------------------------------------------------
// Observer admission control actions (T5)
// ---------------------------------------------------------------------------

/// Path to the observer-specific keystore directory.
fn observer_keystore_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir()
        .ok_or_else(|| "Cannot determine home directory".to_string())?;
    Ok(home.join(".zhtp").join("keystore").join("observer"))
}

/// Load observer identity from ~/.zhtp/keystore/observer/.
fn load_observer_identity() -> Result<(ZhtpIdentity, KeyPair), String> {
    let keystore = observer_keystore_path()?;
    if !keystore.exists() {
        return Err(format!(
            "Observer keystore not found at {:?}. Create an observer identity first.",
            keystore
        ));
    }
    let identity_file = keystore.join(NODE_IDENTITY_FILENAME);
    let private_key_file = keystore.join(NODE_PRIVATE_KEY_FILENAME);
    if !identity_file.exists() {
        return Err(format!("Observer identity file not found: {:?}", identity_file));
    }
    if !private_key_file.exists() {
        return Err(format!("Observer private key not found: {:?}", private_key_file));
    }
    let identity_json = std::fs::read_to_string(&identity_file)
        .map_err(|e| format!("Failed to read identity: {}", e))?;
    let private_key_json = std::fs::read_to_string(&private_key_file)
        .map_err(|e| format!("Failed to read private key: {}", e))?;
    let keystore_key: KeystorePrivateKey = serde_json::from_str(&private_key_json)
        .map_err(|e| format!("Failed to parse private key: {}", e))?;
    let private_key = PrivateKey {
        dilithium_sk: keystore_key.dilithium_sk,
        dilithium_pk: keystore_key.dilithium_pk,
        kyber_sk: keystore_key.kyber_sk,
        master_seed: keystore_key.master_seed,
    };
    let identity = ZhtpIdentity::from_serialized(&identity_json, &private_key)
        .map_err(|e| format!("Failed to restore identity: {}", e))?;
    let keypair = KeyPair {
        public_key: identity.public_key.clone(),
        private_key,
    };
    Ok((identity, keypair))
}

/// Connect to a node using the observer identity (bootstrap trust).
async fn connect_observer_with(
    identity: ZhtpIdentity,
    server: &str,
) -> Result<lib_network::client::ZhtpClient, String> {
    let trust_config = crate::commands::web4_utils::build_trust_config(None, None, false, true)
        .map_err(|e| e.to_string())?;
    crate::commands::web4_utils::connect_client(identity, trust_config, server)
        .await
        .map_err(|e| e.to_string())
}

/// Create a Dilithium5+Kyber1024 observer keypair in ~/.zhtp/keystore/observer/.
///
/// Key generation runs on a dedicated thread with 128 MB stack to prevent
/// stack overflow. Writes are atomic (write to .tmp, then rename) so a crash
/// mid-write never leaves corrupt files.
async fn try_generate_observer_identity() -> Result<serde_json::Value, String> {
    let keystore = observer_keystore_path()?;
    let identity_file = keystore.join(NODE_IDENTITY_FILENAME);

    // Clean up any stale .tmp files from previous crashed attempts
    let _ = std::fs::remove_file(identity_file.with_extension("json.tmp"));
    let _ = std::fs::remove_file(keystore.join(NODE_PRIVATE_KEY_FILENAME).with_extension("json.tmp"));

    if identity_file.exists() {
        let (identity, keypair) = load_observer_identity()?;
        return Ok(serde_json::json!({
            "success": true,
            "did": identity.did,
            "dilithium_pk_hex": hex::encode(&keypair.public_key.dilithium_pk[..]),
            "kyber_pk_hex": hex::encode(&keypair.public_key.kyber_pk[..]),
            "message": "Observer identity already exists",
            "keystore": keystore.to_string_lossy(),
        }));
    }

    std::fs::create_dir_all(&keystore)
        .map_err(|e| format!("Failed to create observer keystore: {}", e))?;

    // Run key generation on a dedicated thread with explicit 128 MB stack.
    // This is the most stack-intensive operation — Dilithium5 keygen alone
    // needs ~200 KB per frame and can go 5+ frames deep.
    let identity = spawn_crypto(move || {
        ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            "observer-node",
            None,
        )
        .map_err(|e| format!("Key generation failed: {}", e))
    })
    .await?;

    let private_key = identity.private_key.as_ref()
        .ok_or_else(|| "Generated identity missing private key".to_string())?;

    let private_key_file = keystore.join(NODE_PRIVATE_KEY_FILENAME);
    let tmp_private_key = private_key_file.with_extension("json.tmp");

    // Save private key to .tmp first
    crate::commands::web4_utils::save_private_key_to_file(private_key, &tmp_private_key)
        .map_err(|e| e.to_string())?;

    // Save identity JSON to .tmp first
    let identity_json = serde_json::to_string_pretty(&identity)
        .map_err(|e| format!("Serialization failed: {}", e))?;
    let tmp_identity = identity_file.with_extension("json.tmp");
    std::fs::write(&tmp_identity, &identity_json)
        .map_err(|e| format!("Failed to write identity file: {}", e))?;

    // Atomically rename .tmp -> final with best-effort backup of existing file
    // Per CLAUDE.md keystore safety rule: preserve old keys so observers can
    // be re-admitted with a previous key if the user changes their mind.
    if identity_file.exists() {
        let _ = std::fs::rename(&identity_file, identity_file.with_extension("json.bak"));
    }
    if private_key_file.exists() {
        let _ = std::fs::rename(&private_key_file, private_key_file.with_extension("json.bak"));
    }
    std::fs::rename(&tmp_identity, &identity_file)
        .map_err(|e| format!("Failed to finalize identity file: {}", e))?;
    std::fs::rename(&tmp_private_key, &private_key_file)
        .map_err(|e| format!("Failed to finalize private key: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&private_key_file, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600));
    }

    Ok(serde_json::json!({
        "success": true,
        "did": identity.did,
        "dilithium_pk_hex": hex::encode(&private_key.dilithium_pk[..]),
        "kyber_pk_hex": hex::encode(&private_key.kyber_sk[..32]),
        "message": "Observer identity created",
        "keystore": keystore.to_string_lossy(),
    }))
}

/// Proxy GET /api/v1/observer/admission/status?did=<did> over QUIC.
async fn try_admission_status(server: &str, did: &str) -> Result<serde_json::Value, String> {
    let did_encoded = urlencoding::encode(did);
    let path = format!("/api/v1/observer/admission/status?did={}", did_encoded);

    let (identity, _keypair) = load_observer_identity()?;
    let mut client = connect_observer_with(identity, server).await?;

    let response = client
        .get(&path)
        .await
        .map_err(|e| format!("Status query failed: {}", e))?;

    lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| format!("Failed to parse response: {}", e))
}

/// Build the v1 QR payload JSON for the desktop UI to render.
///
/// The payload uses truncated keys (first 32 bytes → 64 hex chars) to fit
/// within a smaller, easier-to-scan QR code. The mobile app uses the full
/// keys from the `/prepare` endpoint, not from the QR code — the truncated
/// keys here serve only as a lookup hint.
async fn try_admission_qr_payload(server: &str) -> Result<serde_json::Value, String> {
    let (identity, keypair) = load_observer_identity()?;

    // Only the DID is strictly required for the phone to look up and sign.
    // Truncated keys (32 bytes = 64 hex chars each) are enough to verify the
    // phone scanned the right code. The full keys come from the `/prepare`
    // endpoint on the node, not from the QR.
    Ok(serde_json::json!({
        "v": 1,
        "d": identity.did,
        // Short key fingerprints (32 bytes each) — enough for phone to verify
        "dp": &hex::encode(&keypair.public_key.dilithium_pk[..32]),
        "kp": &hex::encode(&keypair.public_key.kyber_pk[..32]),
        "s": server,
        "n": "testnet"
    }))
}

/// Start the observer node process once the admission record is Active on chain.
async fn try_start_observer_node(server: &str, did: &str) -> Result<serde_json::Value, String> {
    // Verify admission record exists and is Active
    let status = try_admission_status(server, did).await?;

    let obs_status = status
        .get("record")
        .and_then(|r| r.get("status"))
        .and_then(|v| v.as_str());

    match obs_status {
        Some("Active") => { /* proceed */ }
        Some(s) => {
            return Err(format!(
                "Observer {} is not Active (current: {}). Complete phone enrollment first.",
                did, s
            ));
        }
        None => {
            return Err(format!(
                "Observer {} has no admission record. Complete phone enrollment first.",
                did
            ));
        }
    }

    let keystore = observer_keystore_path()?;
    let keystore_str = keystore.to_string_lossy().to_string();
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("zhtp-cli"));

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("node")
        // Pass RUST_MIN_STACK explicitly so the child also has enough stack
        // for Dilithium5 operations during QUIC handshake.
        .env("RUST_MIN_STACK", "134217728")
        .env("ZHTP_OBSERVER_KEYSTORE", &keystore_str)
        .env("ZHTP_OBSERVER_BOOTSTRAP", server)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let child = cmd.spawn().map_err(|e| {
        format!("Failed to spawn observer node: {}", e)
    })?;

    Ok(serde_json::json!({
        "success": true,
        "pid": child.id(),
        "message": format!("Observer node started (PID: {})", child.id()),
    }))
}

/// Delete observer identity files (used by Cancel/Reset in the UI).
async fn try_reset_observer_identity() -> Result<serde_json::Value, String> {
    let keystore = observer_keystore_path()?;
    let mut removed = Vec::new();

    let identity_file = keystore.join(NODE_IDENTITY_FILENAME);
    let private_key_file = keystore.join(NODE_PRIVATE_KEY_FILENAME);

    // Also clean up .tmp files from crashed atomic writes
    for name in [
        NODE_IDENTITY_FILENAME,
        NODE_PRIVATE_KEY_FILENAME,
        &format!("{}.tmp", NODE_IDENTITY_FILENAME),
        &format!("{}.tmp", NODE_PRIVATE_KEY_FILENAME),
    ] {
        let path = keystore.join(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("Failed to remove {}: {}", path.display(), e))?;
            removed.push(name.to_string());
        }
    }

    // Remove the observer keystore directory itself if empty
    let _ = std::fs::remove_dir(&keystore);

    Ok(serde_json::json!({
        "success": true,
        "message": if removed.is_empty() {
            "No observer identity files were present."
        } else {
            "Observer identity removed."
        },
        "removed_files": removed,
        "keystore": keystore.display().to_string(),
    }))
}
