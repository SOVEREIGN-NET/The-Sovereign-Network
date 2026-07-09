//! Node setup web UI — localhost HTTP bridge to QUIC node
//!
//! `zhtp-cli node setup-ui` starts a local HTTP server on port 7840,
//! opens the browser, and proxies API calls to the QUIC node.

use crate::argument_parsing::ZhtpCli;
use crate::commands::web4_utils::{default_keystore_path, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use tokio::sync::watch;

const UI_HTML: &str = include_str!("../ui/setup.html");
const TOPOLOGY_HTML: &str = include_str!("../../../zhtp/src/ui/topology.html");
const DEFAULT_UI_PORT: u16 = 7840;

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
        .with_state(state);

    async fn serve_ui() -> Html<&'static str> {
        Html(UI_HTML)
    }

    async fn serve_topology() -> Html<&'static str> {
        Html(TOPOLOGY_HTML)
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
        ..Default::default()
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
        ..Default::default()
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
        ..Default::default()
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

    if keystore_path.join("user_identity.json").exists() {
        return Err("Identity already exists. Delete keystore to create a new one.".to_string());
    }

    let identity = lib_identity::ZhtpIdentity::new_unified(
        lib_identity::IdentityType::Device,
        None,
        None,
        name,
        None,
    )
    .map_err(|e| format!("Failed to create identity: {}", e))?;

    let did = identity.did.clone();

    // Save to keystore
    std::fs::create_dir_all(&keystore_path).map_err(|e| format!("Keystore dir: {}", e))?;

    let identity_json = serde_json::to_string_pretty(&identity)
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
        ..Default::default()
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
