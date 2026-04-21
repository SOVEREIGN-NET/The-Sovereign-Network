//! Node setup web UI — localhost HTTP bridge to QUIC node
//!
//! `zhtp-cli node setup-ui` starts a local HTTP server on port 7840,
//! opens the browser, and proxies API calls to the QUIC node.

use crate::argument_parsing::ZhtpCli;
use crate::commands::web4_utils::{connect_default, default_keystore_path, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use std::sync::Arc;
use tokio::sync::RwLock;

const UI_HTML: &str = include_str!("../ui/setup.html");
const DEFAULT_UI_PORT: u16 = 7840;

/// Run the setup UI bridge
pub async fn run_setup_ui(cli: &ZhtpCli, output: &dyn Output) -> CliResult<()> {
    let port = DEFAULT_UI_PORT;
    let server_addr = format!("127.0.0.1:{}", port);

    output.info(&format!("Starting node setup UI on http://{}...", server_addr))?;

    // Try to connect to the QUIC node
    let quic_server = cli.server.clone();
    let node_connected = Arc::new(RwLock::new(false));

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
        node_connected: Arc<RwLock<bool>>,
    }

    let state = AppState {
        quic_server,
        node_connected: node_connected.clone(),
    };

    let app = Router::new()
        .route("/", get(serve_ui))
        .route("/api/status", get(proxy_status))
        .route("/api/setup", post(proxy_setup))
        .with_state(state);

    async fn serve_ui() -> Html<&'static str> {
        Html(UI_HTML)
    }

    async fn proxy_status(
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        match try_get_status(&state.quic_server).await {
            Ok(json) => {
                *state.node_connected.write().await = true;
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

    async fn proxy_setup(
        State(state): State<AppState>,
        Json(body): Json<serde_json::Value>,
    ) -> impl IntoResponse {
        let action = body.get("action").and_then(|a| a.as_str()).unwrap_or("");
        match action {
            "restore" => {
                let seed = body.get("seed_phrase").and_then(|s| s.as_str()).unwrap_or("");
                match try_restore_seed(seed, &state.quic_server).await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            "create" => {
                let name = body.get("node_name").and_then(|s| s.as_str()).unwrap_or("sovereign-node");
                match try_create_new(name, &state.quic_server).await {
                    Ok(json) => (StatusCode::OK, Json(json)),
                    Err(e) => (StatusCode::OK, Json(serde_json::json!({ "error": e }))),
                }
            }
            _ => {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Unknown action" })))
            }
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
    let loaded = load_identity_from_keystore(&keystore).map_err(|e| e.to_string())?;

    let trust_config = lib_network::web4::trust::TrustConfig::bootstrap();
    let config = lib_network::client::ZhtpClientConfig {
        allow_bootstrap: true,
    };
    let mut client = lib_network::client::ZhtpClient::new_with_config(loaded.identity, trust_config, config)
        .await
        .map_err(|e| format!("Client error: {}", e))?;

    client.connect(server).await.map_err(|e| format!("Connect failed: {}", e))?;

    let response = client.get("/api/v1/node/status").await.map_err(|e| format!("Request failed: {}", e))?;
    let json: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| format!("Parse failed: {}", e))?;

    Ok(json)
}

/// Restore identity from seed phrase — derives same keypair deterministically
async fn try_restore_seed(seed_phrase: &str, _server: &str) -> Result<serde_json::Value, String> {
    let words: Vec<&str> = seed_phrase.split_whitespace().collect();

    // Support both 20-word (legacy) and 24-word (BIP39) phrases
    if words.len() != 20 && words.len() != 24 {
        return Err(format!("Expected 20 or 24 words, got {}", words.len()));
    }

    let keystore_path = default_keystore_path().map_err(|e| e.to_string())?;

    // Convert mnemonic → entropy → seed → identity
    // The recovery phrase contains the entropy that deterministically derives the keypair.
    let word_vec: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    let phrase = lib_identity::recovery::RecoveryPhrase::from_words(word_vec)
        .map_err(|e| format!("Invalid seed phrase: {}", e))?;

    // Derive 64-byte seed from entropy via HKDF
    let mut seed = [0u8; 64];
    let entropy = &phrase.entropy;
    use sha2::Digest;
    let hash = sha2::Sha512::digest(entropy);
    seed.copy_from_slice(&hash);

    // Recover identity from seed
    let identity = lib_identity::ZhtpIdentity::recover_from_seed(
        seed,
        lib_identity::IdentityType::Device,
        None,
        None,
        "restored-node",
    )
    .map_err(|e| format!("Failed to recover identity: {}", e))?;

    let did = identity.did.clone();

    // Save to keystore
    std::fs::create_dir_all(&keystore_path).map_err(|e| format!("Keystore dir: {}", e))?;

    let identity_json = serde_json::to_string_pretty(&identity)
        .map_err(|e| format!("Serialize: {}", e))?;
    let identity_path = keystore_path.join("user_identity.json");
    std::fs::write(&identity_path, &identity_json)
        .map_err(|e| format!("Write identity: {}", e))?;

    // Save private key
    if let Some(ref pk) = identity.private_key {
        let pk_path = keystore_path.join("user_private_key.json");
        crate::commands::web4_utils::save_private_key_to_file(pk, &pk_path)
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
async fn try_create_new(name: &str, _server: &str) -> Result<serde_json::Value, String> {
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
