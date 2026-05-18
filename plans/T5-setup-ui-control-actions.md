# T5 — Wire new observer control actions in setup_ui.rs

Part of epic #2523. Extends [`zhtp-cli/src/commands/setup_ui.rs`](../zhtp-cli/src/commands/setup_ui.rs).

Reference implementations live in [`zhtp-cli/src/commands/observer.rs`](../zhtp-cli/src/commands/observer.rs) — we pull helpers from there and adapt for the axum handler pattern.

---

## 1. New imports (add to top of setup_ui.rs)

```rust
use std::path::PathBuf;
use lib_crypto::keypair::KeyPair;
use lib_crypto::types::PrivateKey;
use lib_identity::ZhtpIdentity;
use zhtp::keyfile_names::{KeystorePrivateKey, NODE_IDENTITY_FILENAME, NODE_PRIVATE_KEY_FILENAME};
```

## 2. New `include_str!` for qrcode.min.js

```rust
const QRCODE_JS: &str = include_str!("../ui/qrcode.min.js");
```

## 3. New route — `/js/qrcode.min.js`

**In the Router builder** (around line 47–53), add after the existing routes:

```rust
.route("/js/qrcode.min.js", get(serve_qrcode_js))
```

**New handler function:**

```rust
async fn serve_qrcode_js() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        QRCODE_JS,
    )
}
```

> Use the existing `use axum::http::header` import, or just inline `"content-type"`.

## 4. Observer keystore helpers (add before proxy_control)

### 4a. `observer_keystore_path()`
Identical to the one in [`observer.rs:50–54`](../zhtp-cli/src/commands/observer.rs:50):

```rust
fn observer_keystore_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir()
        .ok_or_else(|| "Cannot determine home directory".to_string())?;
    Ok(home.join(".zhtp").join("keystore").join("observer"))
}
```

### 4b. `load_observer_identity()`
Adapted from [`observer.rs:58–107`](../zhtp-cli/src/commands/observer.rs:58) but returning `Result<..., String>` instead of `CliResult` (since these handlers return `String` errors).

```rust
fn load_observer_identity() -> Result<(ZhtpIdentity, KeyPair), String> {
    let keystore = observer_keystore_path()?;
    if !keystore.exists() {
        return Err(format!("Observer keystore not found at {:?}. Create an observer identity first.", keystore));
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
```

### 4c. `connect_observer_with(identity, server)`
Adapted from [`observer.rs:110–116`](../zhtp-cli/src/commands/observer.rs:110):

```rust
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
```

## 5. New action handlers (async `Result<serde_json::Value, String>`)

### 5a. `try_generate_observer_identity()`

```rust
async fn try_generate_observer_identity() -> Result<serde_json::Value, String> {
    let keystore = observer_keystore_path()?;
    let identity_file = keystore.join(NODE_IDENTITY_FILENAME);

    if identity_file.exists() {
        // Already exists — return existing keys
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

    let identity = ZhtpIdentity::new_unified(
        lib_identity::IdentityType::Device,
        None,
        None,
        "observer-node",
        None,
    )
    .map_err(|e| format!("Key generation failed: {}", e))?;

    let private_key = identity.private_key.as_ref()
        .ok_or_else(|| "Generated identity missing private key".to_string())?;

    // Save private key
    let private_key_file = keystore.join(NODE_PRIVATE_KEY_FILENAME);
    crate::commands::web4_utils::save_private_key_to_file(private_key, &private_key_file)
        .map_err(|e| e.to_string())?;

    // Save identity JSON
    let identity_json = serde_json::to_string_pretty(&identity)
        .map_err(|e| format!("Serialization failed: {}", e))?;
    std::fs::write(&identity_file, &identity_json)
        .map_err(|e| format!("Failed to write identity file: {}", e))?;

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
```

### 5b. `try_admission_status(server, did)`

```rust
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
```

### 5c. `try_admission_qr_payload(server)`

```rust
async fn try_admission_qr_payload(server: &str) -> Result<serde_json::Value, String> {
    let (identity, keypair) = load_observer_identity()?;

    Ok(serde_json::json!({
        "version": 1,
        "observer_node_did": identity.did,
        "observer_dilithium_pk_hex": hex::encode(&keypair.public_key.dilithium_pk[..]),
        "observer_kyber_pk_hex": hex::encode(&keypair.public_key.kyber_pk[..]),
        "bootstrap_node": server,
        "network": "testnet",
        "requested_proof_level": "Verified",
        "requested_rate_limit": "Default"
    }))
}
```

> This matches the v1 QR payload schema from epic §3 step 3.

### 5d. `try_start_observer_node(server, did)`

```rust
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
```

> Note: spawning the zhtp binary starts the process but the handler returns immediately with the PID. The spawned process continues running independently (matching the pattern in [`observer.rs:448–497`](../zhtp-cli/src/commands/observer.rs:448)).

## 6. Wire into `proxy_control` match

Add four new match arms **before** the `_` catch-all at line 142:

```rust
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
_ => (
    StatusCode::BAD_REQUEST,
    Json(serde_json::json!({ "error": "Unknown action" })),
),
```

> The `_` catch-all is unchanged — still returns 400 with `"Unknown action"`.

## 7. Expected UI ↔ backend contract

| JS `action` | JSON body extra | Response keys |
|---|---|---|
| `generate_observer_identity` | none | `success`, `did`, `dilithium_pk_hex`, `kyber_pk_hex`, `keystore` |
| `admission_qr_payload` | none | `version`, `observer_node_did`, `observer_dilithium_pk_hex`, `observer_kyber_pk_hex`, `bootstrap_node`, `network`, `requested_proof_level`, `requested_rate_limit` |
| `admission_status` | `did` | full chain response: `record.status`, etc. |
| `start_observer_node` | `did` | `success`, `pid`, `message` |

## 8. Resources served

| Route | Content-Type | Source |
|---|---|---|
| `GET /js/qrcode.min.js` | `application/javascript` | `zhtp-cli/src/ui/qrcode.min.js` via `include_str!` |

## 9. Acceptance criteria

- [ ] `GET /js/qrcode.min.js` returns JavaScript with correct MIME type
- [ ] `generate_observer_identity` creates keys in `~/.zhtp/keystore/observer/` (not `~/.zhtp/keystore/`)
- [ ] `admission_qr_payload` returns v1 JSON matching epic §3 step 3 schema
- [ ] `admission_status` proxies QUIC GET to the chain and returns the response
- [ ] `start_observer_node` fails with clear error when admission record doesn't exist or isn't Active
- [ ] `start_observer_node` succeeds and spawns process when Active
- [ ] Unknown action still returns 400 with `"Unknown action"`
- [ ] Existing actions (`create_identity`, `register_identity`, etc.) still work unchanged
- [ ] Observer keystore (`~/.zhtp/keystore/observer/`) never collides with user keystore (`~/.zhtp/keystore/`)
