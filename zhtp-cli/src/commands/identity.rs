//! Identity commands for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity type parsing, DID validation, name validation
//! - **Imperative Shell**: File I/O, QUIC communication, output printing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{IdentityAction, IdentityArgs, ZhtpCli};
use crate::error::{CliError, CliResult};
use crate::logic;
use crate::output::Output;

use base64::Engine;
use lib_identity::ZhtpIdentity;
use lib_network::client::ZhtpClient;
use std::path::PathBuf;
use zhtp::keyfile_names::{USER_IDENTITY_FILENAME, USER_PRIVATE_KEY_FILENAME};

use super::web4_utils::save_private_key_to_file;
use super::web4_utils::{build_trust_config, connect_client, load_identity_from_keystore};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Valid identity operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOperation {
    Create,
    CreateWithType,
    Init,
    Verify,
    List,
    Import,
    GrantGenerate,
    GrantExercise,
    Unsupported,
}

impl IdentityOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            IdentityOperation::Create => "Create standard identity",
            IdentityOperation::CreateWithType => "Create identity with specific type",
            IdentityOperation::Init => "Initialize creator identity (keystore + on-chain register)",
            IdentityOperation::Verify => "Verify identity on blockchain",
            IdentityOperation::List => "List blockchain identities",
            IdentityOperation::Import => "Import identity from backup",
            IdentityOperation::GrantGenerate => {
                "Generate dual-auth grant keypair (separate from DID keystore)"
            }
            IdentityOperation::GrantExercise => "Sign grant-exercise proof (second ceremony)",
            IdentityOperation::Unsupported => "Run identity operation",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &IdentityAction) -> IdentityOperation {
    match action {
        IdentityAction::Create { .. } => IdentityOperation::Create,
        IdentityAction::CreateDid { .. } => IdentityOperation::CreateWithType,
        IdentityAction::Init { .. } => IdentityOperation::Init,
        IdentityAction::Register { .. } => IdentityOperation::Create,
        IdentityAction::Verify { .. } => IdentityOperation::Verify,
        IdentityAction::List => IdentityOperation::List,
        IdentityAction::Import { .. } => IdentityOperation::Import,
        IdentityAction::SimulateMessage { .. }
        | IdentityAction::Pending { .. }
        | IdentityAction::Ack { .. } => IdentityOperation::Unsupported,
        IdentityAction::GrantGenerate { .. } => IdentityOperation::GrantGenerate,
        IdentityAction::GrantExercise { .. } => IdentityOperation::GrantExercise,
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (File I/O, network, output)
// ============================================================================

/// Handle identity command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_identity_command(
    args: IdentityArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_identity_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_identity_command_impl(
    args: IdentityArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let op = action_to_operation(&args.action);
    output.info(&format!("{}...", op.description()))?;

    match args.action {
        IdentityAction::Create { name } => {
            // Pure validation
            logic::validate_identity_name(&name)?;

            // Imperative: File I/O
            create_identity_impl(&name, None, output).await
        }
        IdentityAction::CreateDid {
            name,
            identity_type,
            recovery_options: _,
        } => {
            // Pure validation
            logic::validate_identity_name(&name)?;
            let _id_type = logic::parse_identity_type(&identity_type)?;

            // Imperative: File I/O
            create_identity_with_type_impl(&name, &identity_type, output).await
        }
        IdentityAction::Init {
            display_name,
            device_id,
            keystore,
        } => {
            init_creator_identity(&display_name, &device_id, keystore.as_deref(), cli, output).await
        }
        IdentityAction::Register {
            display_name,
            device_id,
            keystore,
        } => {
            register_identity_on_chain(&display_name, &device_id, keystore.as_deref(), cli, output)
                .await
        }
        IdentityAction::Verify { identity_id } => {
            // Pure validation
            logic::validate_did(&identity_id)?;

            // Imperative: QUIC communication
            verify_identity_impl(&identity_id, cli, output).await
        }
        IdentityAction::List => {
            // Imperative: QUIC communication
            list_identities_impl(cli, output).await
        }
        IdentityAction::Import { file, keystore } => {
            import_identity_impl(&file, keystore.as_deref(), output).await
        }
        IdentityAction::SimulateMessage { .. }
        | IdentityAction::Pending { .. }
        | IdentityAction::Ack { .. } => Err(CliError::ConfigError(
            "This identity subcommand is not implemented in this command handler".to_string(),
        )),
        IdentityAction::GrantGenerate {
            grant_id,
            lock,
            keystore,
        } => grant_generate_impl(&grant_id, lock, keystore.as_deref(), output).await,
        IdentityAction::GrantExercise {
            grant_id,
            grantee_did,
            session_binding,
            grant_key,
            grant_file,
        } => {
            grant_exercise_impl(
                &grant_id,
                &grantee_did,
                &session_binding,
                grant_key.as_deref(),
                grant_file.as_deref(),
                output,
            )
            .await
        }
    }
}

async fn grant_generate_impl(
    grant_id: &str,
    lock: bool,
    keystore_path: Option<&str>,
    output: &dyn Output,
) -> CliResult<()> {
    output.header("Generate Grant Key (client custody)")?;

    let material = zhtp_client::GrantKeyMaterial::generate()
        .map_err(|e| CliError::IdentityError(format!("grant keygen failed: {e}")))?;

    output.info(&format!(
        "grant public key (hex): {}",
        hex::encode(&material.public_key)
    ))?;

    if lock {
        let dir = match keystore_path {
            Some(p) => PathBuf::from(p),
            None => get_default_keystore_path()?,
        };
        let path = zhtp_client::lock_to_disk(&material, &dir, grant_id)
            .map_err(|e| CliError::IdentityError(format!("failed to lock grant key: {e}")))?;
        output.success(&format!(
            "Grant key locked to {} (never inside user_private_key.json)",
            path.display()
        ))?;
        output.warning(
            "This file is as sensitive as a wallet key. Store it separately from your DID \
             keystore backups.",
        )?;
    } else {
        output.warning(
            "Cold-grant mode: this key was NOT written to disk. Capture the secret now via \
             `--lock` next time, or keep it only in memory for a one-shot exercise.",
        )?;
    }

    Ok(())
}

/// Sign a grant-exercise proof the "second ceremony" required in addition to a normal DID session. Loads the grant key from a path disjoint from the DID identity file and drops it from memory after signing once.
async fn grant_exercise_impl(
    grant_id: &str,
    grantee_did: &str,
    session_binding: &str,
    grant_key: Option<&str>,
    grant_file: Option<&str>,
    output: &dyn Output,
) -> CliResult<()> {
    output.header("Exercise Grant (second ceremony)")?;

    let path = match (grant_key, grant_file) {
        (Some(p), None) => PathBuf::from(p),
        (None, Some(p)) => PathBuf::from(p),
        (Some(_), Some(_)) => {
            return Err(CliError::ConfigError(
                "pass exactly one of --grant-key or --grant-file".to_string(),
            ))
        }
        (None, None) => {
            return Err(CliError::ConfigError(
                "elevated grant exercise requires --grant-key <path> or --grant-file <path>; \
                 the DID keystore alone is not sufficient (dual-auth, ADR §4)"
                    .to_string(),
            ))
        }
    };

    let material = zhtp_client::import_ephemeral(&path)
        .map_err(|e| CliError::IdentityError(format!("failed to load grant key: {e}")))?;

    let mut cold = zhtp_client::ColdGrant::new(material);
    let signed_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CliError::IdentityError(format!("clock error: {e}")))?
        .as_secs();

    let signature = cold
        .sign_once(grant_id, grantee_did, session_binding, signed_at_unix)
        .map_err(|e| CliError::IdentityError(format!("grant proof signing failed: {e}")))?;

    output.success("Grant-exercise proof signed (grant key dropped from memory)")?;
    output.info(&format!("signature (hex): {}", hex::encode(&signature)))?;
    output.info(&format!("signed_at_unix: {signed_at_unix}"))?;
    output.warning(
        "This signature is only half of the elevated request it must be submitted together \
         with an authenticated DID session, never in place of one.",
    )?;

    Ok(())
}

/// Get default keystore path (pure logic of path construction)
fn get_default_keystore_path() -> CliResult<PathBuf> {
    dirs::home_dir()
        .ok_or_else(|| CliError::IdentityError("Could not determine home directory".to_string()))
        .map(|home| home.join(".zhtp").join("keystore"))
}

/// Import identity from a .zkdid backup file
/// The .zkdid file is JSON with a `keystore_base64` field containing a base64-encoded tar.gz archive with `keystore/user_identity.json` and `keystore/user_private_key.json`.
/// The private key JSON from the export uses JSON number arrays for byte fields, which must be converted to hex-encoded format for `KeystorePrivateKey` compatibility.
async fn import_identity_impl(
    file_path: &str,
    keystore_path: Option<&str>,
    output: &dyn Output,
) -> CliResult<()> {
    use base64::Engine;
    use flate2::read::GzDecoder;
    use std::io::Read as IoRead;
    use tar::Archive;

    output.header("Import Identity from .zkdid Backup")?;
    output.info(&format!("Reading backup file: {}", file_path))?;

    let zkdid_content = std::fs::read_to_string(file_path).map_err(|e| {
        CliError::IdentityError(format!("Failed to read .zkdid file '{}': {}", file_path, e))
    })?;
    let zkdid: serde_json::Value = serde_json::from_str(&zkdid_content)
        .map_err(|e| CliError::IdentityError(format!("Failed to parse .zkdid JSON: {}", e)))?;

    let keystore_b64 = zkdid
        .get("keystore_base64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::IdentityError("Missing 'keystore_base64' field in .zkdid file".to_string())
        })?;

    let archive_bytes = base64::engine::general_purpose::STANDARD
        .decode(keystore_b64)
        .map_err(|e| CliError::IdentityError(format!("Failed to decode base64: {}", e)))?;

    let decoder = GzDecoder::new(&archive_bytes[..]);
    let mut archive = Archive::new(decoder);

    let mut identity_json: Option<String> = None;
    let mut private_key_json: Option<String> = None;

    for entry_result in archive
        .entries()
        .map_err(|e| CliError::IdentityError(format!("Failed to read tar archive: {}", e)))?
    {
        let mut entry = entry_result
            .map_err(|e| CliError::IdentityError(format!("Failed to read tar entry: {}", e)))?;
        let path = entry
            .path()
            .map_err(|e| CliError::IdentityError(format!("Failed to read entry path: {}", e)))?
            .to_string_lossy()
            .to_string();

        let mut content = String::new();
        entry
            .read_to_string(&mut content)
            .map_err(|e| CliError::IdentityError(format!("Failed to read entry content: {}", e)))?;

        if path.ends_with("user_identity.json") {
            identity_json = Some(content);
        } else if path.ends_with("user_private_key.json") {
            private_key_json = Some(content);
        }
    }

    let identity_json = identity_json.ok_or_else(|| {
        CliError::IdentityError("Backup archive missing keystore/user_identity.json".to_string())
    })?;
    let private_key_json = private_key_json.ok_or_else(|| {
        CliError::IdentityError("Backup archive missing keystore/user_private_key.json".to_string())
    })?;

    let identity_value: serde_json::Value = serde_json::from_str(&identity_json)
        .map_err(|e| CliError::IdentityError(format!("Failed to parse identity JSON: {}", e)))?;

    let did = identity_value
        .get("did")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    output.info(&format!("DID: {}", did))?;

    let pk_value: serde_json::Value = serde_json::from_str(&private_key_json)
        .map_err(|e| CliError::IdentityError(format!("Failed to parse private key JSON: {}", e)))?;

    let extract_bytes = |value: &serde_json::Value, field: &str| -> CliResult<Vec<u8>> {
        let arr = value.get(field).ok_or_else(|| {
            CliError::IdentityError(format!("Private key missing field '{}'", field))
        })?;

        if let Some(hex_str) = arr.as_str() {
            hex::decode(hex_str)
                .map_err(|e| CliError::IdentityError(format!("Invalid hex in '{}': {}", field, e)))
        } else if let Some(arr) = arr.as_array() {
            Ok(arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect())
        } else {
            Err(CliError::IdentityError(format!(
                "Field '{}' must be hex string or byte array",
                field
            )))
        }
    };

    let dilithium_sk_raw = extract_bytes(&pk_value, "dilithium_sk")?;
    let kyber_sk_raw = extract_bytes(&pk_value, "kyber_sk")?;
    let master_seed_raw = extract_bytes(&pk_value, "master_seed")?;

    let mut dilithium_sk = [0u8; 4896];
    let copy_len = dilithium_sk_raw.len().min(4896);
    dilithium_sk[..copy_len].copy_from_slice(&dilithium_sk_raw[..copy_len]);

    let mut kyber_sk = [0u8; 3168];
    let copy_len = kyber_sk_raw.len().min(3168);
    kyber_sk[..copy_len].copy_from_slice(&kyber_sk_raw[..copy_len]);

    let mut master_seed = [0u8; 64];
    let copy_len = master_seed_raw.len().min(64);
    master_seed[..copy_len].copy_from_slice(&master_seed_raw[..copy_len]);

    let dilithium_pk_raw = if pk_value.get("dilithium_pk").is_some() {
        extract_bytes(&pk_value, "dilithium_pk")?
    } else {
        let pk_obj = identity_value
            .get("public_key")
            .ok_or_else(|| CliError::IdentityError("Identity missing public_key".to_string()))?;

        if let Some(arr) = pk_obj.get("dilithium_pk") {
            if let Some(hex_str) = arr.as_str() {
                hex::decode(hex_str).map_err(|e| {
                    CliError::IdentityError(format!("Invalid dilithium_pk hex: {}", e))
                })?
            } else if let Some(arr) = arr.as_array() {
                arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect()
            } else {
                return Err(CliError::IdentityError(
                    "Cannot extract dilithium_pk".to_string(),
                ));
            }
        } else {
            return Err(CliError::IdentityError(
                "Neither private key nor identity contains dilithium_pk".to_string(),
            ));
        }
    };

    let mut dilithium_pk = [0u8; 2592];
    let copy_len = dilithium_pk_raw.len().min(2592);
    dilithium_pk[..copy_len].copy_from_slice(&dilithium_pk_raw[..copy_len]);

    let keystore_private_key = zhtp::keyfile_names::KeystorePrivateKey {
        dilithium_sk,
        dilithium_pk,
        kyber_sk,
        master_seed,
    };

    let keystore_dir = match keystore_path {
        Some(p) => PathBuf::from(p),
        None => get_default_keystore_path()?,
    };

    std::fs::create_dir_all(&keystore_dir).map_err(|e| {
        CliError::IdentityError(format!("Failed to create keystore directory: {}", e))
    })?;

    let identity_file = keystore_dir.join(USER_IDENTITY_FILENAME);
    std::fs::write(&identity_file, &identity_json).map_err(|e| {
        CliError::IdentityError(format!("Failed to write {}: {}", USER_IDENTITY_FILENAME, e))
    })?;
    output.success(&format!("Saved: {:?}", identity_file))?;

    let private_key_file = keystore_dir.join(USER_PRIVATE_KEY_FILENAME);
    let pk_json = serde_json::to_string_pretty(&keystore_private_key)
        .map_err(|e| CliError::IdentityError(format!("Failed to serialize private key: {}", e)))?;
    std::fs::write(&private_key_file, &pk_json).map_err(|e| {
        CliError::IdentityError(format!(
            "Failed to write {}: {}",
            USER_PRIVATE_KEY_FILENAME, e
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&private_key_file, std::fs::Permissions::from_mode(0o600));
    }
    output.success(&format!("Saved: {:?}", private_key_file))?;

    output.success(&format!("Identity imported successfully: {}", did))?;
    output.print(&format!("Keystore: {:?}", keystore_dir))?;

    Ok(())
}

/// Create a new identity locally and save to keystore
async fn create_identity_impl(
    name: &str,
    keystore_path: Option<&str>,
    output: &dyn Output,
) -> CliResult<()> {
    // Determine keystore path
    let keystore = match keystore_path {
        Some(path) => PathBuf::from(path),
        None => get_default_keystore_path()?,
    };

    // Check if identity already exists
    let identity_file = keystore.join(USER_IDENTITY_FILENAME);
    let private_key_file = keystore.join(USER_PRIVATE_KEY_FILENAME);
    if identity_file.exists() {
        return Err(CliError::IdentityError(format!(
            "Identity already exists at {:?}. Use a different keystore path or delete the existing identity first.",
            identity_file
        )));
    }

    // Create keystore directory
    std::fs::create_dir_all(&keystore).map_err(|e| {
        CliError::IdentityError(format!("Failed to create keystore directory: {}", e))
    })?;

    // Generate new identity locally (no network required)
    output.info("Generating cryptographic keys (post-quantum Dilithium + Kyber)...")?;
    let identity =
        ZhtpIdentity::new_unified(lib_identity::IdentityType::Device, None, None, name, None)
            .map_err(|e| CliError::IdentityError(format!("Failed to generate identity: {}", e)))?;

    output.success(&format!("DID: {}", identity.did))?;
    output.print(&format!("Identity ID: {}", identity.id))?;

    // Extract and save private key
    let private_key = identity
        .private_key
        .as_ref()
        .ok_or_else(|| CliError::IdentityError("Identity missing private key".to_string()))?;
    save_private_key_to_file(private_key, &private_key_file)?;

    // Save identity to file (public data)
    let identity_json = serde_json::to_string_pretty(&identity)
        .map_err(|e| CliError::IdentityError(format!("Failed to serialize identity: {}", e)))?;
    std::fs::write(&identity_file, identity_json).map_err(|e| {
        CliError::IdentityError(format!("Failed to write {}: {}", USER_IDENTITY_FILENAME, e))
    })?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| CliError::IdentityError(format!("Failed to set file permissions: {}", e)),
        )?;
    }

    output.success(&format!("Identity saved to: {:?}", identity_file))?;
    output.success(&format!("Private key saved to: {:?}", private_key_file))?;
    output.warning("Keep your identity secure! It contains cryptographic material.")?;

    Ok(())
}

/// DAO creator wizard: keystore + on-chain registration + next-step guidance.
async fn init_creator_identity(
    display_name: &str,
    device_id: &str,
    keystore_path: Option<&str>,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.header("DAO Creator Identity Init")?;
    register_identity_on_chain(display_name, device_id, keystore_path, cli, output).await?;

    let keystore = match keystore_path {
        Some(path) => PathBuf::from(path),
        None => get_default_keystore_path()?,
    };
    output.print("")?;
    output.success("Creator identity ready.")?;
    output.print("Next steps:")?;
    output.print(&format!("  1. Keystore: {:?}", keystore))?;
    output.print(
        "  2. Launch DAO token: zhtp-cli dao launch --name <NAME> --symbol <SYM> --supply <atoms>",
    )?;
    output.print("  3. Operator runbook: docs/ops/dao-launch-bootstrap.md")?;
    output.print("  4. Rewards policy: schemas/zhtp/rewards-policy/examples/bubl-v1.json")?;
    Ok(())
}

/// Register identity on-chain: generates keys (if needed), then calls
/// POST /api/v1/identity/register to create identity + 3 wallets + SOV welcome bonus.
/// This matches the app's identity creation flow — the single canonical path.
async fn register_identity_on_chain(
    display_name: &str,
    device_id: &str,
    keystore_path: Option<&str>,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore = match keystore_path {
        Some(path) => PathBuf::from(path),
        None => get_default_keystore_path()?,
    };

    let identity_file = keystore.join(USER_IDENTITY_FILENAME);
    let private_key_file = keystore.join(USER_PRIVATE_KEY_FILENAME);

    // Generate keys if no local identity exists
    if identity_file.exists() {
        output.info("Using existing identity from keystore...")?;
    } else {
        output.info("Generating cryptographic keys (Dilithium5 + Kyber1024)...")?;
        std::fs::create_dir_all(&keystore).map_err(|e| {
            CliError::IdentityError(format!("Failed to create keystore directory: {}", e))
        })?;
        let id = ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            display_name,
            None,
        )
        .map_err(|e| CliError::IdentityError(format!("Failed to generate identity: {}", e)))?;

        // Save private key
        let pk = id
            .private_key
            .as_ref()
            .ok_or_else(|| CliError::IdentityError("Missing private key".to_string()))?;
        save_private_key_to_file(pk, &private_key_file)?;

        // Save identity
        let json = serde_json::to_string_pretty(&id)
            .map_err(|e| CliError::IdentityError(format!("Failed to serialize: {}", e)))?;
        std::fs::write(&identity_file, &json)
            .map_err(|e| CliError::IdentityError(format!("Failed to write identity: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&private_key_file, std::fs::Permissions::from_mode(0o600));
        }

        output.success(&format!("DID: {}", id.did))?;
        output.success(&format!("Keys saved to: {:?}", keystore))?;
    }

    // Load keypair for signing (this works with both hex and array formats)
    let loaded = load_identity_from_keystore(&keystore)?;
    output.info(&format!("DID: {}", loaded.identity.did))?;
    output.info("Registering on-chain (identity + wallets + SOV welcome bonus)...")?;

    // Build registration proof: sign "ZHTP_REGISTER:{timestamp}"
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CliError::ConfigError(format!("Time error: {}", e)))?
        .as_secs();
    let proof_message = format!("ZHTP_REGISTER:{}", timestamp);
    let proof_sig = lib_crypto::sign_message(&loaded.keypair, proof_message.as_bytes())
        .map_err(|e| CliError::IdentityError(format!("Failed to sign proof: {}", e)))?;

    // Base64-encode public keys
    let dilithium_pk_b64 =
        base64::engine::general_purpose::STANDARD.encode(&loaded.keypair.public_key.dilithium_pk);
    let kyber_pk_b64 =
        base64::engine::general_purpose::STANDARD.encode(&loaded.keypair.public_key.kyber_pk);
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&proof_sig.signature);

    let body = serde_json::json!({
        "public_key": dilithium_pk_b64,
        "kyber_public_key": kyber_pk_b64,
        "device_id": device_id,
        "display_name": display_name,
        "identity_type": "human",
        "registration_proof": proof_b64,
        "timestamp": timestamp,
    });

    // Connect and POST
    let trust_config = build_trust_config(None, None, false, true)?;
    let client = connect_client(loaded.identity.clone(), trust_config, &cli.server).await?;
    let response = client
        .post_json("/api/v1/identity/register", &body)
        .await
        .map_err(|e| CliError::ConfigError(format!("Registration failed: {}", e)))?;

    let result: serde_json::Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse response: {}", e)))?;

    let status = result.get("status").and_then(|s| s.as_str()).unwrap_or("");
    // API returns "queued" when txs are in the mempool, "confirmed" when
    // wait_for_inclusion saw block commit. Both are operator success paths.
    if status == "success" || status == "queued" || status == "confirmed" {
        if status == "queued" {
            output.success("Identity registration queued on-chain (pending block inclusion)")?;
        } else if status == "confirmed" {
            output.success("Identity confirmed on-chain (block-committed)")?;
        } else {
            output.success("Identity registered on-chain")?;
        }
        if let Some(did) = result.get("did").and_then(|d| d.as_str()) {
            output.print(&format!("DID: {}", did))?;
        }
        if let Some(primary) = result.get("primary_wallet_id").and_then(|w| w.as_str()) {
            output.print(&format!("Primary wallet: {}", primary))?;
        }
        if let Some(ubi) = result.get("ubi_wallet_id").and_then(|w| w.as_str()) {
            output.print(&format!("UBI wallet: {}", ubi))?;
        }
        if let Some(savings) = result.get("savings_wallet_id").and_then(|w| w.as_str()) {
            output.print(&format!("Savings wallet: {}", savings))?;
        }
        if let Some(tx) = result.get("blockchain_tx").and_then(|t| t.as_str()) {
            output.print(&format!("Tx: {}", tx))?;
        }
    } else {
        let err = result
            .get("message")
            .or_else(|| result.get("error"))
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");
        return Err(CliError::IdentityError(format!(
            "On-chain registration failed: {}",
            err
        )));
    }

    Ok(())
}

/// Create identity with specific type
async fn create_identity_with_type_impl(
    name: &str,
    identity_type: &str,
    output: &dyn Output,
) -> CliResult<()> {
    // Parse and validate identity type
    let id_type = logic::parse_identity_type(identity_type)?;

    // Get default keystore path
    let keystore = get_default_keystore_path()?;

    // Check if identity already exists
    let identity_file = keystore.join(USER_IDENTITY_FILENAME);
    let private_key_file = keystore.join(USER_PRIVATE_KEY_FILENAME);
    if identity_file.exists() {
        return Err(CliError::IdentityError(format!(
            "Identity already exists at {:?}",
            identity_file
        )));
    }

    // Create keystore directory
    std::fs::create_dir_all(&keystore).map_err(|e| {
        CliError::IdentityError(format!("Failed to create keystore directory: {}", e))
    })?;

    output.info(&format!(
        "Generating {} identity (post-quantum Dilithium + Kyber)...",
        identity_type
    ))?;

    // Generate new identity
    let identity = ZhtpIdentity::new_unified(id_type, None, None, name, None)
        .map_err(|e| CliError::IdentityError(format!("Failed to generate identity: {}", e)))?;

    output.success(&format!("DID: {}", identity.did))?;
    output.print(&format!("Identity Type: {}", identity_type))?;

    // Extract and save private key
    let private_key = identity
        .private_key
        .as_ref()
        .ok_or_else(|| CliError::IdentityError("Identity missing private key".to_string()))?;
    save_private_key_to_file(private_key, &private_key_file)?;

    // Save identity (public data)
    let identity_json = serde_json::to_string_pretty(&identity)
        .map_err(|e| CliError::IdentityError(format!("Failed to serialize identity: {}", e)))?;
    std::fs::write(&identity_file, identity_json).map_err(|e| {
        CliError::IdentityError(format!("Failed to write {}: {}", USER_IDENTITY_FILENAME, e))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| CliError::IdentityError(format!("Failed to set file permissions: {}", e)),
        )?;
    }

    output.success(&format!("Identity saved to: {:?}", identity_file))?;
    output.success(&format!("Private key saved to: {:?}", private_key_file))?;

    Ok(())
}

/// Verify identity on blockchain (requires QUIC connection)
async fn verify_identity_impl(
    identity_id: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!("Verifying identity: {}", identity_id))?;
    output.print(&format!("Server: {}", cli.server))?;

    // This would normally establish a QUIC connection and verify
    // For now, provide guidance on the process
    output.warning(
        "Identity verification requires a running ZHTP node.\n\
         Use 'zhtp-cli node start' to launch the node first.",
    )?;

    Ok(())
}

/// List identities from blockchain (requires QUIC connection)
async fn list_identities_impl(cli: &ZhtpCli, output: &dyn Output) -> CliResult<()> {
    output.info("Listing identities from blockchain...")?;
    output.print(&format!("Server: {}", cli.server))?;

    // This would normally establish a QUIC connection and fetch identities
    output.warning(
        "Identity listing requires a running ZHTP node.\n\
         Use 'zhtp-cli node start' to launch the node first.",
    )?;

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_create() {
        let action = IdentityAction::Create {
            name: "test".to_string(),
        };
        assert_eq!(action_to_operation(&action), IdentityOperation::Create);
    }

    #[test]
    fn test_action_to_operation_init() {
        let action = IdentityAction::Init {
            display_name: "creator".to_string(),
            device_id: "cli-device".to_string(),
            keystore: None,
        };
        assert_eq!(action_to_operation(&action), IdentityOperation::Init);
    }

    #[test]
    fn test_action_to_operation_create_with_type() {
        let action = IdentityAction::CreateDid {
            name: "test".to_string(),
            identity_type: "human".to_string(),
            recovery_options: vec![],
        };
        assert_eq!(
            action_to_operation(&action),
            IdentityOperation::CreateWithType
        );
    }

    #[test]
    fn test_action_to_operation_verify() {
        let action = IdentityAction::Verify {
            identity_id: "did:zhtp:test:abc".to_string(),
        };
        assert_eq!(action_to_operation(&action), IdentityOperation::Verify);
    }

    #[test]
    fn test_action_to_operation_list() {
        let action = IdentityAction::List;
        assert_eq!(action_to_operation(&action), IdentityOperation::List);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(
            IdentityOperation::Create.description(),
            "Create standard identity"
        );
        assert_eq!(
            IdentityOperation::CreateWithType.description(),
            "Create identity with specific type"
        );
        assert_eq!(
            IdentityOperation::Init.description(),
            "Initialize creator identity (keystore + on-chain register)"
        );
        assert_eq!(
            IdentityOperation::Verify.description(),
            "Verify identity on blockchain"
        );
        assert_eq!(
            IdentityOperation::List.description(),
            "List blockchain identities"
        );
        assert_eq!(
            IdentityOperation::Unsupported.description(),
            "Run identity operation"
        );
    }
}
