//! Web4 Deploy Command
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Deploy mode parsing, domain validation, file manifest building
//! - **Imperative Shell**: File I/O, QUIC communication, trust config building
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{DeployArgs, DeployAction, ZhtpCli};
use crate::commands::web4_utils::{build_trust_config, connect_client, load_identity_from_keystore, resolve_keystore_path, validate_domain};
use crate::error::{CliResult, CliError};
use crate::output::Output;

use base64::Engine;
use lib_network::client::ZhtpClient;
use lib_protocols::types::ZhtpRequest;
use std::path::PathBuf;
use std::str::FromStr;
use zhtp::web4_manifest::{DeployManifest, FileEntry, DeployMode as ManifestDeployMode, canonicalize_file_entries, compute_root_hash, manifest_unsigned_bytes_from_parts, normalize_manifest_path};

const MAX_FILE_SIZE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_SIZE_BYTES: u64 = 1024 * 1024 * 1024;

struct FileToUpload {
    path: String,
    file_path: PathBuf,
    size: u64,
}

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Supported deployment modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployMode {
    /// Single Page Application - all routes serve index.html
    Spa,
    /// Static site - each file served at its path
    Static,
}

impl FromStr for DeployMode {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "spa" => Ok(DeployMode::Spa),
            "static" => Ok(DeployMode::Static),
            _ => Err(CliError::ConfigError(
                format!("Invalid deploy mode: '{}'. Use 'spa' or 'static'", s),
            )),
        }
    }
}

impl DeployMode {
    /// Get mode as string
    pub fn as_str(&self) -> &str {
        match self {
            DeployMode::Spa => "spa",
            DeployMode::Static => "static",
        }
    }
}


/// Valid deployment operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployOperation {
    Site,
    Update,
    Delete,
    Status,
    List,
    History,
    Rollback,
}

impl DeployOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            DeployOperation::Site => "Deploy website to Web4",
            DeployOperation::Update => "Update existing deployment",
            DeployOperation::Delete => "Delete deployed domain",
            DeployOperation::Status => "Check deployment status",
            DeployOperation::List => "List deployments",
            DeployOperation::History => "Show deployment history",
            DeployOperation::Rollback => "Rollback to previous version",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &DeployAction) -> DeployOperation {
    match action {
        DeployAction::Site { .. } => DeployOperation::Site,
        DeployAction::Update { .. } => DeployOperation::Update,
        DeployAction::Delete { .. } => DeployOperation::Delete,
        DeployAction::Status { .. } => DeployOperation::Status,
        DeployAction::List { .. } => DeployOperation::List,
        DeployAction::History { .. } => DeployOperation::History,
        DeployAction::Rollback { .. } => DeployOperation::Rollback,
    }
}

/// Validate build directory
///
/// Pure function - path validation only (no I/O)
pub fn validate_build_directory(path_str: &str) -> CliResult<PathBuf> {
    if path_str.is_empty() {
        return Err(CliError::ConfigError(
            "Build directory path cannot be empty".to_string(),
        ));
    }

    Ok(PathBuf::from(path_str))
}

async fn post_bytes(
    client: &ZhtpClient,
    path: &str,
    body: Vec<u8>,
    content_type: &str,
) -> CliResult<serde_json::Value> {
    let request = ZhtpRequest::post(
        path.to_string(),
        body,
        content_type.to_string(),
        Some(client.identity().id.clone()),
    )
    .map_err(|e| CliError::ConfigError(format!("Failed to build request: {}", e)))?;

    let response = client
        .request(request)
        .await
        .map_err(|e| CliError::ConfigError(format!("Request failed: {}", e)))?;

    if !response.status.is_success() {
        return Err(CliError::ConfigError(format!(
            "Request failed: {} {}",
            response.status.code(),
            response.status_message
        )));
    }

    serde_json::from_slice(&response.body)
        .map_err(|e| CliError::ConfigError(format!("Invalid JSON response: {}", e)))
}

async fn post_raw(
    client: &ZhtpClient,
    path: &str,
    body: Vec<u8>,
    content_type: &str,
) -> CliResult<Vec<u8>> {
    let request = ZhtpRequest::post(
        path.to_string(),
        body,
        content_type.to_string(),
        Some(client.identity().id.clone()),
    )
    .map_err(|e| CliError::ConfigError(format!("Failed to build request: {}", e)))?;

    let response = client
        .request(request)
        .await
        .map_err(|e| CliError::ConfigError(format!("Request failed: {}", e)))?;

    if !response.status.is_success() {
        return Err(CliError::ConfigError(format!(
            "Request failed: {} {}",
            response.status.code(),
            response.status_message
        )));
    }

    Ok(response.body)
}

fn build_manifest(
    domain: &str,
    mode: DeployMode,
    manifest_files: Vec<FileEntry>,
    total_size: u64,
    deployed_at: u64,
    author_did: &str,
    keypair: &lib_crypto::keypair::KeyPair,
) -> CliResult<DeployManifest> {
    let canonical_files = canonicalize_file_entries(manifest_files)
        .map_err(|e| CliError::ConfigError(format!("Manifest file list error: {}", e)))?;
    let root_hash = compute_root_hash(&canonical_files);

    let manifest_bytes = manifest_unsigned_bytes_from_parts(
        1,
        domain.to_string(),
        match mode {
            DeployMode::Spa => ManifestDeployMode::Spa,
            DeployMode::Static => ManifestDeployMode::Static,
        },
        canonical_files.clone(),
        root_hash,
        total_size,
        deployed_at,
        author_did.to_string(),
    )
    .map_err(|e| CliError::ConfigError(format!("Failed to serialize manifest: {}", e)))?;

    let signature = lib_crypto::sign_message(keypair, &manifest_bytes)
        .map_err(|e| CliError::ConfigError(format!("Failed to sign manifest: {}", e)))?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.signature);

    Ok(DeployManifest {
        version: 1,
        domain: domain.to_string(),
        mode: match mode {
            DeployMode::Spa => ManifestDeployMode::Spa,
            DeployMode::Static => ManifestDeployMode::Static,
        },
        files: canonical_files,
        root_hash,
        total_size,
        deployed_at,
        author_did: author_did.to_string(),
        signature: signature_b64,
    })
}

async fn upload_files(
    client: &ZhtpClient,
    files: &[FileToUpload],
    domain: &str,
    output: &dyn Output,
) -> CliResult<(Vec<FileEntry>, u64)> {
    use std::fs;

    let mut manifest_files = Vec::new();
    let mut total_size = 0u64;
    for file in files {
        let content = fs::read(&file.file_path)
            .map_err(|e| CliError::ConfigError(format!("Failed to read {}: {}", file.path, e)))?;

        let content_type = mime_guess::from_path(&file.file_path)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_string();

        let blob_response = post_bytes(client, "/api/v1/web4/content/blob", content, &content_type).await?;
        let blob_hash = blob_response
            .get("content_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::DeploymentFailed {
                domain: domain.to_string(),
                reason: format!("Blob response missing content_id for {}", file.path),
            })?
            .to_string();

        total_size = total_size.saturating_add(file.size);
        manifest_files.push(FileEntry {
            path: file.path.clone(),
            size: file.size,
            mime_type: content_type,
            hash: blob_hash,
        });

        output.print(&format!("✓ Uploaded {}", file.path))?;
    }

    Ok((manifest_files, total_size))
}

async fn upload_manifest(client: &ZhtpClient, manifest: &DeployManifest) -> CliResult<String> {
    let manifest_payload = serde_json::to_vec(manifest)
        .map_err(|e| CliError::ConfigError(format!("Failed to encode manifest: {}", e)))?;
    // Compute CID using same format as server: "bafk" + first 16 bytes of blake3 hash
    let hash = lib_crypto::hash_blake3(&manifest_payload);
    let local_cid = format!("bafk{}", hex::encode(&hash[..16]));
    let manifest_response = post_bytes(
        client,
        "/api/v1/web4/content/manifest",
        manifest_payload,
        "application/json",
    )
    .await?;

    let server_cid = manifest_response
        .get("manifest_cid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CliError::DeploymentFailed {
            domain: manifest.domain.clone(),
            reason: "Manifest response missing manifest_cid".to_string(),
        })?;

    if server_cid != local_cid {
        return Err(CliError::DeploymentFailed {
            domain: manifest.domain.clone(),
            reason: format!(
                "Manifest CID mismatch: server returned {}, local hash {}",
                server_cid, local_cid
            ),
        });
    }

    Ok(local_cid)
}

fn collect_files(
    build_dir: &str,
    domain: &str,
) -> CliResult<Vec<FileToUpload>> {
    let build_path = PathBuf::from(build_dir);
    let canonical_build = build_path
        .canonicalize()
        .map_err(|e| CliError::ConfigError(format!("Failed to resolve build directory: {}", e)))?;

    if !build_path.exists() {
        return Err(CliError::ConfigError(format!(
            "Build directory does not exist: {}",
            build_dir
        )));
    }

    if !build_path.is_dir() {
        return Err(CliError::ConfigError(format!(
            "Path is not a directory: {}",
            build_dir
        )));
    }

    let mut files = Vec::new();
    let mut total_size = 0u64;
    for entry in walkdir::WalkDir::new(&build_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && !e.file_type().is_symlink())
    {
        let relative_path = entry
            .path()
            .strip_prefix(&build_path)
            .map_err(|e| CliError::DeploymentFailed { domain: domain.to_string(), reason: format!("Path error: {}", e) })?
            .to_string_lossy()
            .to_string();

        let normalized_path = normalize_manifest_path(&relative_path)
            .map_err(|e| CliError::ConfigError(format!("Invalid path {}: {}", relative_path, e)))?;

        let canonical_file = entry
            .path()
            .canonicalize()
            .map_err(|e| CliError::ConfigError(format!("Failed to resolve file path: {}", e)))?;
        if !canonical_file.starts_with(&canonical_build) {
            return Err(CliError::ConfigError(format!(
                "File escapes build directory: {}",
                relative_path
            )));
        }

        let size = entry
            .metadata()
            .map_err(|e| CliError::ConfigError(format!("Failed to read metadata: {}", e)))?
            .len();
        if size > MAX_FILE_SIZE_BYTES {
            return Err(CliError::ConfigError(format!(
                "File exceeds size limit ({} bytes): {}",
                MAX_FILE_SIZE_BYTES, normalized_path
            )));
        }
        total_size = total_size.saturating_add(size);
        if total_size > MAX_TOTAL_SIZE_BYTES {
            return Err(CliError::ConfigError(format!(
                "Total deployment size exceeds limit ({} bytes)",
                MAX_TOTAL_SIZE_BYTES
            )));
        }

        files.push(FileToUpload {
            path: normalized_path,
            file_path: entry.path().to_path_buf(),
            size,
        });
    }

    if files.is_empty() {
        return Err(CliError::InvalidBuildDirectory("No files found in build directory".to_string()));
    }

    Ok(files)
}


// ============================================================================
// IMPERATIVE SHELL - All side effects here (file I/O, network, output)
// ============================================================================

/// Handle deploy command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_deploy_command(
    args: DeployArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_deploy_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_deploy_command_impl(
    args: DeployArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let op = action_to_operation(&args.action);
    output.info(&format!("{}...", op.description()))?;

    match args.action {
        DeployAction::Site {
            build_dir,
            domain,
            mode,
            keystore,
            fee,
            dry_run,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;
            validate_build_directory(&build_dir)?;
            let deploy_mode: DeployMode = mode
                .as_deref()
                .unwrap_or("spa")
                .parse()?;

            output.header("Web4 Site Deployment")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("Build directory: {}", build_dir))?;
            output.print(&format!("Mode: {}", deploy_mode.as_str()))?;

            // Imperative: File I/O and deployment
            deploy_site_impl(
                &build_dir,
                &domain,
                deploy_mode,
                Some(keystore.as_str()),
                fee,
                dry_run,
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DeployAction::Update {
            build_dir,
            domain,
            mode,
            keystore,
            fee,
            dry_run,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;
            validate_build_directory(&build_dir)?;
            let deploy_mode: DeployMode = mode
                .as_deref()
                .unwrap_or("spa")
                .parse()?;

            output.header("Update Website Deployment")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("Build directory: {}", build_dir))?;
            output.print(&format!("Mode: {}", deploy_mode.as_str()))?;

            // Imperative: File I/O and deployment
            deploy_update_impl(
                &build_dir,
                &domain,
                deploy_mode,
                Some(keystore.as_str()),
                fee,
                dry_run,
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DeployAction::Delete {
            domain,
            keystore,
            force,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Delete Deployment")?;
            output.print(&format!("Domain: {}", domain))?;

            // Imperative: Network communication
            delete_deployment_impl(
                &domain,
                Some(keystore.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                force,
                output,
            )
            .await
        }
        DeployAction::Status {
            domain,
            keystore,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Deployment Status")?;
            output.print(&format!("Domain: {}", domain))?;

            // Imperative: Network communication
            check_deployment_status_impl(
                &domain,
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DeployAction::List {
            keystore,
            trust,
        } => {
            output.header("Deployments")?;

            // Imperative: Network communication
            list_deployments_impl(
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DeployAction::History {
            domain,
            limit,
            keystore,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Deployment History")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("Limit: {}", limit))?;

            // Imperative: Network communication
            show_deployment_history_impl(
                &domain,
                limit as u32,
                keystore.as_ref().map(|s| s.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                output,
            )
            .await
        }
        DeployAction::Rollback {
            domain,
            to_version,
            keystore,
            force,
            trust,
        } => {
            // Pure validation
            let domain = validate_domain(&domain)?;

            output.header("Rollback Deployment")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("Rolling back to version: {}", to_version))?;

            // Imperative: Network communication
            rollback_deployment_impl(
                &domain,
                &to_version.to_string(),
                Some(keystore.as_str()),
                trust.pin_spki.as_deref(),
                trust.node_did.as_deref(),
                trust.tofu,
                trust.trust_node,
                &cli.server,
                force,
                output,
            )
            .await
        }
    }
}

async fn fetch_manifest_impl(
    cid: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore_path = resolve_keystore_path(keystore)?;

    output.info("Loading identity from keystore...")?;
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let body = serde_json::to_vec(&serde_json::json!({ "cid": cid }))
        .map_err(|e| CliError::ConfigError(format!("Failed to encode request JSON: {}", e)))?;

    let bytes = post_raw(&client, "/api/v1/web4/content/manifest", body, "application/json").await?;

    // Server returns raw manifest bytes as octet-stream. It should be JSON.
    let manifest_json: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::ConfigError(format!(
            "Fetched manifest is not valid JSON ({} bytes): {}",
            bytes.len(),
            e
        ))
    })?;

    // Print pretty JSON to stdout (not via Output so it can be piped/redirected).
    println!(
        "{}",
        serde_json::to_string_pretty(&manifest_json)
            .map_err(|e| CliError::ConfigError(format!("Failed to pretty print JSON: {}", e)))?
    );

    output.success("Manifest fetched")?;
    Ok(())
}

/// Deploy a static site to Web4
async fn deploy_site_impl(
    build_dir: &str,
    domain: &str,
    mode: DeployMode,
    keystore: Option<&str>,
    fee: Option<u64>,
    dry_run: bool,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    output.info("Collecting files from build directory...")?;
    let files = collect_files(build_dir, domain)?;

    output.print(&format!("Found {} files to deploy", files.len()))?;

    if dry_run {
        output.info("DRY RUN - showing what would be deployed:")?;
        for file in &files {
            output.print(&format!("  - {}", file.path))?;
        }
        output.success("Dry run complete - no files deployed")?;
        return Ok(());
    }

    let keystore_path = resolve_keystore_path(keystore)?;

    output.info("Loading identity from keystore...")?;
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    output.info("Uploading files...")?;
    let (manifest_files, canonical_total_size) = upload_files(&client, &files, domain, output).await?;

    output.print(&format!("📊 Upload complete: {} files, {} bytes total", manifest_files.len(), canonical_total_size))?;

    let deployed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CliError::ConfigError(format!("Time error: {}", e)))?
        .as_secs();

    output.info("Building manifest...")?;
    let manifest = build_manifest(
        domain,
        mode,
        manifest_files.clone(),
        canonical_total_size,
        deployed_at,
        &loaded.identity.did,
        &loaded.keypair,
    )?;

    output.print(&format!("✅ Manifest built: {} files, hash computed", manifest.files.len()))?;

    output.info("Uploading manifest...")?;
    let manifest_hash = upload_manifest(&client, &manifest).await?;
    output.print(&format!("✅ Manifest uploaded with CID: {}", manifest_hash))?;

    if let Some(_fee_amount) = fee {
        output.info(&format!("Note: Registration fee of {} tokens reserved for future billing integration", _fee_amount))?;
    }

    let registration_body = serde_json::json!({
        "domain": domain,
        "manifest_cid": manifest_hash,
        "owner": loaded.identity.did.clone(),
    });
    let response = client
        .post_json("/api/v1/web4/domains/register", &registration_body)
        .await
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to register domain: {}", e),
        })?;
    let _: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to parse registration response: {}", e),
        })?;

    output.success(&format!("✓ Site deployed successfully to {}", domain))?;
    output.print(&format!("Manifest hash: {}", manifest_hash))?;
    output.print(&format!(
        "Use 'zhtp-cli deploy status {}' to check deployment status",
        domain
    ))?;

    Ok(())
}

/// Update an existing website deployment
async fn deploy_update_impl(
    build_dir: &str,
    domain: &str,
    mode: DeployMode,
    keystore: Option<&str>,
    fee: Option<u64>,
    dry_run: bool,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    output.info("Collecting updated files from build directory...")?;
    let files = collect_files(build_dir, domain)?;

    output.print(&format!("Found {} files to update", files.len()))?;

    if dry_run {
        output.info("DRY RUN - showing what would be updated:")?;
        for file in &files {
            output.print(&format!("  - {}", file.path))?;
        }
        output.success("Dry run complete - no files updated")?;
        return Ok(());
    }

    let keystore_path = resolve_keystore_path(keystore)?;

    output.info("Loading identity from keystore...")?;
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    output.info("Retrieving current domain status...")?;
    let status_response = client
        .get(&format!("/api/v1/web4/domains/status/{}", domain))
        .await
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to get domain status: {}", e),
        })?;
    let status: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&status_response)
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to parse domain status: {}", e),
        })?;

    let previous_cid = status
        .get("current_web4_manifest_cid")
        .or_else(|| status.get("current_manifest_cid"))  // Fallback for backwards compatibility
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: "Domain does not exist or has no manifest".to_string(),
        })?;

    output.info("Uploading updated files...")?;
    let (manifest_files, canonical_total_size) = upload_files(&client, &files, domain, output).await?;
    let deployed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CliError::ConfigError(format!("Time error: {}", e)))?
        .as_secs();

    let manifest = build_manifest(
        domain,
        mode,
        manifest_files,
        canonical_total_size,
        deployed_at,
        &loaded.identity.did,
        &loaded.keypair,
    )?;
    let manifest_hash = upload_manifest(&client, &manifest).await?;

    if let Some(_fee_amount) = fee {
        output.info(&format!("Note: Update fee of {} tokens reserved for future billing integration", _fee_amount))?;
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CliError::ConfigError(format!("Time error: {}", e)))?
        .as_secs();
    let update_message = format!("{}|{}|{}|{}", domain, previous_cid, manifest_hash, timestamp);
    let update_signature = lib_crypto::sign_message(&loaded.keypair, update_message.as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign update: {}", e)))?;

    let update_body = serde_json::json!({
        "domain": domain,
        "new_manifest_cid": manifest_hash,
        "expected_previous_manifest_cid": previous_cid,
        "signature": hex::encode(update_signature.signature),
        "timestamp": timestamp,
    });

    let response = client
        .post_json("/api/v1/web4/domains/update", &update_body)
        .await
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to update domain: {}", e),
        })?;

    let update_response: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to parse update response: {}", e),
        })?;

    let success = update_response
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !success {
        let reason = update_response
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Update failed");
        return Err(CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: reason.to_string(),
        });
    }

    output.success(&format!("✓ Domain '{}' updated successfully", domain))?;

    Ok(())
}

/// Delete a deployed domain and its manifest
async fn delete_deployment_impl(
    domain: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    _force: bool,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore_path = resolve_keystore_path(keystore)?;

    output.info("Loading identity from keystore...")?;
    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    output.info(&format!("Deleting domain: {}", domain))?;

    let body = serde_json::json!({
        "domain": domain,
        "owner_identity": loaded.identity.did,
    });
    let response = client
        .post_json(&format!("/api/v1/web4/domains/{}/release", domain), &body)
        .await
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to release domain: {}", e),
        })?;
    let result: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to parse release response: {}", e),
        })?;

    if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        output.success(&format!("✓ Domain {} released", domain))?;
        output.print(&format!(
            "Use 'zhtp-cli deploy status {}' to verify deletion status",
            domain
        ))?;
        return Ok(());
    }

    Err(CliError::DeploymentFailed {
        domain: domain.to_string(),
        reason: "Domain release failed".to_string(),
    })
}


/// Check deployment status
async fn check_deployment_status_impl(
    domain: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore_path = resolve_keystore_path(keystore)?;

    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let response = client
        .get(&format!("/api/v1/web4/domains/status/{}", domain))
        .await
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to get status: {}", e),
        })?;
    let status: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to parse status: {}", e),
        })?;

    let found = status
        .get("found")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !found {
        output.warning(&format!("Domain '{}' not found", domain))?;
        return Ok(());
    }

    output.success(&format!("✓ Domain '{}' is deployed", domain))?;

    if let Some(owner) = status.get("owner_did").and_then(|v| v.as_str()) {
        output.print(&format!("Owner: {}", owner))?;
    }

    if let Some(version) = status.get("version").and_then(|v| v.as_u64()) {
        output.print(&format!("Current version: {}", version))?;
    }

    if let Some(cid) = status.get("current_web4_manifest_cid")
        .or_else(|| status.get("current_manifest_cid"))  // Fallback for backwards compatibility
        .and_then(|v| v.as_str())
    {
        output.print(&format!("Manifest CID: {}", cid))?;
    }

    if let Some(updated) = status.get("updated_at").and_then(|v| v.as_u64()) {
        output.print(&format!("Last updated: {}", updated))?;
    }

    Ok(())
}


/// List all deployments
async fn list_deployments_impl(
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore_path = resolve_keystore_path(keystore)?;

    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let response = client
        .get(&format!("/api/v1/web4/domains?owner={}", loaded.identity.did))
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to list domains: {}", e)))?;
    let data: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse domain list: {}", e)))?;

    let domains = data
        .get("domains")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if domains.is_empty() {
        output.info("No deployments found")?;
        return Ok(());
    }

    output.success(&format!("✓ Found {} deployment(s)", domains.len()))?;
    for (idx, domain) in domains.iter().enumerate() {
        let display = domain
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| domain.to_string());
        output.print(&format!("  {}. {}", idx + 1, display))?;
    }

    Ok(())
}

/// Show deployment history for a domain
async fn show_deployment_history_impl(
    domain: &str,
    limit: u32,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore_path = resolve_keystore_path(keystore)?;

    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    let path = if limit > 0 {
        format!("/api/v1/web4/domains/history/{}?limit={}", domain, limit)
    } else {
        format!("/api/v1/web4/domains/history/{}", domain)
    };
    let response = client
        .get(&path)
        .await
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to get history: {}", e),
        })?;
    let history: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to parse history: {}", e),
        })?;

    let empty_vec = vec![];
    let versions = history
        .get("versions")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_vec);

    if versions.is_empty() {
        output.info(&format!("No deployment history found for '{}'", domain))?;
        return Ok(());
    }

    output.success(&format!("✓ Found {} version(s)", versions.len()))?;
    for (idx, version) in versions.iter().enumerate() {
        let display_version = version.get("version").and_then(|v| v.as_u64());
        match display_version {
            Some(v) => output.print(&format!("  Version {}", v))?,
            None => output.print(&format!("  Version {}", idx + 1))?,
        }
        if let Some(cid) = version.get("web4_manifest_cid")
            .or_else(|| version.get("manifest_cid"))  // Fallback for backwards compatibility
            .and_then(|v| v.as_str())
        {
            output.print(&format!("    Manifest CID: {}", cid))?;
        }
        if let Some(created) = version.get("created_at").and_then(|v| v.as_u64()) {
            output.print(&format!("    Created: {}", created))?;
        }
    }

    Ok(())
}
/// Rollback deployment to a previous version
async fn rollback_deployment_impl(
    domain: &str,
    to_version: &str,
    keystore: Option<&str>,
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
    server: &str,
    _force: bool,
    output: &dyn Output,
) -> CliResult<()> {
    let keystore_path = resolve_keystore_path(keystore)?;

    let loaded = load_identity_from_keystore(&keystore_path)?;
    let trust_config = build_trust_config(pin_spki, node_did, tofu, trust_node)?;
    let client = connect_client(loaded.identity.clone(), trust_config, server).await?;

    // Parse version number
    let version_num: u64 = to_version
        .parse()
        .map_err(|_| CliError::ConfigError(format!("Invalid version number: {}", to_version)))?;

    output.info(&format!("Rolling back {} to version {}...", domain, version_num))?;

    let body = serde_json::json!({
        "to_version": version_num,
    });
    let response = client
        .post_json(&format!("/api/v1/web4/domains/{}/rollback", domain), &body)
        .await
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to rollback: {}", e),
        })?;
    let result: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: format!("Failed to parse rollback response: {}", e),
        })?;

    output.success(&format!("✓ Rolled back {} to version {}", domain, version_num))?;

    if let Some(new_version) = result.get("rolled_back_to").and_then(|v| v.as_u64()) {
        output.print(&format!("New version: {}", new_version))?;
    }

    Ok(())
}


// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_mode_from_str_spa() {
        assert_eq!("spa".parse::<DeployMode>().unwrap(), DeployMode::Spa);
        assert_eq!("SPA".parse::<DeployMode>().unwrap(), DeployMode::Spa);
        assert_eq!("Spa".parse::<DeployMode>().unwrap(), DeployMode::Spa);
    }

    #[test]
    fn test_deploy_mode_from_str_static() {
        assert_eq!(
            "static".parse::<DeployMode>().unwrap(),
            DeployMode::Static
        );
        assert_eq!(
            "STATIC".parse::<DeployMode>().unwrap(),
            DeployMode::Static
        );
    }

    #[test]
    fn test_deploy_mode_from_str_invalid() {
        assert!("invalid".parse::<DeployMode>().is_err());
        assert!("".parse::<DeployMode>().is_err());
    }

    #[test]
    fn test_deploy_mode_as_str() {
        assert_eq!(DeployMode::Spa.as_str(), "spa");
        assert_eq!(DeployMode::Static.as_str(), "static");
    }

    #[test]
    fn test_action_to_operation_site() {
        let action = DeployAction::Site {
            build_dir: "./dist".to_string(),
            domain: "myapp.zhtp".to_string(),
            mode: Some("spa".to_string()),
            keystore: Some("~/.zhtp/keystore".to_string()),
            fee: None,
            dry_run: false,
            trust: crate::argument_parsing::TrustFlags {
                pin_spki: None,
                node_did: None,
                tofu: false,
                trust_node: false,
            },
        };
        assert_eq!(action_to_operation(&action), DeployOperation::Site);
    }

    #[test]
    fn test_action_to_operation_status() {
        let action = DeployAction::Status {
            domain: "myapp.zhtp".to_string(),
            keystore: None,
            trust: crate::argument_parsing::TrustFlags {
                pin_spki: None,
                node_did: None,
                tofu: false,
                trust_node: false,
            },
        };
        assert_eq!(action_to_operation(&action), DeployOperation::Status);
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("myapp.zhtp").is_ok());
        assert!(validate_domain("example.sov").is_ok());
    }

    #[test]
    fn test_validate_domain_invalid_extension() {
        assert!(validate_domain("myapp.com").is_err());
        assert!(validate_domain("example.net").is_err());
    }

    #[test]
    fn test_validate_domain_empty() {
        assert!(validate_domain("").is_err());
    }

    #[test]
    fn test_validate_build_directory_valid() {
        let result = validate_build_directory("./dist");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("./dist"));
    }

    #[test]
    fn test_validate_build_directory_empty() {
        assert!(validate_build_directory("").is_err());
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(
            DeployOperation::Site.description(),
            "Deploy website to Web4"
        );
        assert_eq!(
            DeployOperation::Status.description(),
            "Check deployment status"
        );
        assert_eq!(
            DeployOperation::List.description(),
            "List deployments"
        );
        assert_eq!(
            DeployOperation::History.description(),
            "Show deployment history"
        );
        assert_eq!(
            DeployOperation::Rollback.description(),
            "Rollback to previous version"
        );
    }
}
