//! Web4 Deploy Command
//!
//! Deploy static websites (React, Next.js, Vue, etc.) to Web4 domains.
//!
//! Uses native QUIC transport with UHP+Kyber handshake for authenticated
//! communication with ZHTP nodes.
//!
//! Usage:
//!   zhtp deploy ./build --domain myapp.zhtp --keystore ~/.zhtp/keystore
//!   zhtp deploy ./out --domain myapp.zhtp --mode spa --keystore ./keys
//!   zhtp deploy ./dist --domain myapp.zhtp --owner did:zhtp:abc123

use anyhow::{anyhow, Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing::{info, debug, warn};
use atty::Stream;

use lib_network::web4::{Web4Client, TrustConfig};
use lib_identity::ZhtpIdentity;

use crate::cli::{DeployArgs, DeployAction, ZhtpCli};

/// Supported deployment modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployMode {
    /// Single Page Application - all routes serve index.html
    Spa,
    /// Static site - each file served at its path
    Static,
}

impl std::str::FromStr for DeployMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "spa" => Ok(DeployMode::Spa),
            "static" => Ok(DeployMode::Static),
            _ => Err(anyhow!("Invalid deploy mode: {}. Use 'spa' or 'static'", s)),
        }
    }
}

/// Deployment manifest tracking all files
#[derive(Debug, Serialize, Deserialize)]
pub struct DeployManifest {
    pub domain: String,
    pub mode: String,
    pub files: Vec<FileEntry>,
    pub total_size: u64,
    pub deployed_at: u64,
}

/// Single file entry in manifest
#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mime_type: String,
    pub hash: String,
}

/// Handle deploy command
pub async fn handle_deploy_command(args: DeployArgs, cli: &ZhtpCli) -> Result<()> {
    match &args.action {
        DeployAction::Site {
            build_dir,
            domain,
            mode,
            keystore,
            fee,
            pin_spki,
            node_did,
            tofu,
            trust_node,
            dry_run,
        } => {
            let trust_config = build_trust_config(
                pin_spki.clone(),
                node_did.clone(),
                *tofu,
                *trust_node,
            )?;

            deploy_site(
                build_dir,
                domain,
                mode.as_deref().unwrap_or("spa"),
                keystore,
                *fee,
                trust_config,
                *dry_run,
                cli,
            ).await
        }
        DeployAction::Status {
            domain,
            keystore,
            pin_spki,
            node_did,
            tofu,
            trust_node,
        } => {
            let trust_config = build_trust_config(
                pin_spki.clone(),
                node_did.clone(),
                *tofu,
                *trust_node,
            )?;

            check_deployment_status(
                domain,
                keystore.as_deref(),
                trust_config,
                cli,
            ).await
        }
        DeployAction::List {
            keystore,
            pin_spki,
            node_did,
            tofu,
            trust_node,
        } => {
            let trust_config = build_trust_config(
                pin_spki.clone(),
                node_did.clone(),
                *tofu,
                *trust_node,
            )?;

            list_deployments(
                keystore.as_deref(),
                trust_config,
                cli,
            ).await
        }

        DeployAction::History {
            domain,
            limit,
            keystore,
            pin_spki,
            node_did,
            tofu,
            trust_node,
        } => {
            let trust_config = build_trust_config(
                pin_spki.clone(),
                node_did.clone(),
                *tofu,
                *trust_node,
            )?;

            show_deployment_history(
                domain,
                *limit,
                keystore.as_deref(),
                trust_config,
                cli,
            ).await
        }

        DeployAction::Rollback {
            domain,
            to_version,
            keystore,
            pin_spki,
            node_did,
            tofu,
            trust_node,
            force,
        } => {
            let trust_config = build_trust_config(
                pin_spki.clone(),
                node_did.clone(),
                *tofu,
                *trust_node,
            )?;

            rollback_deployment(
                domain,
                *to_version,
                keystore,
                trust_config,
                *force,
                cli,
            ).await
        }
    }
}

/// Build TrustConfig from CLI flags
fn build_trust_config(
    pin_spki: Option<String>,
    node_did: Option<String>,
    tofu: bool,
    trust_node: bool,
) -> Result<TrustConfig> {
    let trustdb_path = TrustConfig::default_trustdb_path()?;

    let mut config = if trust_node {
        warn!("Bootstrap mode enabled - NO TLS VERIFICATION (insecure)");
        TrustConfig::bootstrap()
    } else if let Some(pin) = pin_spki {
        info!("Using SPKI pinning");
        TrustConfig::with_pin(pin)
    } else if tofu {
        info!("Using Trust On First Use (TOFU)");
        TrustConfig::with_tofu(trustdb_path.clone())
    } else {
        // Default: strict mode with trustdb
        TrustConfig {
            trustdb_path: Some(trustdb_path.clone()),
            ..Default::default()
        }
    };

    // Add node_did expectation if provided
    if let Some(did) = node_did {
        config.node_did = Some(did);
    }

    // Ensure persistence paths are set
    if config.trustdb_path.is_none() {
        config.trustdb_path = Some(trustdb_path.clone());
    }
    if config.audit_log_path.is_none() {
        config.audit_log_path = Some(TrustConfig::default_audit_path());
    }

    Ok(config)
}

/// Confirm TOFU usage on interactive terminals
fn confirm_tofu_if_needed(config: &TrustConfig) -> Result<()> {
    if config.allow_tofu && !config.bootstrap_mode && config.pin_spki.is_none() {
        // If stdin is a TTY, prompt; otherwise rely on explicit flag
        if atty::is(Stream::Stdin) {
            println!("\nTOFU WARNING: First connection may be intercepted (MITM risk).");
            println!("This will trust the presented certificate fingerprint and store it for future sessions.");
            print!("Proceed with TOFU? (y/N): ");
            io::stdout().flush().ok();
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let proceed = input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes");
            if !proceed {
                return Err(anyhow!("TOFU not confirmed by user"));
            }
        }
    }
    Ok(())
}

/// Deploy a static site to Web4
async fn deploy_site(
    build_dir: &str,
    domain: &str,
    mode: &str,
    keystore: &str,
    fee: Option<u64>,
    trust_config: TrustConfig,
    dry_run: bool,
    cli: &ZhtpCli,
) -> Result<()> {
    let build_path = PathBuf::from(build_dir);

    // Validate build directory exists
    if !build_path.exists() {
        return Err(anyhow!("Build directory does not exist: {}", build_dir));
    }

    if !build_path.is_dir() {
        return Err(anyhow!("Path is not a directory: {}", build_dir));
    }

    // Validate domain format
    if !domain.ends_with(".zhtp") && !domain.ends_with(".sov") {
        return Err(anyhow!(
            "Domain must end with .zhtp or .sov (got: {})",
            domain
        ));
    }

    let deploy_mode: DeployMode = mode.parse()?;

    println!("Deploying to Web4");
    println!("   Domain: {}", domain);
    println!("   Mode: {:?}", deploy_mode);
    println!("   Build dir: {}", build_path.display());

    // Walk directory and collect files
    println!("\nCollecting files...");
    let files = collect_files(&build_path)?;

    if files.is_empty() {
        return Err(anyhow!("No files found in build directory"));
    }

    let total_size: u64 = files.iter().map(|(_, _, size)| size).sum();
    println!("   Found {} files ({} bytes total)", files.len(), total_size);

    // Build file entries for manifest
    println!("\nProcessing files...");
    let mut file_entries: Vec<(String, Vec<u8>, String, String)> = Vec::new(); // (path, content, mime, hash)
    let mut manifest_files = Vec::new();

    for (rel_path, abs_path, size) in &files {
        let content = std::fs::read(abs_path)?;
        let mime_type = guess_mime_type(rel_path);
        let hash = hex::encode(&lib_crypto::hash_blake3(&content)[..8]);

        // Convert path to web path (ensure leading /)
        let web_path = if rel_path.starts_with('/') {
            rel_path.clone()
        } else {
            format!("/{}", rel_path)
        };

        debug!("  {} ({}, {} bytes)", web_path, mime_type, size);

        file_entries.push((web_path.clone(), content, mime_type.clone(), hash.clone()));

        manifest_files.push(FileEntry {
            path: web_path,
            size: *size,
            mime_type,
            hash,
        });
    }

    // For SPA mode, ensure index.html exists
    if deploy_mode == DeployMode::Spa {
        let has_index = file_entries.iter().any(|(p, _, _, _)| p == "/index.html");
        if !has_index {
            return Err(anyhow!(
                "SPA mode requires index.html in build directory"
            ));
        }
        println!("   SPA mode: /index.html will serve all routes");
    }

    // Calculate fee if not provided
    let estimated_tx_size = 5400 + (total_size / 10); // Base + content size factor
    let min_fee = (estimated_tx_size / 5) as u64; // ~1 ZHTP per 5 bytes
    let deploy_fee = fee.unwrap_or(min_fee.max(1500)); // At least 1500 ZHTP

    println!("\nEstimated fee: {} ZHTP", deploy_fee);

    if dry_run {
        println!("\nDRY RUN - No changes will be made");
        println!("\nFiles that would be deployed:");
        for file in &manifest_files {
            println!("  {} ({}, {} bytes)", file.path, file.mime_type, file.size);
        }
        return Ok(());
    }

    // Load identity from keystore (REQUIRED - no ephemeral fallback)
    let identity = load_identity(keystore)
        .context("Failed to load identity from keystore")?;

    // Domain ownership bound to deploy identity
    let owner_did = identity.did.clone();

    println!("\nUsing identity: {}", identity.did);
    println!("Domain owner: {}", owner_did);

    // Confirm TOFU usage interactively if applicable
    confirm_tofu_if_needed(&trust_config)?;

    // Create Web4 client and connect
    println!("\nConnecting to node at {}...", cli.server);

    let mut client = Web4Client::new_with_trust(identity, trust_config).await
        .context("Failed to create Web4 client")?;

    client.connect(&cli.server).await
        .context("Failed to connect to ZHTP node")?;

    // Log verified peer for audit
    if let Some(peer_did) = client.peer_did() {
        println!("   Connected to node: {}", peer_did);
    }
    println!("   PQC encryption active");

    // Sort files for deterministic manifest (stable upload order)
    file_entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Upload each file as a blob
    println!("\nUploading {} files...", file_entries.len());
    let mut file_cids: Vec<FileCidEntry> = Vec::with_capacity(file_entries.len());

    // Chunk size for large files (1MB default)
    const CHUNK_SIZE: usize = 1024 * 1024;
    // Threshold for using chunked uploads (files > 1MB use chunking)
    const CHUNK_THRESHOLD: usize = CHUNK_SIZE;

    for (i, (path, content, mime_type, hash)) in file_entries.iter().enumerate() {
        let cid = if content.len() > CHUNK_THRESHOLD {
            // Large file: use chunked upload
            println!("   [{}/{}] {} ({} bytes, chunked)", i + 1, file_entries.len(), path, content.len());
            client.put_blob_chunked(content.clone(), mime_type, Some(CHUNK_SIZE)).await
                .with_context(|| format!("Failed to upload {} (chunked)", path))?
        } else {
            // Small file: upload directly
            client.put_blob(content.clone(), mime_type).await
                .with_context(|| format!("Failed to upload {}", path))?
        };

        file_cids.push(FileCidEntry {
            path: path.clone(),
            cid: cid.clone(),
            size: content.len() as u64,
            mime: mime_type.clone(),
            etag: hash.clone(),
            encoding: None, // No compression yet
        });
        println!("   [{}/{}] {} -> {}", i + 1, file_entries.len(), path, &cid[..16]);
    }

    // Build manifest per spec (section 8.3)
    println!("\nBuilding manifest...");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // Calculate root CID from sorted file CIDs
    let root_cid = calculate_root_cid(&file_cids);

    let manifest = serde_json::json!({
        "version": "1.0",
        "domain": domain,
        "owner": owner_did,
        "root_cid": root_cid,
        "files": file_cids.iter().map(|f| serde_json::json!({
            "path": f.path,
            "cid": f.cid,
            "size": f.size,
            "mime": f.mime,
            "etag": f.etag,
            "encoding": f.encoding,
        })).collect::<Vec<_>>(),
        "spa_fallback": if deploy_mode == DeployMode::Spa { Some("/index.html") } else { None },
        "cache_hints": {
            "immutable": ["*.woff2", "*.woff", "*.js", "*.css"],
            "revalidate": ["*.html", "*.json"],
        },
        "deployed_at": timestamp,
        "fee": deploy_fee,
    });

    let manifest_cid = client.put_manifest(&manifest).await
        .context("Failed to upload manifest")?;

    println!("   Root CID: {}", root_cid);
    println!("   Manifest CID: {}", manifest_cid);

    // Check if domain already exists to determine update vs register
    println!("\nChecking domain status...");
    let domain_status = client.get_domain_status(domain).await
        .context("Failed to check domain status")?;

    let result = if domain_status.get("found").and_then(|v| v.as_bool()).unwrap_or(false) {
        // Domain exists - perform versioned update
        let current_version = domain_status.get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let current_cid = domain_status.get("current_manifest_cid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let domain_owner = domain_status.get("owner_did")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        println!("   Domain exists at v{}", current_version);
        println!("   Owner: {}", domain_owner);

        // Verify we own the domain
        if !domain_owner.is_empty() && domain_owner != owner_did {
            return Err(anyhow!(
                "Domain {} is owned by {}, not by your identity {}. Cannot update.",
                domain, domain_owner, owner_did
            ));
        }

        println!("\nUpdating domain {} (v{} -> v{})...", domain, current_version, current_version + 1);

        client.update_domain(domain, &manifest_cid, &current_cid).await
            .context("Failed to update domain")?
    } else {
        // New domain - register it
        println!("\nRegistering new domain {}...", domain);
        client.register_domain(domain, &manifest_cid).await
            .context("Failed to register domain")?
    };

    client.close().await;

    // Extract version info from result
    let new_version = result.get("new_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    let is_update = result.get("previous_manifest_cid").is_some();

    println!("\nDeployment successful!");
    println!("   Domain: {}", domain);
    println!("   URL: zhtp://{}", domain);
    println!("   Version: v{}", new_version);
    println!("   Manifest: {}", manifest_cid);
    println!("   Owner: {}", owner_did);
    if is_update {
        if let Some(prev_cid) = result.get("previous_manifest_cid").and_then(|v| v.as_str()) {
            println!("   Previous: {}...", &prev_cid[..16.min(prev_cid.len())]);
        }
    }

    if let Some(tx_hash) = result.get("blockchain_transaction") {
        println!("   Transaction: {}", tx_hash);
    }

    if let Some(fees) = result.get("fees_charged") {
        println!("   Fees: {} ZHTP", fees);
    }

    Ok(())
}

/// File CID entry for manifest
#[derive(Debug, Clone)]
struct FileCidEntry {
    path: String,
    cid: String,
    size: u64,
    mime: String,
    etag: String,
    encoding: Option<String>,
}

/// Calculate root CID from sorted file CIDs (deterministic)
fn calculate_root_cid(files: &[FileCidEntry]) -> String {
    // Concatenate all CIDs in sorted order and hash
    let mut hasher_input = Vec::new();
    for f in files {
        hasher_input.extend_from_slice(f.cid.as_bytes());
    }
    let hash = lib_crypto::hash_blake3(&hasher_input);
    format!("bafk{}", hex::encode(&hash[..16]))
}

/// Load identity from keystore (REQUIRED - no ephemeral fallback)
///
/// Returns error if keystore doesn't exist or identity cannot be loaded.
/// This enforces domain ownership bound to a persistent, authorized identity.
fn load_identity(keystore_path: &str) -> Result<ZhtpIdentity> {
    let keystore = PathBuf::from(keystore_path);
    let identity_file = keystore.join("identity.json");

    if !keystore.exists() {
        return Err(anyhow!(
            "Keystore directory not found: {:?}\n\
            Create an identity first with: zhtp identity create --keystore {:?}",
            keystore, keystore
        ));
    }

    if !identity_file.exists() {
        return Err(anyhow!(
            "No identity.json found in keystore at {:?}\n\
            Create an identity first with: zhtp identity create --keystore {:?}",
            keystore, keystore
        ));
    }

    let data = std::fs::read_to_string(&identity_file)
        .context("Failed to read identity.json")?;
    let identity: ZhtpIdentity = serde_json::from_str(&data)
        .context("Failed to parse identity.json")?;

    info!("Loaded identity {} from {:?}", identity.did, identity_file);
    Ok(identity)
}

/// Collect all files from a directory recursively
fn collect_files(dir: &Path) -> Result<Vec<(String, PathBuf, u64)>> {
    let mut files = Vec::new();
    collect_files_recursive(dir, dir, &mut files)?;
    Ok(files)
}

fn collect_files_recursive(
    base: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf, u64)>,
) -> Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Skip hidden directories and node_modules
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            collect_files_recursive(base, &path, files)?;
        } else if path.is_file() {
            // Skip hidden files
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.starts_with('.') {
                continue;
            }

            let rel_path = path.strip_prefix(base)?
                .to_string_lossy()
                .replace('\\', "/"); // Normalize for Windows

            let metadata = std::fs::metadata(&path)?;
            files.push((rel_path, path.clone(), metadata.len()));
        }
    }
    Ok(())
}

/// Guess MIME type from file extension
fn guess_mime_type(path: &str) -> String {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();

    match ext.as_str() {
        // Web essentials
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",

        // Images
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "avif" => "image/avif",

        // Fonts
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",

        // Other
        "txt" => "text/plain",
        "md" => "text/markdown",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "map" => "application/json", // Source maps

        _ => "application/octet-stream",
    }.to_string()
}

/// Check deployment status for a domain
async fn check_deployment_status(
    domain: &str,
    keystore: Option<&str>,
    trust_config: TrustConfig,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("Checking deployment status for {}", domain);
    println!();

    // Load identity from provided keystore or default location
    let keystore_path = keystore
        .map(|s| s.to_string())
        .unwrap_or_else(|| get_default_keystore_path().unwrap_or_else(|_| "~/.zhtp/keystore".to_string()));
    let identity = load_identity(&keystore_path)
        .context("Failed to load identity. Create one with: zhtp identity create")?;

    // Connect to node with trust configuration
    let mut client = Web4Client::new_with_trust(identity, trust_config).await
        .context("Failed to create Web4 client")?;

    client.connect(&cli.server).await
        .context("Failed to connect to ZHTP node")?;

    // Query domain status
    match client.get_domain(domain).await? {
        Some(info) => {
            println!("Domain: {}", domain);
            println!("   Status: Active");

            if let Some(owner) = info.get("owner").and_then(|v| v.as_str()) {
                println!("   Owner: {}", owner);
            }

            if let Some(manifest_cid) = info.get("manifest_cid").and_then(|v| v.as_str()) {
                println!("   Manifest: {}", manifest_cid);
            }

            if let Some(root_cid) = info.get("root_cid").and_then(|v| v.as_str()) {
                println!("   Root CID: {}", root_cid);
            }

            if let Some(deployed_at) = info.get("deployed_at").and_then(|v| v.as_u64()) {
                let datetime = chrono::DateTime::from_timestamp(deployed_at as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| deployed_at.to_string());
                println!("   Deployed: {}", datetime);
            }

            if let Some(files) = info.get("files").and_then(|v| v.as_array()) {
                println!("   Files: {} total", files.len());
                if cli.verbose {
                    for file in files {
                        if let Some(path) = file.get("path").and_then(|v| v.as_str()) {
                            let size = file.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                            println!("      {} ({} bytes)", path, size);
                        }
                    }
                }
            }

            if let Some(mode) = info.get("spa_fallback") {
                if !mode.is_null() {
                    println!("   Mode: SPA (fallback: {})", mode);
                } else {
                    println!("   Mode: Static");
                }
            }

            println!();
            println!("URL: zhtp://{}", domain);
        }
        None => {
            println!("Domain not found: {}", domain);
            println!();
            println!("The domain may not be registered or the node may not have it cached.");
        }
    }

    client.close().await;
    Ok(())
}

/// List all deployments
async fn list_deployments(
    keystore: Option<&str>,
    trust_config: TrustConfig,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("Listing Web4 deployments");
    println!();

    // Load identity from provided keystore or default location
    let keystore_path = keystore
        .map(|s| s.to_string())
        .unwrap_or_else(|| get_default_keystore_path().unwrap_or_else(|_| "~/.zhtp/keystore".to_string()));
    let identity = load_identity(&keystore_path)
        .context("Failed to load identity. Create one with: zhtp identity create")?;

    println!("Identity: {}", identity.did);
    println!();

    // Connect to node with trust configuration
    let mut client = Web4Client::new_with_trust(identity, trust_config).await
        .context("Failed to create Web4 client")?;

    client.connect(&cli.server).await
        .context("Failed to connect to ZHTP node")?;

    // Query domains owned by this identity
    let domains = client.list_domains().await?;

    if domains.is_empty() {
        println!("No deployments found for this identity.");
        println!();
        println!("Deploy a site with:");
        println!("  zhtp deploy site ./build --domain myapp.zhtp --keystore ~/.zhtp/keystore");
    } else {
        println!("Deployments ({} total):", domains.len());
        println!();

        for domain_info in &domains {
            let domain = domain_info.get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let manifest_cid = domain_info.get("manifest_cid")
                .and_then(|v| v.as_str())
                .map(|s| &s[..16.min(s.len())])
                .unwrap_or("...");

            let deployed_at = domain_info.get("deployed_at")
                .and_then(|v| v.as_u64())
                .map(|ts| {
                    chrono::DateTime::from_timestamp(ts as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .unwrap_or_else(|| "unknown".to_string());

            let file_count = domain_info.get("files")
                .and_then(|v| v.as_array())
                .map(|f| f.len())
                .unwrap_or(0);

            println!("  {} ", domain);
            println!("    Manifest: {}...", manifest_cid);
            println!("    Files: {}", file_count);
            println!("    Deployed: {}", deployed_at);
            println!("    URL: zhtp://{}", domain);
            println!();
        }
    }

    client.close().await;
    Ok(())
}

/// Get default keystore path (~/.zhtp/keystore)
fn get_default_keystore_path() -> Result<String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("Could not determine home directory")?;

    Ok(format!("{}/.zhtp/keystore", home))
}

/// Show deployment version history for a domain
async fn show_deployment_history(
    domain: &str,
    limit: usize,
    keystore: Option<&str>,
    trust_config: TrustConfig,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("Deployment history for: {}", domain);
    println!();

    // Load identity from provided keystore or default location
    let keystore_path = keystore
        .map(|s| s.to_string())
        .unwrap_or_else(|| get_default_keystore_path().unwrap_or_else(|_| "~/.zhtp/keystore".to_string()));
    let identity = load_identity(&keystore_path)
        .context("Failed to load identity. Create one with: zhtp identity create")?;

    // Connect to node with trust configuration
    let mut client = Web4Client::new_with_trust(identity, trust_config).await
        .context("Failed to create Web4 client")?;

    client.connect(&cli.server).await
        .context("Failed to connect to ZHTP node")?;

    // Get domain history
    let history = client.get_domain_history(domain, Some(limit)).await?;

    let current_version = history.get("current_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let versions = history.get("versions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    println!("Current version: v{}", current_version);
    println!("Showing {} versions:", versions.len());
    println!();

    for ver in &versions {
        let version = ver.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        let manifest_cid = ver.get("manifest_cid")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let created_at = ver.get("created_at")
            .and_then(|v| v.as_u64())
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());
        let message = ver.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let build_hash = ver.get("build_hash")
            .and_then(|v| v.as_str())
            .map(|s| &s[..8.min(s.len())])
            .unwrap_or("");

        let current_marker = if version == current_version { " <- current" } else { "" };

        println!("  v{}{}", version, current_marker);
        println!("    CID: {}...", &manifest_cid[..16.min(manifest_cid.len())]);
        println!("    Hash: {}...", build_hash);
        println!("    Date: {}", created_at);
        if !message.is_empty() {
            println!("    Message: {}", message);
        }
        println!();
    }

    if versions.is_empty() {
        println!("  No version history available.");
    }

    println!("Rollback with:");
    println!("  zhtp deploy rollback {} --to-version N --keystore {}", domain, keystore_path);

    client.close().await;
    Ok(())
}

/// Rollback a domain to a previous version
async fn rollback_deployment(
    domain: &str,
    to_version: u64,
    keystore: &str,
    trust_config: TrustConfig,
    force: bool,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("Rolling back {} to version {}", domain, to_version);
    println!();

    // Load identity (REQUIRED)
    let identity = load_identity(keystore)
        .context("Failed to load identity. Keystore is required for rollback.")?;

    println!("Identity: {}", identity.did);

    // Connect to node with trust configuration
    let mut client = Web4Client::new_with_trust(identity, trust_config).await
        .context("Failed to create Web4 client")?;

    client.connect(&cli.server).await
        .context("Failed to connect to ZHTP node")?;

    // Get current status first
    let status = client.get_domain_status(domain).await?;
    let current_version = status.get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let owner_did = status.get("owner_did")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    println!("Current version: v{}", current_version);
    println!("Domain owner: {}", owner_did);
    println!();

    if to_version >= current_version {
        return Err(anyhow!(
            "Cannot rollback to v{} - current version is v{}. Target must be < current.",
            to_version, current_version
        ));
    }

    if to_version == 0 {
        return Err(anyhow!("Cannot rollback to version 0. Minimum is v1."));
    }

    // Confirm unless force flag is set
    if !force {
        println!("This will create a new version (v{}) pointing to the content from v{}.",
            current_version + 1, to_version);
        print!("Continue? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Rollback cancelled.");
            client.close().await;
            return Ok(());
        }
    }

    // Perform rollback
    println!("\nExecuting rollback...");
    let result = client.rollback_domain(domain, to_version).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    let new_version = result.get("new_version").and_then(|v| v.as_u64()).unwrap_or(0);
    let new_cid = result.get("new_manifest_cid")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if success {
        println!("\nRollback successful!");
        println!("   Domain: {}", domain);
        println!("   New version: v{}", new_version);
        println!("   Manifest: {}...", &new_cid[..16.min(new_cid.len())]);
        println!("   Content from: v{}", to_version);
    } else {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        return Err(anyhow!("Rollback failed: {}", error));
    }

    client.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_mime_type() {
        // Web essentials
        assert_eq!(guess_mime_type("index.html"), "text/html");
        assert_eq!(guess_mime_type("styles.css"), "text/css");
        assert_eq!(guess_mime_type("app.js"), "application/javascript");
        assert_eq!(guess_mime_type("data.json"), "application/json");

        // Images
        assert_eq!(guess_mime_type("logo.png"), "image/png");
        assert_eq!(guess_mime_type("photo.jpg"), "image/jpeg");
        assert_eq!(guess_mime_type("photo.jpeg"), "image/jpeg");
        assert_eq!(guess_mime_type("icon.svg"), "image/svg+xml");
        assert_eq!(guess_mime_type("favicon.ico"), "image/x-icon");

        // Fonts
        assert_eq!(guess_mime_type("font.woff"), "font/woff");
        assert_eq!(guess_mime_type("font.woff2"), "font/woff2");

        // Other
        assert_eq!(guess_mime_type("module.wasm"), "application/wasm");
        assert_eq!(guess_mime_type("bundle.js.map"), "application/json");
        assert_eq!(guess_mime_type("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn test_deploy_mode_parsing() {
        assert_eq!("spa".parse::<DeployMode>().unwrap(), DeployMode::Spa);
        assert_eq!("SPA".parse::<DeployMode>().unwrap(), DeployMode::Spa);
        assert_eq!("static".parse::<DeployMode>().unwrap(), DeployMode::Static);
        assert_eq!("STATIC".parse::<DeployMode>().unwrap(), DeployMode::Static);
        assert!("invalid".parse::<DeployMode>().is_err());
    }

    #[test]
    fn test_file_entry_serialization() {
        let entry = FileEntry {
            path: "/index.html".to_string(),
            size: 1234,
            mime_type: "text/html".to_string(),
            hash: "abc12345".to_string(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let decoded: FileEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.path, entry.path);
        assert_eq!(decoded.size, entry.size);
        assert_eq!(decoded.mime_type, entry.mime_type);
        assert_eq!(decoded.hash, entry.hash);
    }
}
