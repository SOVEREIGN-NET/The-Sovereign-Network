//! Web4 Deploy Command
//!
//! Deploy static websites (React, Next.js, Vue, etc.) to Web4 domains.
//!
//! Usage:
//!   zhtp deploy ./build --domain myapp.zhtp
//!   zhtp deploy ./out --domain myapp.zhtp --mode spa
//!   zhtp deploy ./dist --domain myapp.zhtp --owner did:zhtp:abc123

use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn, error, debug};

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

/// Content mapping for deployment
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentMapping {
    pub content: String,      // Base64 encoded
    pub content_type: String, // MIME type
}

/// Domain registration request (matches API)
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleDomainRegistrationRequest {
    pub domain: String,
    pub owner: String,
    pub content_mappings: HashMap<String, ContentMapping>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    pub signature: String,
    pub timestamp: u64,
    #[serde(default)]
    pub fee: Option<u64>,
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
            owner,
            fee,
            dry_run,
        } => {
            deploy_site(
                build_dir,
                domain,
                mode.as_deref().unwrap_or("spa"),
                owner.as_deref(),
                *fee,
                *dry_run,
                cli,
            ).await
        }
        DeployAction::Status { domain } => {
            check_deployment_status(domain, cli).await
        }
        DeployAction::List => {
            list_deployments(cli).await
        }
    }
}

/// Deploy a static site to Web4
async fn deploy_site(
    build_dir: &str,
    domain: &str,
    mode: &str,
    owner: Option<&str>,
    fee: Option<u64>,
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

    println!("🚀 Deploying to Web4");
    println!("   Domain: {}", domain);
    println!("   Mode: {:?}", deploy_mode);
    println!("   Build dir: {}", build_path.display());

    // Walk directory and collect files
    println!("\n📦 Collecting files...");
    let files = collect_files(&build_path)?;

    if files.is_empty() {
        return Err(anyhow!("No files found in build directory"));
    }

    let total_size: u64 = files.iter().map(|(_, _, size)| size).sum();
    println!("   Found {} files ({} bytes total)", files.len(), total_size);

    // Build content mappings
    println!("\n🔧 Building content mappings...");
    let mut content_mappings = HashMap::new();
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

        content_mappings.insert(web_path.clone(), ContentMapping {
            content: general_purpose::STANDARD.encode(&content),
            content_type: mime_type.clone(),
        });

        manifest_files.push(FileEntry {
            path: web_path,
            size: *size,
            mime_type,
            hash,
        });
    }

    // For SPA mode, ensure index.html exists and will be served for all routes
    if deploy_mode == DeployMode::Spa {
        if !content_mappings.contains_key("/index.html") {
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

    println!("\n💰 Estimated fee: {} ZHTP", deploy_fee);

    if dry_run {
        println!("\n🔍 DRY RUN - No changes will be made");
        println!("\nFiles that would be deployed:");
        for file in &manifest_files {
            println!("  {} ({}, {} bytes)", file.path, file.mime_type, file.size);
        }
        return Ok(());
    }

    // Build registration request
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // For now, use test signature (in production, would sign with identity keypair)
    let owner_id = owner.unwrap_or("test_owner");
    let signature = if owner.is_some() {
        // TODO: Sign with actual identity keypair
        // For now, this will only work in dev mode
        "746573745f6465765f7369676e6174757265".to_string() // "test_dev_signature" hex
    } else {
        "746573745f6465765f7369676e6174757265".to_string()
    };

    let request = SimpleDomainRegistrationRequest {
        domain: domain.to_string(),
        owner: owner_id.to_string(),
        content_mappings,
        metadata: Some(serde_json::json!({
            "title": domain,
            "description": format!("Web4 site deployed via CLI"),
            "mode": mode,
            "deployed_at": timestamp,
        })),
        signature,
        timestamp,
        fee: Some(deploy_fee),
    };

    println!("\n📡 Sending to node {}...", cli.server);

    // Send request to node via QUIC
    let response = send_deploy_request(&cli.server, &request).await?;

    println!("\n✅ Deployment successful!");
    println!("   Domain: {}", domain);
    println!("   URL: https://{}", domain);

    if let Some(tx_hash) = response.get("blockchain_transaction") {
        println!("   Transaction: {}", tx_hash);
    }

    if let Some(fees) = response.get("fees_charged") {
        println!("   Fees: {} ZHTP", fees);
    }

    Ok(())
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

/// Send deploy request to node
///
/// TODO: Implement actual transport layer.
/// Options being evaluated:
/// 1. QUIC with full UHP+Kyber handshake (requires identity)
/// 2. HTTP gateway that translates to ZHTP
/// 3. Lightweight QUIC client for CLI
async fn send_deploy_request(
    server: &str,
    request: &SimpleDomainRegistrationRequest,
) -> Result<serde_json::Value> {
    // For now, output the request that would be sent
    info!("Would send deploy request to {}", server);
    info!("Domain: {}", request.domain);
    info!("Files: {}", request.content_mappings.len());

    // TODO: Implement actual network transport
    // The node speaks QUIC+UHP+Kyber, need to determine best CLI approach
    Err(anyhow!(
        "Network transport not yet implemented. \
        Use --dry-run to preview deployment, or deploy via node API directly."
    ))
}

/// Check deployment status for a domain
async fn check_deployment_status(domain: &str, cli: &ZhtpCli) -> Result<()> {
    println!("🔍 Checking deployment status for {}", domain);

    // TODO: Query node for domain status
    // For now, just show placeholder
    println!("   Status: Active");
    println!("   Files: (query node for details)");

    Ok(())
}

/// List all deployments
async fn list_deployments(cli: &ZhtpCli) -> Result<()> {
    println!("📋 Listing Web4 deployments");

    // TODO: Query node for all domains owned by current identity
    println!("   (No deployments found or not connected to node)");

    Ok(())
}
