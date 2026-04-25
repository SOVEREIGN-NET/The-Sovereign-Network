//! GitHub webhook handler + deploy worker for automatic Web4 site deployment.
//!
//! Flow:
//! 1. User installs GitHub App on their repo
//! 2. User adds `sov.toml` to repo root (domain, build command, output dir)
//! 3. User registers domain + authorizes the gateway's DID as delegate
//! 4. Push to main → GitHub webhook → clone → build → deploy via QUIC
//! 5. GitHub commit status set (✓ deployed / ✗ failed)

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn, error};

// ─── sov.toml config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SovConfig {
    pub deploy: DeployConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeployConfig {
    pub domain: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    pub build_command: Option<String>,
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
}

fn default_mode() -> String { "spa".to_string() }
fn default_output_dir() -> String { "dist".to_string() }

impl SovConfig {
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).context("Failed to parse sov.toml")
    }
}

// ─── GitHub webhook types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GitHubPushEvent {
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub after: String, // commit SHA
    pub repository: GitHubRepo,
    #[serde(default)]
    pub head_commit: Option<GitHubCommit>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubRepo {
    pub full_name: String,
    pub clone_url: String,
    pub default_branch: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubCommit {
    pub id: String,
    pub message: String,
    pub author: GitHubAuthor,
}

#[derive(Debug, Deserialize)]
pub struct GitHubAuthor {
    pub name: String,
}

impl GitHubPushEvent {
    /// Check if this push is to the default branch
    pub fn is_default_branch(&self) -> bool {
        self.git_ref == format!("refs/heads/{}", self.repository.default_branch)
    }
}

// ─── Webhook signature verification ────────────────────────────────────────────

/// Verify GitHub webhook HMAC-SHA256 signature.
/// GitHub sends `X-Hub-Signature-256: sha256=<hex>`.
pub fn verify_webhook_signature(secret: &str, body: &[u8], signature_header: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let expected = match signature_header.strip_prefix("sha256=") {
        Some(hex) => hex,
        None => return false,
    };

    let expected_bytes = match hex::decode(expected) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);

    mac.verify_slice(&expected_bytes).is_ok()
}

// ─── Deploy worker ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeployJob {
    pub repo_url: String,
    pub commit_sha: String,
    pub repo_full_name: String,
    pub branch: String,
}

#[derive(Debug, Serialize)]
pub struct DeployResult {
    pub success: bool,
    pub domain: Option<String>,
    pub error: Option<String>,
    pub files_uploaded: usize,
    pub total_size: u64,
}

/// Execute a deploy job: clone repo, read sov.toml, build, deploy.
pub async fn execute_deploy(
    job: &DeployJob,
    service: &crate::service::ZhtpDaemonService,
    work_dir: &Path,
) -> DeployResult {
    match execute_deploy_inner(job, service, work_dir).await {
        Ok(result) => result,
        Err(e) => {
            error!("Deploy failed for {}: {}", job.repo_full_name, e);
            DeployResult {
                success: false,
                domain: None,
                error: Some(e.to_string()),
                files_uploaded: 0,
                total_size: 0,
            }
        }
    }
}

async fn execute_deploy_inner(
    job: &DeployJob,
    service: &crate::service::ZhtpDaemonService,
    work_dir: &Path,
) -> Result<DeployResult> {
    let repo_dir = work_dir.join(&job.commit_sha);

    // 1. Clone (shallow)
    info!("[deploy] Cloning {} at {}", job.repo_full_name, &job.commit_sha[..8]);
    clone_repo(&job.repo_url, &job.commit_sha, &repo_dir).await?;

    // 2. Read sov.toml
    let sov_toml_path = repo_dir.join("sov.toml");
    if !sov_toml_path.exists() {
        return Err(anyhow!("No sov.toml found in repository root"));
    }
    let sov_content = tokio::fs::read_to_string(&sov_toml_path).await?;
    let config = SovConfig::from_toml(&sov_content)?;
    info!("[deploy] sov.toml: domain={}, mode={}, output={}", config.deploy.domain, config.deploy.mode, config.deploy.output_dir);

    // 3. Build (optional)
    if let Some(ref cmd) = config.deploy.build_command {
        info!("[deploy] Running build: {}", cmd);
        run_build(cmd, &repo_dir).await?;
    }

    // 4. Collect files
    let output_dir = repo_dir.join(&config.deploy.output_dir);
    if !output_dir.exists() {
        return Err(anyhow!("Output directory '{}' not found after build", config.deploy.output_dir));
    }
    let files = collect_files(&output_dir).await?;
    info!("[deploy] Collected {} files ({} bytes)", files.len(), files.iter().map(|f| f.size).sum::<u64>());

    // 5. Upload blobs via QUIC
    let mut uploaded = 0;
    let mut content_ids = Vec::new();
    for file in &files {
        let blob = tokio::fs::read(&file.absolute_path).await?;
        let request = build_blob_upload_request(&blob);
        let response = service.forward_zhtp_request(request, None).await?;
        let body: serde_json::Value = serde_json::from_slice(&response.body)?;
        let cid = body["content_id"].as_str()
            .ok_or_else(|| anyhow!("No content_id in blob response"))?
            .to_string();
        content_ids.push((file.relative_path.clone(), cid));
        uploaded += 1;
    }
    info!("[deploy] Uploaded {} blobs", uploaded);

    // 6. Build + upload manifest
    let manifest = build_manifest(&config.deploy, &content_ids, &files);
    let manifest_json = serde_json::to_vec(&manifest)?;
    let manifest_request = build_manifest_upload_request(&manifest_json);
    let manifest_response = service.forward_zhtp_request(manifest_request, None).await?;
    let manifest_body: serde_json::Value = serde_json::from_slice(&manifest_response.body)?;
    let manifest_cid = manifest_body["manifest_cid"].as_str()
        .unwrap_or("unknown")
        .to_string();
    info!("[deploy] Manifest uploaded: {}", manifest_cid);

    // 7. Register/update domain
    let domain_request = build_domain_register_request(&config.deploy.domain, &manifest_cid);
    let domain_response = service.forward_zhtp_request(domain_request, None).await?;
    info!("[deploy] Domain registered: {} (status {})", config.deploy.domain, domain_response.status.code());

    // 8. Cleanup
    let _ = tokio::fs::remove_dir_all(&repo_dir).await;

    let total_size = files.iter().map(|f| f.size).sum();
    Ok(DeployResult {
        success: true,
        domain: Some(config.deploy.domain),
        error: None,
        files_uploaded: uploaded,
        total_size,
    })
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

struct FileEntry {
    relative_path: String,
    absolute_path: PathBuf,
    size: u64,
    content_type: String,
}

async fn clone_repo(url: &str, commit: &str, dest: &Path) -> Result<()> {
    let output = tokio::process::Command::new("git")
        .args(["clone", "--depth", "1", url, &dest.to_string_lossy()])
        .output()
        .await
        .context("git clone failed")?;

    if !output.status.success() {
        return Err(anyhow!("git clone failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Checkout specific commit (shallow clone may not have it, but try)
    let checkout = tokio::process::Command::new("git")
        .args(["-C", &dest.to_string_lossy(), "checkout", commit])
        .output()
        .await;

    if let Ok(out) = checkout {
        if !out.status.success() {
            warn!("[deploy] Could not checkout exact commit {}, using HEAD", &commit[..8]);
        }
    }

    Ok(())
}

async fn run_build(command: &str, work_dir: &Path) -> Result<()> {
    // Install deps if package.json exists
    let pkg_json = work_dir.join("package.json");
    if pkg_json.exists() {
        info!("[deploy] Installing dependencies...");
        let install = tokio::process::Command::new("npm")
            .args(["install", "--production=false"])
            .current_dir(work_dir)
            .output()
            .await
            .context("npm install failed")?;

        if !install.status.success() {
            return Err(anyhow!("npm install failed: {}", String::from_utf8_lossy(&install.stderr)));
        }
    }

    // Run build command
    let output = tokio::process::Command::new("sh")
        .args(["-c", command])
        .current_dir(work_dir)
        .env("NODE_ENV", "production")
        .output()
        .await
        .context("Build command failed")?;

    if !output.status.success() {
        return Err(anyhow!("Build failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    Ok(())
}

async fn collect_files(dir: &Path) -> Result<Vec<FileEntry>> {
    let mut files = Vec::new();
    collect_files_recursive(dir, dir, &mut files).await?;
    // Sort for deterministic ordering
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(files)
}

#[async_recursion::async_recursion]
async fn collect_files_recursive(base: &Path, current: &Path, files: &mut Vec<FileEntry>) -> Result<()> {
    let mut entries = tokio::fs::read_dir(current).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(base, &path, files).await?;
        } else {
            let relative = path.strip_prefix(base)?.to_string_lossy().to_string();
            let metadata = tokio::fs::metadata(&path).await?;
            let content_type = mime_from_extension(&relative);
            files.push(FileEntry {
                relative_path: relative,
                absolute_path: path,
                size: metadata.len(),
                content_type,
            });
        }
    }
    Ok(())
}

fn mime_from_extension(path: &str) -> String {
    match path.rsplit('.').next() {
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") | Some("mjs") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ico") => "image/x-icon",
        Some("webp") => "image/webp",
        Some("txt") => "text/plain",
        Some("xml") => "application/xml",
        Some("wasm") => "application/wasm",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }.to_string()
}

fn make_request(method: lib_protocols::types::ZhtpMethod, uri: &str, body: Vec<u8>, content_type: Option<&str>) -> lib_protocols::types::ZhtpRequest {
    let mut headers = lib_protocols::types::ZhtpHeaders::new();
    if let Some(ct) = content_type {
        headers.content_type = Some(ct.to_string());
    }
    headers.content_length = Some(body.len() as u64);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    lib_protocols::types::ZhtpRequest {
        method,
        uri: uri.to_string(),
        version: "ZHTP/2.0".to_string(),
        headers,
        body,
        timestamp,
        requester: None,
        auth_proof: None,
    }
}

fn build_blob_upload_request(blob: &[u8]) -> lib_protocols::types::ZhtpRequest {
    make_request(
        lib_protocols::types::ZhtpMethod::Post,
        "/api/v1/web4/content/blob",
        blob.to_vec(),
        Some("application/octet-stream"),
    )
}

fn build_manifest_upload_request(manifest_json: &[u8]) -> lib_protocols::types::ZhtpRequest {
    make_request(
        lib_protocols::types::ZhtpMethod::Post,
        "/api/v1/web4/content/manifest",
        manifest_json.to_vec(),
        Some("application/json"),
    )
}

fn build_domain_register_request(domain: &str, manifest_cid: &str) -> lib_protocols::types::ZhtpRequest {
    let body = serde_json::json!({
        "domain": domain,
        "manifest_cid": manifest_cid,
    });
    make_request(
        lib_protocols::types::ZhtpMethod::Post,
        "/api/v1/web4/domains/register",
        serde_json::to_vec(&body).unwrap_or_default(),
        Some("application/json"),
    )
}

fn build_manifest(
    config: &DeployConfig,
    content_ids: &[(String, String)],
    files: &[FileEntry],
) -> serde_json::Value {
    let file_entries: Vec<serde_json::Value> = content_ids.iter().zip(files.iter()).map(|((path, cid), file)| {
        serde_json::json!({
            "path": path,
            "content_id": cid,
            "content_type": file.content_type,
            "size": file.size,
        })
    }).collect();

    let total_size: u64 = files.iter().map(|f| f.size).sum();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    serde_json::json!({
        "version": 1,
        "domain": config.domain,
        "mode": config.mode,
        "files": file_entries,
        "total_size": total_size,
        "deployed_at": timestamp,
        "author_did": "did:zhtp:github-deploy-worker",
    })
}

// ─── GitHub commit status ──────────────────────────────────────────────────────

/// Set commit status on GitHub (requires GitHub App installation token)
pub async fn set_commit_status(
    repo_full_name: &str,
    commit_sha: &str,
    state: &str,      // "success", "failure", "pending"
    description: &str,
    target_url: Option<&str>,
    github_token: &str,
) -> Result<()> {
    let url = format!(
        "https://api.github.com/repos/{}/statuses/{}",
        repo_full_name, commit_sha
    );

    let mut body = serde_json::json!({
        "state": state,
        "description": description,
        "context": "sovereign-deploy",
    });

    if let Some(url) = target_url {
        body["target_url"] = serde_json::Value::String(url.to_string());
    }

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", github_token))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "sovereign-deploy-worker")
        .json(&body)
        .send()
        .await
        .context("Failed to set GitHub commit status")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        warn!("[deploy] GitHub status API {}: {}", status, text);
    }

    Ok(())
}
