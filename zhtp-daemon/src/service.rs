use crate::config::DaemonConfig;
use anyhow::{anyhow, Context, Result};
use lib_identity::ZhtpIdentity;
use lib_network::web4::client::Web4ClientConfig;
use lib_network::web4::{ManifestFile, Web4Client, Web4Manifest};
use lib_protocols::types::ZhtpRequest;
use lib_protocols::ZhtpResponse;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::warn;

pub const DAEMON_API_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    pub daemon_version: String,
    pub api_version: String,
    pub daemon_did: String,
    pub active_backend: Option<String>,
    pub configured_backends: Vec<String>,
    pub started_at: u64,
}

struct SessionState {
    active_backend: Option<String>,
    client: Option<Arc<Web4Client>>,
}

pub struct ZhtpDaemonService {
    config: DaemonConfig,
    identity: Arc<ZhtpIdentity>,
    started_at: u64,
    session: Mutex<SessionState>,
}

impl ZhtpDaemonService {
    pub fn new(config: DaemonConfig, identity: ZhtpIdentity) -> Self {
        Self {
            config,
            identity: Arc::new(identity),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            session: Mutex::new(SessionState {
                active_backend: None,
                client: None,
            }),
        }
    }

    pub async fn status(&self) -> ServiceStatus {
        let active_backend = self.session.lock().await.active_backend.clone();
        ServiceStatus {
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: DAEMON_API_VERSION.to_string(),
            daemon_did: self.identity.did.clone(),
            active_backend,
            configured_backends: self.config.backend_nodes.clone(),
            started_at: self.started_at,
        }
    }

    pub async fn resolve_domain(&self, domain: &str) -> Result<serde_json::Value> {
        let client = self.connected_client().await?;
        match client.resolve_domain(domain, None).await {
            Ok(value) => Ok(value),
            Err(first_error) => {
                warn!(
                    error = %first_error,
                    "Resolve failed on active backend, reconnecting"
                );
                self.invalidate_client(&client).await;
                self.connected_client()
                    .await
                    .context("Connected client missing after reconnect")?
                    .resolve_domain(domain, None)
                    .await
                    .context("Domain resolve failed after reconnect")
            }
        }
    }

    pub async fn fetch_content(&self, domain: &str, path: &str) -> Result<ZhtpResponse> {
        let client = self.connected_client().await?;
        match self.fetch_content_with_active_client(client.as_ref(), domain, path).await {
            Ok(response) => Ok(response),
            Err(first_error) => {
                warn!(
                    error = %first_error,
                    "Content fetch failed on active backend, reconnecting"
                );
                self.invalidate_client(&client).await;
                self.fetch_content_with_active_client(
                    self.connected_client()
                        .await
                        .context("Connected client missing after reconnect")?
                        .as_ref(),
                    domain,
                    path,
                )
                    .await
                    .context("Content fetch failed after reconnect")
            }
        }
    }

    pub async fn list_domains(&self) -> Result<serde_json::Value> {
        let client = self.connected_client().await?;
        match self.list_domains_with_active_client(client.as_ref()).await {
            Ok(value) => Ok(value),
            Err(first_error) => {
                warn!(
                    error = %first_error,
                    "Domain list failed on active backend, reconnecting"
                );
                self.invalidate_client(&client).await;
                self.list_domains_with_active_client(
                    self.connected_client()
                        .await
                        .context("Connected client missing after reconnect")?
                        .as_ref(),
                )
                    .await
                    .context("Domain list failed after reconnect")
            }
        }
    }

    async fn list_domains_with_active_client(&self, client: &Web4Client) -> Result<serde_json::Value> {
        for uri in ["/api/v1/web4/domains/catalog", "/api/v1/dns/domains"] {
            let request = ZhtpRequest::get(uri.to_string(), Some(self.identity.id.clone()))?;
            let response = client.request(request).await?;

            if response.status.code() == 404 {
                continue;
            }

            if !response.status.is_success() {
                return Err(anyhow!(
                    "Failed to list domains via {}: {} {}",
                    uri,
                    response.status.code(),
                    response.status_message
                ));
            }

            let value: serde_json::Value = serde_json::from_slice(&response.body)
                .with_context(|| format!("Invalid JSON response for {}", uri))?;

            let has_domains = value
                .get("domains")
                .and_then(|domains| domains.as_array())
                .map(|domains| !domains.is_empty())
                .unwrap_or(false);
            if has_domains || uri == "/api/v1/dns/domains" {
                return Ok(value);
            }
        }

        Ok(serde_json::json!({
            "domains": [],
            "total_count": 0,
        }))
    }

    async fn fetch_content_with_active_client(
        &self,
        client: &Web4Client,
        domain: &str,
        path: &str,
    ) -> Result<ZhtpResponse> {
        let resolved = client
            .resolve_domain(domain, None)
            .await
            .with_context(|| format!("Failed to resolve domain {}", domain))?;

        let manifest_cid = resolved
            .get("web4_manifest_cid")
            .and_then(Value::as_str)
            .or_else(|| resolved.get("manifest_cid").and_then(Value::as_str))
            .ok_or_else(|| anyhow!("Resolve response missing manifest CID for {}", domain))?;

        let manifest = self
            .fetch_manifest(client, domain, manifest_cid)
            .await
            .with_context(|| format!("Failed to fetch manifest {} for {}", manifest_cid, domain))?;

        let requested_path = normalize_requested_path(path);
        let (selected_path, selected_file) =
            resolve_manifest_file(&manifest, &requested_path).ok_or_else(|| {
                anyhow!(
                    "No manifest entry matched requested path {} for {}",
                    requested_path,
                    domain
                )
            })?;

        let blob = self
            .fetch_blob(client, domain, &selected_file.cid)
            .await
            .with_context(|| {
                format!(
                    "Failed to fetch blob {} for {} ({})",
                    selected_file.cid, domain, selected_path
                )
            })?;

        let mut response = ZhtpResponse::success_with_content_type(
            blob,
            selected_file.content_type.clone(),
            None,
        );
        response.headers.content_length = Some(selected_file.size);
        response.headers.host = Some(domain.to_string());
        response = response.with_custom_header("X-ZHTP-Resolved-Path".to_string(), selected_path);
        Ok(response)
    }

    async fn fetch_manifest(
        &self,
        client: &Web4Client,
        domain: &str,
        cid: &str,
    ) -> Result<Web4Manifest> {
        let request = json_post_request(
            "/api/v1/web4/content/manifest",
            serde_json::json!({ "cid": cid }),
            Some(domain),
            self.identity.id.clone(),
        )?;
        let response = client.request(request).await?;
        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to fetch manifest: {} {}",
                response.status.code(),
                response.status_message
            ));
        }
        serde_json::from_slice(&response.body).context("Invalid manifest JSON")
    }

    async fn fetch_blob(&self, client: &Web4Client, domain: &str, cid: &str) -> Result<Vec<u8>> {
        let request = json_post_request(
            "/api/v1/web4/content/blob",
            serde_json::json!({ "cid": cid }),
            Some(domain),
            self.identity.id.clone(),
        )?;
        let response = client.request(request).await?;
        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to fetch blob: {} {}",
                response.status.code(),
                response.status_message
            ));
        }
        Ok(response.body)
    }

    async fn connected_client(&self) -> Result<Arc<Web4Client>> {
        if let Some(client) = self.session.lock().await.client.clone() {
            return Ok(client);
        }
        let mut errors = Vec::new();
        for backend in &self.config.backend_nodes {
            match self.connect_backend(backend).await {
                Ok(client) => {
                    let client = Arc::new(client);
                    let mut session = self.session.lock().await;
                    if let Some(existing) = session.client.clone() {
                        return Ok(existing);
                    }
                    session.active_backend = Some(backend.clone());
                    session.client = Some(client.clone());
                    return Ok(client);
                }
                Err(error) => {
                    errors.push(format!("{}: {}", backend, error));
                }
            }
        }

        Err(anyhow!(
            "Unable to connect to any configured backend node: {}",
            errors.join(" | ")
        ))
    }

    async fn invalidate_client(&self, client: &Arc<Web4Client>) {
        let mut session = self.session.lock().await;
        if session
            .client
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, client))
        {
            session.client = None;
            session.active_backend = None;
        }
    }

    async fn connect_backend(&self, backend: &str) -> Result<Web4Client> {
        let trust_config = self.config.trust_config()?;
        let client_config = Web4ClientConfig {
            allow_bootstrap: trust_config.bootstrap_mode,
            cache_dir: Some(crate::config::DaemonConfig::root_dir()?.join("client-cache")),
            session_id: Some("zhtp-daemon".to_string()),
        };

        let mut client = if trust_config.bootstrap_mode {
            Web4Client::new_bootstrap_with_config((*self.identity).clone(), client_config)
                .await
                .context("Failed to construct bootstrap Web4 client")?
        } else {
            Web4Client::new_with_trust_and_config(
                (*self.identity).clone(),
                trust_config,
                client_config,
            )
            .await
            .context("Failed to construct Web4 client")?
        };

        client
            .connect(backend)
            .await
            .with_context(|| format!("Failed to connect to backend {}", backend))?;
        Ok(client)
    }
}

fn json_post_request(
    uri: &str,
    body: serde_json::Value,
    host: Option<&str>,
    requester: lib_identity::IdentityId,
) -> Result<ZhtpRequest> {
    let bytes = serde_json::to_vec(&body)?;
    let mut request = ZhtpRequest::post(
        uri.to_string(),
        bytes,
        "application/json".to_string(),
        Some(requester),
    )?;
    if let Some(host) = host {
        request.headers.host = Some(host.to_string());
    }
    Ok(request)
}

fn normalize_requested_path(path: &str) -> String {
    let trimmed = path.trim();
    let trimmed = trimmed
        .split_once('#')
        .map(|(value, _)| value)
        .unwrap_or(trimmed);
    let trimmed = trimmed
        .split_once('?')
        .map(|(value, _)| value)
        .unwrap_or(trimmed);
    if trimmed.is_empty() || trimmed == "/" {
        "/index.html".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

fn resolve_manifest_file<'a>(
    manifest: &'a Web4Manifest,
    requested_path: &str,
) -> Option<(String, &'a ManifestFile)> {
    for candidate in candidate_manifest_paths(requested_path) {
        if let Some(file) = manifest.files.get(&candidate) {
            return Some((candidate, file));
        }
    }

    None
}

fn candidate_manifest_paths(requested_path: &str) -> Vec<String> {
    let normalized = requested_path.trim();
    let normalized = normalized.trim_start_matches('/');
    let normalized = normalized.trim_end_matches('/');
    let route_stem = normalized.strip_suffix(".txt").unwrap_or(normalized);

    let mut candidates = Vec::new();

    for candidate in [
        format!("/{}", normalized),
        normalized.to_string(),
        format!("/{}/index.html", normalized),
        format!("{}/index.html", normalized),
        format!("/{}.html", normalized),
        format!("{}.html", normalized),
        format!("/{}", route_stem),
        route_stem.to_string(),
        format!("/{}/index.html", route_stem),
        format!("{}/index.html", route_stem),
        format!("/{}.html", route_stem),
        format!("{}.html", route_stem),
        "/index.html".to_string(),
        "index.html".to_string(),
    ] {
        if !candidate.is_empty() && !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::{candidate_manifest_paths, normalize_requested_path, resolve_manifest_file};
    use lib_network::web4::{ManifestFile, Web4Manifest};
    use std::collections::BTreeMap;

    fn manifest_with(paths: &[&str]) -> Web4Manifest {
        let files = paths
            .iter()
            .map(|path| {
                (
                    (*path).to_string(),
                    ManifestFile {
                        cid: format!("cid-{path}"),
                        size: 1,
                        content_type: "text/html".to_string(),
                        hash: format!("hash-{path}"),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        Web4Manifest {
            domain: "example.sov".to_string(),
            version: 1,
            previous_manifest: None,
            build_hash: "build-hash".to_string(),
            files,
            created_at: 0,
            created_by: "did:zhtp:test".to_string(),
            message: None,
        }
    }

    #[test]
    fn normalize_requested_path_strips_query_and_fragment() {
        assert_eq!(normalize_requested_path("/select-dao.txt?_rsc=abc#frag"), "/select-dao.txt");
        assert_eq!(normalize_requested_path("feed?page=1"), "/feed");
        assert_eq!(normalize_requested_path("/"), "/index.html");
    }

    #[test]
    fn candidate_manifest_paths_include_html_and_index_variants() {
        let candidates = candidate_manifest_paths("/select-dao.txt");
        assert!(candidates.contains(&"/select-dao.txt".to_string()));
        assert!(candidates.contains(&"/select-dao.html".to_string()));
        assert!(candidates.contains(&"select-dao.html".to_string()));
        assert!(candidates.contains(&"/select-dao/index.html".to_string()));
        assert!(candidates.contains(&"/index.html".to_string()));
    }

    #[test]
    fn resolve_manifest_file_prefers_route_specific_file_before_index_fallback() {
        let manifest = manifest_with(&["select-dao.html", "index.html"]);
        let (path, _) = resolve_manifest_file(&manifest, "/select-dao").expect("route should resolve");
        assert_eq!(path, "select-dao.html");
    }

    #[test]
    fn resolve_manifest_file_supports_rsc_text_payloads() {
        let manifest = manifest_with(&["select-dao.txt", "index.html"]);
        let (path, _) =
            resolve_manifest_file(&manifest, "/select-dao.txt").expect("rsc payload should resolve");
        assert_eq!(path, "select-dao.txt");
    }
}
