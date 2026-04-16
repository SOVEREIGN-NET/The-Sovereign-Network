use crate::backend_pool::BackendPool;
use crate::config::DaemonConfig;
use anyhow::{anyhow, Context, Result};
use lib_identity::ZhtpIdentity;
use lib_network::web4::{ManifestFile, Web4Manifest};
use lib_protocols::types::ZhtpRequest;
use lib_protocols::ZhtpResponse;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub struct ZhtpDaemonService {
    config: DaemonConfig,
    identity: Arc<ZhtpIdentity>,
    started_at: u64,
    backend_pool: Arc<BackendPool>,
}

impl ZhtpDaemonService {
    pub async fn new(config: DaemonConfig, identity: ZhtpIdentity) -> Result<Self> {
        let trust_config = config.trust_config()?;
        let gateway_cfg = config.effective_gateway_config();
        let identity = Arc::new(identity);
        let backend_pool = Arc::new(
            BackendPool::new(gateway_cfg.clone(), (*identity).clone(), trust_config).await?,
        );

        // Start discovery and wire the PeerRegistry into the backend pool.
        let _registry =
            crate::discovery::start_gateway_discovery(&gateway_cfg, (*identity).clone(), backend_pool.clone())
                .await?;

        Ok(Self {
            config,
            identity,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            backend_pool,
        })
    }

    pub async fn status(&self) -> ServiceStatus {
        ServiceStatus {
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: DAEMON_API_VERSION.to_string(),
            daemon_did: self.identity.did.clone(),
            active_backend: None,
            configured_backends: self.config.static_backends(),
            started_at: self.started_at,
        }
    }

    pub async fn resolve_domain(&self, domain: &str) -> Result<serde_json::Value> {
        let req = ZhtpRequest::get(
            format!("/api/v1/web4/domains/{}?resolve=true", domain),
            Some(self.identity.id.clone()),
        )
        .unwrap_or_else(|_| {
            ZhtpRequest::get("/api/v1/resolve".to_string(), Some(self.identity.id.clone()))
                .expect("valid request")
        });

        let backend = self.backend_pool.pick_backend(&req).await?;
        let start = std::time::Instant::now();

        let result = backend.client.read().await.resolve_domain(domain, None).await;
        match result {
            Ok(value) => {
                self.backend_pool
                    .report_success(&backend.addr, start.elapsed().as_millis() as u64)
                    .await;
                Ok(value)
            }
            Err(e) => {
                self.backend_pool.report_failure(&backend.addr).await;
                Err(anyhow!("Resolve failed on {}: {}", backend.addr, e))
            }
        }
    }

    pub async fn fetch_content(&self, domain: &str, path: &str) -> Result<ZhtpResponse> {
        let normalized_path = normalize_requested_path(path);
        let req = ZhtpRequest::get(
            format!("/web4/content/{}{}", domain, normalized_path),
            Some(self.identity.id.clone()),
        )
        .unwrap_or_else(|_| {
            ZhtpRequest::get("/".to_string(), Some(self.identity.id.clone())).expect("valid request")
        });

        let backend = self.backend_pool.pick_backend(&req).await?;
        let start = std::time::Instant::now();

        match self
            .fetch_content_with_backend(&backend, domain, &normalized_path)
            .await
        {
            Ok(response) => {
                self.backend_pool
                    .report_success(&backend.addr, start.elapsed().as_millis() as u64)
                    .await;
                Ok(response)
            }
            Err(e) => {
                self.backend_pool.report_failure(&backend.addr).await;
                if req.is_idempotent() && self.config.effective_gateway_config().retry_idempotent_requests {
                    if let Ok(retry_backend) = self.backend_pool.pick_backend(&req).await {
                        return self
                            .fetch_content_with_backend(&retry_backend, domain, &normalized_path)
                            .await;
                    }
                }
                Err(e)
            }
        }
    }

    pub async fn list_domains(&self) -> Result<serde_json::Value> {
        let req =
            ZhtpRequest::get("/api/v1/web4/domains/catalog".to_string(), Some(self.identity.id.clone()))
                .unwrap_or_else(|_| {
                    ZhtpRequest::get("/api/v1/dns/domains".to_string(), Some(self.identity.id.clone()))
                        .expect("valid request")
                });

        let backend = self.backend_pool.pick_backend(&req).await?;
        let start = std::time::Instant::now();

        match self.list_domains_with_backend(&backend).await {
            Ok(value) => {
                self.backend_pool
                    .report_success(&backend.addr, start.elapsed().as_millis() as u64)
                    .await;
                Ok(value)
            }
            Err(e) => {
                self.backend_pool.report_failure(&backend.addr).await;
                if req.is_idempotent() && self.config.effective_gateway_config().retry_idempotent_requests {
                    if let Ok(retry_backend) = self.backend_pool.pick_backend(&req).await {
                        return self.list_domains_with_backend(&retry_backend).await;
                    }
                }
                Err(e)
            }
        }
    }

    async fn list_domains_with_backend(&self, backend: &crate::backend_pool::BackendEntry) -> Result<serde_json::Value> {
        for uri in ["/api/v1/web4/domains/catalog", "/api/v1/dns/domains"] {
            let request = ZhtpRequest::get(uri.to_string(), Some(self.identity.id.clone()))?;
            let response = backend.client.read().await.request(request).await?;

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

    async fn fetch_content_with_backend(
        &self,
        backend: &crate::backend_pool::BackendEntry,
        domain: &str,
        path: &str,
    ) -> Result<ZhtpResponse> {
        let resolved = backend
            .client
            .read()
            .await
            .resolve_domain(domain, None)
            .await
            .with_context(|| format!("Failed to resolve domain {}", domain))?;

        let manifest_cid = resolved
            .get("web4_manifest_cid")
            .and_then(Value::as_str)
            .or_else(|| resolved.get("manifest_cid").and_then(Value::as_str))
            .ok_or_else(|| anyhow!("Resolve response missing manifest CID for {}", domain))?;

        let manifest = self
            .fetch_manifest(backend, domain, manifest_cid)
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
            .fetch_blob(backend, domain, &selected_file.cid)
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
        backend: &crate::backend_pool::BackendEntry,
        domain: &str,
        cid: &str,
    ) -> Result<Web4Manifest> {
        let request = json_post_request(
            "/api/v1/web4/content/manifest",
            serde_json::json!({ "cid": cid }),
            Some(domain),
            self.identity.id.clone(),
        )?;
        let response = backend.client.read().await.request(request).await?;
        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to fetch manifest: {} {}",
                response.status.code(),
                response.status_message
            ));
        }
        serde_json::from_slice(&response.body).context("Invalid manifest JSON")
    }

    async fn fetch_blob(
        &self,
        backend: &crate::backend_pool::BackendEntry,
        domain: &str,
        cid: &str,
    ) -> Result<Vec<u8>> {
        let request = json_post_request(
            "/api/v1/web4/content/blob",
            serde_json::json!({ "cid": cid }),
            Some(domain),
            self.identity.id.clone(),
        )?;
        let response = backend.client.read().await.request(request).await?;
        if !response.status.is_success() {
            return Err(anyhow!(
                "Failed to fetch blob: {} {}",
                response.status.code(),
                response.status_message
            ));
        }
        Ok(response.body)
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
