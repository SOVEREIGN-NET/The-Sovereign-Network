//! Local Web4 stubs to keep zhtp compiling while lib-network is protocol-only.
//! These provide no real functionality; they return placeholder data.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use lib_crypto::KeyPair;
use lib_proofs::ZeroKnowledgeProof;
use lib_identity::ZhtpIdentity;
use lib_storage::dht::transport::{DhtTransport, PeerId};

// ----------------------------- Trust -----------------------------
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustConfig {
    pub allow_tofu: bool,
    pub bootstrap_mode: bool,
    pub pin_spki: Option<String>,
    pub audit_log_path: Option<String>,
    pub trustdb_path: Option<String>,
    pub node_did: Option<String>,
}

impl TrustConfig {
    pub fn default_trustdb_path() -> Result<String> {
        Ok("trustdb.json".to_string())
    }

    pub fn default_audit_path() -> String {
        "trust_audit.log".to_string()
    }

    pub fn bootstrap() -> Self {
        Self {
            allow_tofu: false,
            bootstrap_mode: true,
            pin_spki: None,
            audit_log_path: None,
            trustdb_path: None,
            node_did: None,
        }
    }

    pub fn with_pin(pin: String) -> Self {
        Self {
            allow_tofu: false,
            bootstrap_mode: false,
            pin_spki: Some(pin),
            audit_log_path: None,
            trustdb_path: None,
            node_did: None,
        }
    }

    pub fn with_tofu(path: String) -> Self {
        Self {
            allow_tofu: true,
            bootstrap_mode: false,
            pin_spki: None,
            audit_log_path: None,
            trustdb_path: Some(path),
            node_did: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAuditEntry {
    pub timestamp: u64,
    pub node_addr: String,
    pub node_did: Option<String>,
    pub spki_sha256: String,
    pub tool_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustAnchor {
    pub node_did: Option<String>,
    pub spki_sha256: String,
    pub policy: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustDb {
    pub anchors: HashMap<String, TrustAnchor>,
}

impl TrustDb {
    pub fn load_or_create(_path: &Path) -> Result<Self> {
        Ok(Self::default())
    }

    pub fn remove(&mut self, key: &str) -> Option<TrustAnchor> {
        self.anchors.remove(key)
    }

    pub fn save(&self, _path: &Path) -> Result<()> {
        Ok(())
    }
}

// ----------------------------- Web4 domain/content -----------------------------
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainMetadata {
    pub title: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub public: bool,
    pub economic_settings: DomainEconomicSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainEconomicSettings {
    pub registration_fee: f64,
    pub renewal_fee: f64,
    pub transfer_fee: f64,
    pub hosting_budget: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRegistrationRequest {
    pub domain: String,
    pub owner: ZhtpIdentity,
    pub duration_days: u64,
    pub metadata: DomainMetadata,
    pub initial_content: HashMap<String, Vec<u8>>,
    pub registration_proof: ZeroKnowledgeProof,
    pub manifest_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainRegistrationResponse {
    pub domain: String,
    pub success: bool,
    pub registration_id: String,
    pub expires_at: u64,
    pub fees_charged: f64,
    pub new_manifest_cid: Option<String>,
    pub new_version: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainUpdateRequest {
    pub domain: String,
    pub new_manifest_cid: String,
    pub expected_previous_manifest_cid: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContentMetadata {
    pub title: String,
    pub description: String,
    pub version: String,
    pub tags: Vec<String>,
    pub public: bool,
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPublishRequest {
    pub domain: String,
    pub path: String,
    pub content: Vec<u8>,
    pub content_type: String,
    pub publisher: ZhtpIdentity,
    pub ownership_proof: Option<Vec<u8>>,
    pub metadata: Option<ContentMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContentPublishResponse {
    pub success: bool,
    pub content_cid: String,
    pub manifest_cid: String,
    pub content_hash: Option<String>,
    pub zhtp_url: Option<String>,
    pub published_at: Option<u64>,
    pub storage_fees: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainLookupResponse {
    pub found: bool,
    pub content_mappings: HashMap<String, String>,
    pub record: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainHistoryEntry {
    pub version: u64,
    pub manifest_cid: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainHistoryResponse {
    pub versions: Vec<DomainHistoryEntry>,
    pub history: Vec<DomainHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainStatusResponse {
    pub found: bool,
    pub status: String,
    pub owner_did: Option<String>,
    pub updated_at: Option<u64>,
    pub current_manifest_cid: Option<String>,
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Web4Statistics;

#[derive(Debug, Clone, Default)]
pub struct ZhtpRelayProtocol;

impl ZhtpRelayProtocol {
    pub fn new<T1, T2, T3>(_privkey: T1, _pubkey: T2, _caps: T3) -> Self {
        Self
    }
}

#[derive(Debug, Clone, Default)]
pub struct ZdnsTransportServer;

#[derive(Debug, Clone, Default)]
pub struct ZdnsServerConfig;

impl ZdnsServerConfig {
    pub fn production(_gateway_ip: std::net::Ipv4Addr) -> Self {
        Self
    }

    pub fn with_bind_addr(self, _addr: std::net::IpAddr) -> Self {
        self
    }
}

impl ZdnsTransportServer {
    pub fn new(_resolver: Arc<ZdnsResolver>, _config: ZdnsServerConfig) -> Self {
        Self
    }

    pub async fn start(&self) -> Result<()> {
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct StubManifestFile {
    pub path: String,
    pub cid: String,
    pub size: u64,
    pub mime: String,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct StubManifest {
    pub domain: String,
    pub version: u64,
    pub previous_manifest: Option<String>,
    pub build_hash: String,
    pub files: Vec<StubManifestFile>,
}

impl StubManifest {
    pub fn compute_cid(&self) -> String {
        self.build_hash.clone()
    }
}

#[derive(Debug, Clone)]
pub struct DomainRegistry {
    pub domain_records: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    pub content_store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    pub history: Arc<RwLock<HashMap<String, Vec<DomainHistoryEntry>>>>,
}

impl DomainRegistry {
    pub async fn new_with_storage(
        _storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>,
    ) -> Result<Self> {
        Ok(Self {
            domain_records: Arc::new(RwLock::new(HashMap::new())),
            content_store: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn register_domain(
        &self,
        request: DomainRegistrationRequest,
    ) -> Result<DomainRegistrationResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let record = serde_json::json!({
            "domain": request.domain,
            "owner": request.owner.did,
            "registered_at": now,
            "expires_at": now + (request.duration_days * 24 * 60 * 60),
            "current_manifest_cid": request.manifest_cid,
            "version": 1u64,
        });

        let mut records = self.domain_records.write().await;
        records.insert(record["domain"].as_str().unwrap_or_default().to_string(), record.clone());

        let mut history = self.history.write().await;
        history.insert(
            record["domain"].as_str().unwrap_or_default().to_string(),
            vec![DomainHistoryEntry {
                version: 1,
                manifest_cid: record["current_manifest_cid"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                created_at: now,
            }],
        );

        Ok(DomainRegistrationResponse {
            domain: record["domain"].as_str().unwrap_or_default().to_string(),
            success: true,
            registration_id: "stub".to_string(),
            expires_at: 0,
            fees_charged: 0.0,
            new_manifest_cid: record["current_manifest_cid"]
                .as_str()
                .map(|cid| cid.to_string()),
            new_version: Some(1),
            error: None,
        })
    }

    pub async fn register_domain_with_content(
        &self,
        domain: String,
        owner: ZhtpIdentity,
        _content: HashMap<String, Vec<u8>>,
        _metadata: DomainMetadata,
    ) -> Result<DomainRegistrationResponse> {
        let req = DomainRegistrationRequest {
            domain,
            owner,
            duration_days: 0,
            metadata: DomainMetadata::default(),
            initial_content: HashMap::new(),
            registration_proof: ZeroKnowledgeProof::default(),
            manifest_cid: None,
        };
        self.register_domain(req).await
    }

    pub async fn lookup_domain(&self, _domain: &str) -> Result<DomainLookupResponse> {
        let records = self.domain_records.read().await;
        if let Some(record) = records.get(_domain) {
            return Ok(DomainLookupResponse {
                found: true,
                content_mappings: HashMap::new(),
                record: Some(record.clone()),
            });
        }

        Ok(DomainLookupResponse {
            found: false,
            content_mappings: HashMap::new(),
            record: None,
        })
    }

    pub async fn get_domain_status(&self, _domain: &str) -> Result<DomainStatusResponse> {
        let records = self.domain_records.read().await;
        if let Some(record) = records.get(_domain) {
            return Ok(DomainStatusResponse {
                found: true,
                status: "active".to_string(),
                owner_did: record.get("owner").and_then(|v| v.as_str()).map(|s| s.to_string()),
                updated_at: record.get("updated_at").and_then(|v| v.as_u64()),
                current_manifest_cid: record
                    .get("current_manifest_cid")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                version: record.get("version").and_then(|v| v.as_u64()),
            });
        }

        Ok(DomainStatusResponse {
            found: false,
            status: "stub".to_string(),
            owner_did: None,
            updated_at: Some(0),
            current_manifest_cid: None,
            version: Some(0),
        })
    }

    pub async fn get_domain_history(
        &self,
        _domain: &str,
        _limit: usize,
    ) -> Result<DomainHistoryResponse> {
        let history = self.history.read().await;
        let versions = history
            .get(_domain)
            .cloned()
            .unwrap_or_default();

        let limited = if _limit == 0 || versions.len() <= _limit {
            versions.clone()
        } else {
            versions[versions.len() - _limit..].to_vec()
        };

        Ok(DomainHistoryResponse {
            versions: limited.clone(),
            history: limited,
        })
    }

    pub async fn list_domains_by_owner(&self, owner: &str) -> Result<Vec<String>> {
        let records = self.domain_records.read().await;
        let mut domains = Vec::new();
        for (domain, record) in records.iter() {
            let record_owner = record.get("owner").and_then(|v| v.as_str());
            if record_owner == Some(owner) {
                domains.push(domain.clone());
            }
        }
        domains.sort();
        Ok(domains)
    }

    pub async fn update_domain(&self, _req: DomainUpdateRequest) -> Result<DomainRegistrationResponse> {
        let mut records = self.domain_records.write().await;
        if let Some(record) = records.get_mut(&_req.domain) {
            let current_cid = record
                .get("current_manifest_cid")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if current_cid != _req.expected_previous_manifest_cid {
                return Ok(DomainRegistrationResponse {
                    domain: _req.domain.clone(),
                    success: false,
                    registration_id: "update".to_string(),
                    expires_at: 0,
                    fees_charged: 0.0,
                    new_manifest_cid: None,
                    new_version: None,
                    error: Some("Previous manifest CID does not match".to_string()),
                });
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let new_version = record.get("version").and_then(|v| v.as_u64()).unwrap_or(0) + 1;

            record["current_manifest_cid"] = serde_json::Value::String(_req.new_manifest_cid.clone());
            record["version"] = serde_json::Value::Number(new_version.into());
            record["updated_at"] = serde_json::Value::Number(now.into());

            let mut history = self.history.write().await;
            history
                .entry(_req.domain.clone())
                .or_default()
                .push(DomainHistoryEntry {
                    version: new_version,
                    manifest_cid: _req.new_manifest_cid.clone(),
                    created_at: now,
                });

            return Ok(DomainRegistrationResponse {
                domain: _req.domain.clone(),
                success: true,
                registration_id: "update".to_string(),
                expires_at: 0,
                fees_charged: 0.0,
                new_manifest_cid: Some(_req.new_manifest_cid.clone()),
                new_version: Some(new_version),
                error: None,
            });
        }

        Ok(DomainRegistrationResponse {
            domain: _req.domain.clone(),
            success: false,
            registration_id: "update".to_string(),
            expires_at: 0,
            fees_charged: 0.0,
            new_manifest_cid: None,
            new_version: None,
            error: Some("Domain not found".to_string()),
        })
    }

    pub async fn transfer_domain(
        &self,
        _domain: &str,
        _from_owner: &str,
        _new_owner: &str,
        _proof: Option<Vec<u8>>,
    ) -> Result<bool> {
        let mut records = self.domain_records.write().await;
        if let Some(record) = records.get_mut(_domain) {
            let record_owner = record.get("owner").and_then(|v| v.as_str());
            if record_owner != Some(_from_owner) {
                return Ok(false);
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            record["owner"] = serde_json::Value::String(_new_owner.to_string());
            record["updated_at"] = serde_json::Value::Number(now.into());
            return Ok(true);
        }
        Ok(false)
    }

    pub async fn release_domain(&self, _domain: &str, _owner: &str) -> Result<bool> {
        let mut records = self.domain_records.write().await;
        if let Some(record) = records.get(_domain) {
            let record_owner = record.get("owner").and_then(|v| v.as_str());
            if record_owner != Some(_owner) {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
        records.remove(_domain);
        let mut history = self.history.write().await;
        history.remove(_domain);
        Ok(true)
    }

    pub async fn get_manifest(&self, domain: &str, cid: &str) -> Result<Option<StubManifest>> {
        Ok(Some(StubManifest {
            domain: domain.to_string(),
            version: 1,
            previous_manifest: None,
            build_hash: cid.to_string(),
            files: Vec::new(),
        }))
    }

    pub async fn rollback_domain(&self, domain: &str, version: u64, _owner: &str) -> Result<DomainRegistrationResponse> {
        let history = self.history.read().await;
        let manifest_cid = history
            .get(domain)
            .and_then(|entries| entries.iter().find(|e| e.version == version))
            .map(|entry| entry.manifest_cid.clone());
        drop(history);

        if let Some(cid) = manifest_cid {
            let mut records = self.domain_records.write().await;
            if let Some(record) = records.get_mut(domain) {
                record["current_manifest_cid"] = serde_json::Value::String(cid.clone());
                record["version"] = serde_json::Value::Number(version.into());
            }
            return Ok(DomainRegistrationResponse {
                domain: domain.to_string(),
                success: true,
                registration_id: "rollback".to_string(),
                expires_at: 0,
                fees_charged: 0.0,
                new_manifest_cid: Some(cid),
                new_version: Some(version),
                error: None,
            });
        }

        Ok(DomainRegistrationResponse {
            domain: domain.to_string(),
            success: false,
            registration_id: "rollback".to_string(),
            expires_at: 0,
            fees_charged: 0.0,
            new_manifest_cid: None,
            new_version: None,
            error: Some("Requested version not found".to_string()),
        })
    }

    pub async fn store_content_by_cid(&self, _content: Vec<u8>) -> Result<String> {
        let cid = hex::encode(lib_crypto::hash_blake3(&_content));
        let mut store = self.content_store.write().await;
        store.insert(cid.clone(), _content);
        Ok(cid)
    }

    pub async fn get_content_by_cid(&self, _cid: &str) -> Result<Option<Vec<u8>>> {
        let store = self.content_store.read().await;
        Ok(store.get(_cid).cloned())
    }

    pub async fn get_statistics(&self) -> Result<Web4Statistics> {
        Ok(Web4Statistics)
    }
}

#[derive(Debug, Clone)]
pub struct Web4Manager {
    pub registry: Arc<DomainRegistry>,
}

impl Web4Manager {
    pub async fn new_with_registry(
        registry: Arc<DomainRegistry>,
        _storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>,
    ) -> Result<Self> {
        Ok(Self { registry })
    }
}

pub async fn initialize_web4_system_with_storage(
    storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>,
) -> Result<Web4Manager> {
    let registry = Arc::new(DomainRegistry::new_with_storage(storage.clone()).await?);
    Web4Manager::new_with_registry(registry, storage).await
}

#[derive(Debug, Clone)]
pub struct ZdnsResolver;

impl ZdnsResolver {
    pub fn new() -> Self { Self }

    pub fn is_valid_domain(domain: &str) -> bool {
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }
        if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
            return false;
        }
        if domain.chars().any(|c| c.is_ascii_uppercase()) {
            return false;
        }

        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return false;
        }
        let tld = parts.last().unwrap_or(&"");
        if *tld != "zhtp" && *tld != "sov" {
            return false;
        }

        for label in &parts[..parts.len() - 1] {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
            if !label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Default)]
pub struct ZdnsConfig;

#[derive(Debug, Clone, Default)]
pub struct ContentResult {
    pub content: Vec<u8>,
    pub content_type: String,
    pub mime_type: String,
    pub cache_control: String,
    pub etag: Option<String>,
    pub headers: std::collections::HashMap<String, String>,
    pub is_fallback: bool,
}

#[derive(Debug, Clone)]
pub struct Web4ContentService {
    registry: Arc<DomainRegistry>,
    _zdns: Option<ZdnsResolver>,
}

impl Web4ContentService {
    pub fn new(registry: Arc<DomainRegistry>) -> Self {
        Self { registry, _zdns: None }
    }

    pub fn with_zdns(registry: Arc<DomainRegistry>, zdns_resolver: Arc<ZdnsResolver>) -> Self {
        Self {
            registry,
            _zdns: Some((*zdns_resolver).clone()),
        }
    }

    pub async fn get_content(&self, _host: &str, _path: &str) -> Result<ContentResult> {
        Ok(ContentResult {
            content: Vec::new(),
            content_type: "application/octet-stream".to_string(),
            mime_type: "application/octet-stream".to_string(),
            cache_control: "no-cache".to_string(),
            etag: None,
            headers: std::collections::HashMap::new(),
            is_fallback: false,
        })
    }

    pub async fn serve(&self, host: &str, path: &str) -> Result<ContentResult> {
        self.get_content(host, path).await
    }
}

#[derive(Debug, Clone, Default)]
pub struct Web4Capability;

// ----------------------------- Client stub -----------------------------
#[derive(Debug, Clone)]
pub struct Web4Client {
    trust: TrustConfig,
    peer: Option<String>,
}

impl Web4Client {
    pub async fn new_with_trust(_identity: ZhtpIdentity, trust: TrustConfig) -> Result<Self> {
        Ok(Self {
            trust,
            peer: None,
        })
    }

    pub async fn connect(&mut self, _server: &str) -> Result<()> {
        self.peer = Some("peer".to_string());
        Ok(())
    }

    pub fn peer_did(&self) -> Option<String> {
        self.peer.clone()
    }

    pub async fn put_manifest(&mut self, _manifest: &serde_json::Value) -> Result<String> {
        Ok("manifest-cid-stub".to_string())
    }

    pub async fn put_blob(&mut self, _content: Vec<u8>, _mime: String) -> Result<String> {
        Ok("cid-blob".to_string())
    }

    pub async fn put_blob_chunked(
        &mut self,
        _content: Vec<u8>,
        _mime: String,
        _chunk: Option<usize>,
    ) -> Result<String> {
        Ok("cid-blob-chunked".to_string())
    }

    pub async fn get_domain(&mut self, _domain: &str) -> Result<Option<serde_json::Value>> {
        Ok(Some(serde_json::json!({})))
    }

    pub async fn get_domain_status(&mut self, _domain: &str) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "found": false,
            "version": 0,
            "current_manifest_cid": null,
            "owner_did": null
        }))
    }

    pub async fn get_domain_history(
        &mut self,
        _domain: &str,
        _limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "current_version": 0,
            "versions": []
        }))
    }

    pub async fn list_domains(&mut self) -> Result<Vec<serde_json::Value>> {
        Ok(Vec::new())
    }

    pub async fn register_domain(&mut self, domain: &str, manifest_cid: &str) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "domain": domain,
            "new_version": 1,
            "new_manifest_cid": manifest_cid,
            "previous_manifest_cid": null
        }))
    }

    pub async fn update_domain(&mut self, domain: &str, manifest_cid: &str, previous_cid: &str) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "domain": domain,
            "new_version": 2,
            "new_manifest_cid": manifest_cid,
            "previous_manifest_cid": previous_cid
        }))
    }

    pub async fn rollback_domain(&mut self, domain: &str, to_version: u64) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "domain": domain,
            "rolled_back_to": to_version
        }))
    }

    pub async fn close(&mut self) {}
}

#[derive(Debug, Clone)]
pub struct ZhtpClient {
    inner: Web4Client,
}

#[derive(Debug, Clone)]
pub struct ClientResponseStatus {
    code: u16,
}

impl ClientResponseStatus {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    pub fn code(&self) -> u16 {
        self.code
    }
}

#[derive(Debug, Clone)]
pub struct ZhtpClientResponse {
    pub status: ClientResponseStatus,
    pub body: Vec<u8>,
    pub status_message: String,
}

impl ZhtpClient {
    pub async fn new(identity: ZhtpIdentity, trust: TrustConfig) -> Result<Self> {
        let inner = Web4Client::new_with_trust(identity, trust).await?;
        Ok(Self { inner })
    }

    pub async fn connect(&mut self, server: &str) -> Result<()> {
        self.inner.connect(server).await
    }

    pub fn peer_did(&self) -> Option<String> {
        self.inner.peer_did()
    }

    pub async fn post_json<T: Serialize + ?Sized>(&mut self, _path: &str, _body: &T) -> Result<ZhtpClientResponse> {
        let body = serde_json::to_vec(&serde_json::json!({
            "verified": true,
            "verification_score": 1.0,
            "verification_level": "stub"
        }))?;
        Ok(ZhtpClientResponse {
            status: ClientResponseStatus { code: 200 },
            body,
            status_message: "OK".to_string(),
        })
    }

    pub async fn get(&mut self, _path: &str) -> Result<ZhtpClientResponse> {
        let body = serde_json::to_vec(&serde_json::json!({
            "block": "stub"
        }))?;
        Ok(ZhtpClientResponse {
            status: ClientResponseStatus { code: 200 },
            body,
            status_message: "OK".to_string(),
        })
    }

    pub async fn close(&mut self) {
        let _ = self.inner.close().await;
    }
}

// ----------------------------- Mesh DHT transport stub -----------------------------
pub struct MeshDhtTransport {
    receiver: Arc<RwLock<mpsc::UnboundedReceiver<(Vec<u8>, PeerId)>>>,
}

impl MeshDhtTransport {
    pub fn new(
        _router: Arc<RwLock<lib_network::routing::message_routing::MeshMessageRouter>>,
        _keypair: Arc<KeyPair>,
    ) -> (Self, mpsc::UnboundedSender<(Vec<u8>, PeerId)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                receiver: Arc::new(RwLock::new(rx)),
            },
            tx,
        )
    }
}

#[async_trait::async_trait]
impl DhtTransport for MeshDhtTransport {
    async fn send(&self, _data: &[u8], _peer: &PeerId) -> Result<()> {
        Ok(())
    }

    async fn receive(&self) -> Result<(Vec<u8>, PeerId)> {
        let mut rx = self.receiver.write().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("mesh dht receiver closed"))
    }

    fn local_peer_id(&self) -> PeerId {
        PeerId::Mesh(vec![])
    }

    async fn can_reach(&self, _peer: &PeerId) -> bool {
        true
    }

    fn mtu(&self) -> usize {
        1200
    }

    fn typical_latency_ms(&self) -> u32 {
        10
    }
}
