use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::SystemTime,
};
use tokio::sync::{mpsc, Mutex, RwLock};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};

use crate::{
    storage::{ContentId, ContentMetadata},
    zhtp::{Keypair, ZhtpNode},
    audit::{AuditTrail, AuditEventType},
};

/// Browser request type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BrowserRequest {
    /// Get content by ID
    GetContent(ContentId),
    /// Search content by query
    Search(String),
    /// Connect to ZHTP node
    Connect(SocketAddr),
    /// Deploy contract
    DeployContract(Vec<u8>, String),
    /// Call contract method
    CallContract(String, String, Vec<Vec<u8>>),
    /// Create anonymous identity
    CreateIdentity,
    /// Create personhood proof
    CreatePersonhoodProof(Vec<u8>), // biometric data
    /// Register domain in ZHTP DNS
    RegisterDomain(String, Vec<SocketAddr>),
    /// Submit DAO proposal
    SubmitProposal(String, String), // title, description
    /// Vote on DAO proposal
    VoteOnProposal(String, bool), // proposal_id, vote
    /// Deploy DApp
    DeployDApp(String, Vec<u8>), // name, code
}

/// Browser security configuration
#[derive(Debug, Clone)]
pub struct BrowserSecurityConfig {
    pub enable_csp: bool,
    pub allowed_origins: Vec<String>,
    pub enable_sri: bool,
    pub secure_cookies: bool,
    pub enable_csrf_protection: bool,
    pub session_timeout_minutes: u64,
}

impl Default for BrowserSecurityConfig {
    fn default() -> Self {
        Self {
            enable_csp: true,
            allowed_origins: vec!["self".to_string()],
            enable_sri: true,
            secure_cookies: true,
            enable_csrf_protection: true,
            session_timeout_minutes: 30,
        }
    }
}

/// Content Security Policy manager
#[derive(Debug)]
pub struct CspManager {
    config: BrowserSecurityConfig,
    nonces: Arc<RwLock<HashMap<String, SystemTime>>>,
    audit_trail: Option<Arc<AuditTrail>>,
}

impl CspManager {
    pub fn new(config: BrowserSecurityConfig, audit_trail: Option<Arc<AuditTrail>>) -> Self {
        Self {
            config,
            nonces: Arc::new(RwLock::new(HashMap::new())),
            audit_trail,
        }
    }

    /// Generate a new nonce for scripts/styles
    pub async fn generate_nonce(&self) -> String {
        let nonce = Uuid::new_v4().to_string();
        let mut nonces = self.nonces.write().await;
        nonces.insert(nonce.clone(), SystemTime::now());
        
        // Log nonce generation
        if let Some(audit) = &self.audit_trail {
            let _ = audit.log_system_event(
                AuditEventType::SystemOperation,
                format!("CSP nonce generated: {}", &nonce[..8]),
                None,
            ).await;
        }
        
        nonce
    }

    /// Validate nonce
    pub async fn validate_nonce(&self, nonce: &str) -> bool {
        let nonces = self.nonces.read().await;
        if let Some(created_at) = nonces.get(nonce) {
            // Nonces expire after 1 hour
            SystemTime::now().duration_since(*created_at).unwrap().as_secs() < 3600
        } else {
            false
        }
    }

    /// Generate Content Security Policy header
    pub async fn generate_csp_header(&self, script_nonce: &str, style_nonce: &str) -> String {
        if !self.config.enable_csp {
            return String::new();
        }

        let mut directives = vec![
            "default-src 'self'".to_string(),
            format!("script-src 'self' 'nonce-{}'", script_nonce),
            format!("style-src 'self' 'nonce-{}' 'unsafe-inline'", style_nonce), // Allow inline for CSS variables
            "img-src 'self' data: blob:".to_string(),
            "font-src 'self'".to_string(),
            "connect-src 'self' wss: ws:".to_string(), // Allow WebSocket connections
            "media-src 'none'".to_string(),
            "object-src 'none'".to_string(),
            "child-src 'none'".to_string(),
            "worker-src 'self'".to_string(),
            "frame-ancestors 'none'".to_string(),
            "form-action 'self'".to_string(),
            "upgrade-insecure-requests".to_string(),
        ];

        // Add report-uri if audit trail is available
        if self.audit_trail.is_some() {
            directives.push("report-uri /api/security/csp-report".to_string());
        }

        directives.join("; ")
    }

    /// Generate subresource integrity hash
    pub fn generate_sri_hash(&self, content: &str) -> String {
        if !self.config.enable_sri {
            return String::new();
        }

        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = hasher.finalize();
        format!("sha256-{}", general_purpose::STANDARD.encode(hash))
    }

    /// Clean expired nonces
    pub async fn cleanup_expired_nonces(&self) {
        let mut nonces = self.nonces.write().await;
        let now = SystemTime::now();
        nonces.retain(|_, created_at| {
            now.duration_since(*created_at).unwrap().as_secs() < 3600
        });
    }
}

/// CSRF token manager
#[derive(Debug)]
pub struct CsrfManager {
    tokens: Arc<RwLock<HashMap<String, (String, SystemTime)>>>, // session_id -> (token, created_at)
    timeout_minutes: u64,
}

impl CsrfManager {
    pub fn new(timeout_minutes: u64) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            timeout_minutes,
        }
    }

    /// Generate CSRF token for session
    pub async fn generate_token(&self, session_id: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let mut tokens = self.tokens.write().await;
        tokens.insert(session_id.to_string(), (token.clone(), SystemTime::now()));
        token
    }

    /// Validate CSRF token
    pub async fn validate_token(&self, session_id: &str, token: &str) -> bool {
        let tokens = self.tokens.read().await;
        if let Some((stored_token, created_at)) = tokens.get(session_id) {
            if stored_token == token {
                // Check if token is not expired
                let elapsed = SystemTime::now().duration_since(*created_at).unwrap().as_secs();
                elapsed < (self.timeout_minutes * 60)
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Clean expired tokens
    pub async fn cleanup_expired_tokens(&self) {
        let mut tokens = self.tokens.write().await;
        let now = SystemTime::now();
        let timeout_secs = self.timeout_minutes * 60;
        
        tokens.retain(|_, (_, created_at)| {
            now.duration_since(*created_at).unwrap().as_secs() < timeout_secs
        });
    }
}
pub enum BrowserResponse {
    /// Content data
    Content(Vec<u8>, ContentMetadata),
    /// Search results
    SearchResults(Vec<(ContentId, ContentMetadata)>),
    /// Connection status
    ConnectionStatus(bool),
    /// Contract response
    ContractResponse(Vec<u8>),
    /// Identity created
    IdentityCreated(String), // commitment
    /// Personhood proof created
    PersonhoodProofCreated(String), // proof_id
    /// Domain registered
    DomainRegistered(String), // domain
    /// Proposal submitted
    ProposalSubmitted(String), // proposal_id
    /// Vote recorded
    VoteRecorded(String), // vote_id
    /// DApp deployed
    DAppDeployed(String), // deployment_hash
    /// Error message
    Error(String),
}

/// ZHTP Browser interface with security features
pub struct ZhtpBrowser {
    /// Request channel
    request_tx: mpsc::Sender<BrowserRequest>,
    /// Response channel
    response_rx: mpsc::Receiver<BrowserResponse>,
    /// Storage manager reference
    storage: Option<Arc<crate::storage::ZhtpStorageManager>>,
    /// CSP manager
    csp_manager: Arc<CspManager>,
    /// CSRF manager
    csrf_manager: Arc<CsrfManager>,
    /// Security configuration
    security_config: BrowserSecurityConfig,
}

impl ZhtpBrowser {
    /// Create new browser instance with security features
    pub async fn new(
        addr: SocketAddr, 
        security_config: Option<BrowserSecurityConfig>,
        audit_trail: Option<Arc<AuditTrail>>,
    ) -> Result<Self> {
        let security_config = security_config.unwrap_or_default();
        
        // Create ZHTP node
        let node = ZhtpNode::new(addr, Keypair::generate()).await?;
        let node = Arc::new(Mutex::new(node));

        // Create channels
        let (request_tx, request_rx) = mpsc::channel(100);
        let (response_tx, response_rx) = mpsc::channel(100);

        // Create security managers
        let csp_manager = Arc::new(CspManager::new(security_config.clone(), audit_trail));
        let csrf_manager = Arc::new(CsrfManager::new(security_config.session_timeout_minutes));

        // Spawn request handler
        let node_clone = Arc::clone(&node);
        let response_tx_clone = response_tx.clone();
        tokio::spawn(async move {
            Self::handle_requests(node_clone, request_rx, response_tx_clone).await;
        });

        // Spawn cleanup tasks
        let csp_manager_cleanup = Arc::clone(&csp_manager);
        let csrf_manager_cleanup = Arc::clone(&csrf_manager);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                csp_manager_cleanup.cleanup_expired_nonces().await;
                csrf_manager_cleanup.cleanup_expired_tokens().await;
            }
        });

        // Create browser
        let browser = Self {
            request_tx,
            response_rx,
            storage: None,
            csp_manager,
            csrf_manager,
            security_config,
        };

        Ok(browser)
    }

    /// Generate secure HTML with CSP and CSRF protection
    pub async fn generate_secure_html(&self, template: &str, session_id: &str) -> Result<String> {
        // Generate nonces
        let script_nonce = self.csp_manager.generate_nonce().await;
        let style_nonce = self.csp_manager.generate_nonce().await;
        
        // Generate CSRF token
        let csrf_token = self.csrf_manager.generate_token(session_id).await;
        
        // Generate CSP header (for response headers)
        let _csp_header = self.csp_manager.generate_csp_header(&script_nonce, &style_nonce).await;
        
        // Replace template variables
        let html = template
            .replace("{{script_nonce}}", &script_nonce)
            .replace("{{style_nonce}}", &style_nonce)
            .replace("{{csrf_token}}", &csrf_token);
            
        Ok(html)
    }

    /// Validate CSRF token for requests
    pub async fn validate_csrf_token(&self, session_id: &str, token: &str) -> bool {
        self.csrf_manager.validate_token(session_id, token).await
    }

    /// Get CSP headers for HTTP response
    pub async fn get_security_headers(&self, session_id: &str) -> HashMap<String, String> {
        let script_nonce = self.csp_manager.generate_nonce().await;
        let style_nonce = self.csp_manager.generate_nonce().await;
        let csp_header = self.csp_manager.generate_csp_header(&script_nonce, &style_nonce).await;
        
        let mut headers = HashMap::new();
        
        if self.security_config.enable_csp {
            headers.insert("Content-Security-Policy".to_string(), csp_header);
        }
        
        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());
        headers.insert("Referrer-Policy".to_string(), "strict-origin-when-cross-origin".to_string());
        headers.insert("Permissions-Policy".to_string(), 
            "geolocation=(), camera=(), microphone=(), payment=(), usb=()".to_string());
        
        if self.security_config.secure_cookies {
            headers.insert("Set-Cookie".to_string(), 
                format!("session_id={}; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
                    session_id, self.security_config.session_timeout_minutes * 60));
        }
        
        headers
    }

    /// Handle browser requests
    async fn handle_requests(
        node: Arc<Mutex<ZhtpNode>>,
        mut request_rx: mpsc::Receiver<BrowserRequest>,
        response_tx: mpsc::Sender<BrowserResponse>,
    ) {
        while let Some(request) = request_rx.recv().await {
            let response = match request {
                BrowserRequest::GetContent(id) => {
                    let n = node.lock().await;
                    match n.get_content(&id.to_string()).await {
                        Ok((data, _)) => {
                            // Create basic metadata for response
                            let metadata = ContentMetadata {
                                id: id.clone(),
                                size: data.len() as u64,
                                content_type: "application/octet-stream".to_string(),
                                locations: vec![],
                                last_verified: 0,
                                tags: vec![],
                            };
                            BrowserResponse::Content(data, metadata)
                        },
                        Err(e) => BrowserResponse::Error(e.to_string()),
                    }
                }
                BrowserRequest::Search(query) => {
                    let n = node.lock().await;
                    match n.search_content(&query).await {
                        Ok(results) => {
                            let converted: Vec<(ContentId, ContentMetadata)> = results
                                .into_iter()
                                .filter(|(_, metadata)| {
                                    // Match against content_type and tags
                                    metadata.content_type.contains(&query) ||
                                    metadata.tags.iter().any(|tag| tag.contains(&query))
                                })
                                .map(|(id, metadata)| (ContentId::from(id), metadata))
                                .collect();
                            BrowserResponse::SearchResults(converted)
                        },
                        Err(e) => BrowserResponse::Error(e.to_string()),
                    }
                }
                BrowserRequest::Connect(addr) => {
                    let mut n = node.lock().await;
                    match n.connect(addr).await {
                        Ok(_) => BrowserResponse::ConnectionStatus(true),
                        Err(_) => BrowserResponse::ConnectionStatus(false),
                    }
                }
                BrowserRequest::CreateIdentity => {
                    // Simulate identity creation
                    let commitment = format!("identity_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
                    BrowserResponse::IdentityCreated(commitment)
                }
                BrowserRequest::CreatePersonhoodProof(_biometric_data) => {
                    // Simulate personhood proof creation
                    let proof_id = format!("proof_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
                    BrowserResponse::PersonhoodProofCreated(proof_id)
                }
                BrowserRequest::RegisterDomain(domain, _addresses) => {
                    // Simulate domain registration
                    BrowserResponse::DomainRegistered(domain)
                }
                BrowserRequest::SubmitProposal(_title, _description) => {
                    // Simulate proposal submission
                    let proposal_id = format!("proposal_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
                    BrowserResponse::ProposalSubmitted(proposal_id)
                }
                BrowserRequest::VoteOnProposal(_proposal_id, _vote) => {
                    // Simulate vote recording
                    let vote_id = format!("vote_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
                    BrowserResponse::VoteRecorded(vote_id)
                }
                BrowserRequest::DeployDApp(_name, _code) => {
                    // Simulate DApp deployment
                    let deployment_hash = format!("dapp_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
                    BrowserResponse::DAppDeployed(deployment_hash)
                }
                BrowserRequest::DeployContract(bytecode, interface) => {
                    let mut n = node.lock().await;
                    match n.deploy_contract(bytecode, interface).await {
                        Ok(response) => BrowserResponse::ContractResponse(response),
                        Err(e) => BrowserResponse::Error(e.to_string()),
                    }
                }
                BrowserRequest::CallContract(id, method, params) => {
                    let mut n = node.lock().await;
                    match n.call_contract(&id, &method, params).await {
                        Ok(response) => BrowserResponse::ContractResponse(response),
                        Err(e) => BrowserResponse::Error(e.to_string()),
                    }
                }
            };

            if response_tx.send(response).await.is_err() {
                break;
            }
        }
    }

    /// Send browser request
    async fn send_request(&mut self, request: BrowserRequest) -> Result<BrowserResponse> {
        self.request_tx.send(request).await?;
        Ok(self.response_rx.recv().await.ok_or_else(|| anyhow::anyhow!("No response received"))?)
    }

    /// Get content by ID
    pub async fn get_content(&mut self, id: &ContentId) -> Result<Vec<u8>> {
        // Try DHT first if available
        if let Some(storage) = &self.storage {
            if let Ok(Some(data)) = storage.get_content(&id.to_string()).await {
                return Ok(data);
            }
        }

        // Fall back to ZHTP
        match self.send_request(BrowserRequest::GetContent(id.clone())).await? {
            BrowserResponse::Content(data, _) => Ok(data),
            BrowserResponse::Error(e) => Err(anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }

    /// Search content
    pub async fn search(&mut self, query: String) -> Result<Vec<(ContentId, ContentMetadata)>> {
        // Try DHT search first if available
        if let Some(storage) = &self.storage {
            let results = storage.search_by_tag(&query).await;
            if !results.is_empty() {
                return Ok(results);
            }
            // Also try searching by content type
            let type_results = storage.search_by_type(&query).await;
            if !type_results.is_empty() {
                return Ok(type_results);
            }
        }

        // Fall back to ZHTP search
        match self.send_request(BrowserRequest::Search(query)).await? {
            BrowserResponse::SearchResults(results) => Ok(results),
            BrowserResponse::Error(e) => Err(anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }


    /// Connect to storage network
    pub async fn connect_storage(&mut self, storage: Arc<crate::storage::ZhtpStorageManager>) -> Result<()> {
        self.storage = Some(storage);
        Ok(())
    }

    /// Connect to ZHTP node
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<bool> {
        match self.send_request(BrowserRequest::Connect(addr)).await? {
            BrowserResponse::ConnectionStatus(status) => Ok(status),
            BrowserResponse::Error(e) => Err(anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }

    /// Deploy contract
    pub async fn deploy_contract(&mut self, bytecode: Vec<u8>, interface: String) -> Result<Vec<u8>> {
        // Send deployment request with provided interface
        match self.send_request(BrowserRequest::DeployContract(bytecode, interface)).await? {
            BrowserResponse::ContractResponse(response) => Ok(response),
            BrowserResponse::Error(e) => Err(anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }

    /// Call contract method
    pub async fn call_contract(
        &mut self,
        id: String,
        method: String,
        params: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        match self.send_request(BrowserRequest::CallContract(id, method, params)).await? {
            BrowserResponse::ContractResponse(response) => Ok(response),
            BrowserResponse::Error(e) => Err(anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_browser_basic() -> Result<()> {
        let addr: SocketAddr = "127.0.0.1:8000".parse()?;
        let mut browser = ZhtpBrowser::new(addr, None, None).await?;

        // Test that browser was created successfully
        println!("✅ ZHTP Browser created successfully");

        // Test content search (should be empty initially)
        let results = browser.search("test".to_string()).await?;
        assert!(results.is_empty(), "No content should be indexed initially");
        
        println!("✅ Content search returns empty results as expected");
        Ok(())
    }
}