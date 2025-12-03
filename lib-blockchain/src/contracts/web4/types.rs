//! Web4 contract types and data structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Web4 website metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebsiteMetadata {
    /// Website title
    pub title: String,
    /// Website description
    pub description: String,
    /// Website author/owner
    pub author: String,
    /// Website version
    pub version: String,
    /// Website tags
    pub tags: Vec<String>,
    /// Website language
    pub language: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Additional metadata
    pub custom: HashMap<String, String>,
}

/// Content route configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRoute {
    /// Route path (e.g., "/", "/about", "/api/data")
    pub path: String,
    /// DHT content hash for this route
    pub content_hash: String,
    /// MIME content type
    pub content_type: String,
    /// Content size in bytes
    pub size: u64,
    /// Route-specific metadata
    pub metadata: HashMap<String, String>,
    /// Last updated timestamp
    pub updated_at: u64,
}

impl ContentRoute {
    /// Create ContentRoute from lib-storage ContentMetadata
    /// Extracts key metadata fields and serializes them to HashMap
    pub fn from_content_metadata(
        path: String,
        content_hash: String,
        metadata: &lib_storage::ContentMetadata,
    ) -> Self {
        let mut metadata_map = HashMap::new();
        metadata_map.insert("size".to_string(), metadata.size.to_string());
        metadata_map.insert("content_type".to_string(), metadata.content_type.clone());
        metadata_map.insert("filename".to_string(), metadata.filename.clone());
        metadata_map.insert("tier".to_string(), format!("{:?}", metadata.tier));
        metadata_map.insert("encryption".to_string(), format!("{:?}", metadata.encryption));
        metadata_map.insert("replication".to_string(), metadata.replication_factor.to_string());
        metadata_map.insert("cost_per_day".to_string(), metadata.cost_per_day.to_string());
        metadata_map.insert("access_count".to_string(), metadata.access_count.to_string());
        metadata_map.insert("created_at".to_string(), metadata.created_at.to_string());
        metadata_map.insert("last_accessed".to_string(), metadata.last_accessed.to_string());
        metadata_map.insert("tags".to_string(), metadata.tags.join(","));
        
        Self {
            path,
            content_hash,
            content_type: metadata.content_type.clone(),
            size: metadata.size,
            metadata: metadata_map,
            updated_at: metadata.last_accessed,
        }
    }
}

/// Domain ownership record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRecord {
    /// Domain name (e.g., "mysite.zhtp")
    pub domain: String,
    /// Current owner public key
    pub owner: String,
    /// Contract address managing this domain
    pub contract_address: String,
    /// Registration timestamp
    pub registered_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Domain status
    pub status: DomainStatus,
}

/// Domain status enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainStatus {
    /// Domain is active and accessible
    Active,
    /// Domain is suspended (owner action required)
    Suspended,
    /// Domain has expired
    Expired,
    /// Domain is being transferred
    Transferring,
    /// Domain is reserved
    Reserved,
}

/// Web4 contract operation types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Web4Operation {
    /// Register a new domain
    RegisterDomain {
        domain: String,
        owner: String,
        duration_years: u32,
    },
    /// Update website content
    UpdateContent {
        route: String,
        content_hash: String,
        content_type: String,
        size: u64,
    },
    /// Add a new route
    AddRoute {
        route: ContentRoute,
    },
    /// Update website metadata
    UpdateMetadata {
        metadata: WebsiteMetadata,
    },
    /// Transfer domain ownership
    TransferOwnership {
        domain: String,
        new_owner: String,
    },
    /// Renew domain registration
    RenewDomain {
        domain: String,
        duration_years: u32,
    },
    /// Remove a route
    RemoveRoute {
        route_path: String,
    },
}

/// Web4 contract query types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Web4Query {
    /// Get domain information
    GetDomain {
        domain: String,
    },
    /// Get content hash for a route
    GetContentHash {
        route: String,
    },
    /// Get all routes for the website
    GetRoutes,
    /// Get website metadata
    GetMetadata,
    /// Get domain owner
    GetOwner {
        domain: String,
    },
    /// Check if domain is available
    IsDomainAvailable {
        domain: String,
    },
    /// Get contract statistics
    GetStats,
}

/// Web4 contract response types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Web4Response {
    /// Domain information response
    Domain(DomainRecord),
    /// Content hash response
    ContentHash(String),
    /// Routes list response
    Routes(Vec<ContentRoute>),
    /// Metadata response
    Metadata(WebsiteMetadata),
    /// Owner response
    Owner(String),
    /// Domain availability response
    DomainAvailable(bool),
    /// Statistics response
    Stats {
        total_routes: u64,
        total_size: u64,
        last_updated: u64,
        domain_status: DomainStatus,
    },
    /// Operation success response
    Success {
        message: String,
        data: Option<serde_json::Value>,
    },
    /// Error response
    Error {
        code: u32,
        message: String,
    },
}

/// Web4 contract error types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Web4Error {
    /// Domain not found
    DomainNotFound(String),
    /// Domain already registered
    DomainAlreadyRegistered(String),
    /// Domain expired
    DomainExpired(String),
    /// Unauthorized operation
    Unauthorized,
    /// Invalid domain name
    InvalidDomain(String),
    /// Invalid content hash
    InvalidContentHash(String),
    /// Route not found
    RouteNotFound(String),
    /// Route already exists
    RouteAlreadyExists(String),
    /// Invalid metadata
    InvalidMetadata(String),
    /// Insufficient funds for operation
    InsufficientFunds,
    /// Contract storage full
    StorageFull,
    /// Internal contract error
    InternalError(String),
}

impl std::fmt::Display for Web4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Web4Error::DomainNotFound(domain) => write!(f, "Domain not found: {}", domain),
            Web4Error::DomainAlreadyRegistered(domain) => write!(f, "Domain already registered: {}", domain),
            Web4Error::DomainExpired(domain) => write!(f, "Domain expired: {}", domain),
            Web4Error::Unauthorized => write!(f, "Unauthorized operation"),
            Web4Error::InvalidDomain(domain) => write!(f, "Invalid domain name: {}", domain),
            Web4Error::InvalidContentHash(hash) => write!(f, "Invalid content hash: {}", hash),
            Web4Error::RouteNotFound(route) => write!(f, "Route not found: {}", route),
            Web4Error::RouteAlreadyExists(route) => write!(f, "Route already exists: {}", route),
            Web4Error::InvalidMetadata(msg) => write!(f, "Invalid metadata: {}", msg),
            Web4Error::InsufficientFunds => write!(f, "Insufficient funds for operation"),
            Web4Error::StorageFull => write!(f, "Contract storage is full"),
            Web4Error::InternalError(msg) => write!(f, "Internal contract error: {}", msg),
        }
    }
}

impl std::error::Error for Web4Error {}

/// Website deployment data structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebsiteDeploymentData {
    /// Domain name
    pub domain: String,
    /// Website metadata
    pub metadata: WebsiteMetadata,
    /// Content routes
    pub routes: Vec<ContentRoute>,
    /// Owner identity
    pub owner: String,
    /// Deployment configuration
    pub config: HashMap<String, String>,
}

// ============================================================================
// DIRECTORY TREE STRUCTURES - For complete file system support
// ============================================================================

/// Node type in directory tree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// Regular file
    File {
        /// MIME type
        mime_type: String,
        /// File size in bytes
        size: u64,
        /// Is this file executable/WASM
        is_executable: bool,
    },
    /// Directory/folder
    Directory,
    /// Symbolic link to another path
    Symlink {
        /// Target path
        target: String,
    },
}

/// File metadata for directory nodes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
    /// File permissions (Unix-style: 755, 644, etc.)
    pub permissions: u32,
    /// File owner
    pub owner: String,
    /// Custom attributes
    pub attributes: HashMap<String, String>,
}

/// Directory node in the file tree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryNode {
    /// Node name (filename or directory name)
    pub name: String,
    /// Full path from root
    pub path: String,
    /// Node type
    pub node_type: NodeType,
    /// DHT content hash (for files only)
    pub content_hash: Option<String>,
    /// Child nodes (for directories only)
    pub children: Vec<DirectoryNode>,
    /// File metadata
    pub metadata: FileMetadata,
    /// Compression algorithm used (if any)
    pub compression: Option<String>,
    /// Encryption status
    pub is_encrypted: bool,
}

impl DirectoryNode {
    /// Create a new file node
    pub fn new_file(
        name: String,
        path: String,
        content_hash: String,
        mime_type: String,
        size: u64,
        owner: String,
        is_executable: bool,
    ) -> Self {
        let current_time = chrono::Utc::now().timestamp() as u64;
        Self {
            name,
            path,
            node_type: NodeType::File {
                mime_type,
                size,
                is_executable,
            },
            content_hash: Some(content_hash),
            children: Vec::new(),
            metadata: FileMetadata {
                created_at: current_time,
                modified_at: current_time,
                permissions: 0o644, // rw-r--r--
                owner,
                attributes: HashMap::new(),
            },
            compression: None,
            is_encrypted: false,
        }
    }

    /// Create a new directory node
    pub fn new_directory(name: String, path: String, owner: String) -> Self {
        let current_time = chrono::Utc::now().timestamp() as u64;
        Self {
            name,
            path,
            node_type: NodeType::Directory,
            content_hash: None,
            children: Vec::new(),
            metadata: FileMetadata {
                created_at: current_time,
                modified_at: current_time,
                permissions: 0o755, // rwxr-xr-x
                owner,
                attributes: HashMap::new(),
            },
            compression: None,
            is_encrypted: false,
        }
    }

    /// Add a child node to this directory
    pub fn add_child(&mut self, child: DirectoryNode) -> Result<(), String> {
        if !matches!(self.node_type, NodeType::Directory) {
            return Err("Cannot add child to non-directory node".to_string());
        }

        // Check for duplicate names
        if self.children.iter().any(|c| c.name == child.name) {
            return Err(format!("Child with name '{}' already exists", child.name));
        }

        self.children.push(child);
        self.metadata.modified_at = chrono::Utc::now().timestamp() as u64;
        Ok(())
    }

    /// Find a node by path
    pub fn find_node(&self, path: &str) -> Option<&DirectoryNode> {
        if self.path == path {
            return Some(self);
        }

        for child in &self.children {
            if let Some(node) = child.find_node(path) {
                return Some(node);
            }
        }

        None
    }

    /// Get total size of this node and all children
    pub fn total_size(&self) -> u64 {
        let mut size = 0;

        if let NodeType::File { size: file_size, .. } = &self.node_type {
            size += file_size;
        }

        for child in &self.children {
            size += child.total_size();
        }

        size
    }

    /// Count total files in this tree
    pub fn file_count(&self) -> u32 {
        let mut count = 0;

        if matches!(self.node_type, NodeType::File { .. }) {
            count += 1;
        }

        for child in &self.children {
            count += child.file_count();
        }

        count
    }

    /// List all file paths in this tree
    pub fn list_all_files(&self) -> Vec<String> {
        let mut files = Vec::new();

        if matches!(self.node_type, NodeType::File { .. }) {
            files.push(self.path.clone());
        }

        for child in &self.children {
            files.extend(child.list_all_files());
        }

        files
    }
}

// ============================================================================
// WEBSITE MANIFEST STRUCTURES - For complete deployments
// ============================================================================

/// Website manifest for complete site deployments
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebsiteManifest {
    /// Manifest version
    pub version: String,
    /// Root directory tree
    pub root_directory: DirectoryNode,
    /// Entry points mapping (route -> file path)
    pub entry_points: HashMap<String, String>,
    /// Default entry point (usually "/index.html")
    pub default_entry: String,
    /// Total size of all files
    pub total_size: u64,
    /// Total file count
    pub file_count: u32,
    /// Deployment timestamp
    pub deployed_at: u64,
    /// Manifest hash for integrity
    pub manifest_hash: String,
    /// Dependencies on other contracts/libraries
    pub dependencies: Vec<DependencyRef>,
}

impl WebsiteManifest {
    /// Create a new website manifest
    pub fn new(root_directory: DirectoryNode, default_entry: String) -> Self {
        let total_size = root_directory.total_size();
        let file_count = root_directory.file_count();
        let deployed_at = chrono::Utc::now().timestamp() as u64;

        // Calculate manifest hash
        let manifest_data = format!("{}{}{}", total_size, file_count, deployed_at);
        let hash_bytes = blake3::hash(manifest_data.as_bytes());
        let manifest_hash = hex::encode(hash_bytes.as_bytes());

        Self {
            version: "1.0.0".to_string(),
            root_directory,
            entry_points: HashMap::new(),
            default_entry,
            total_size,
            file_count,
            deployed_at,
            manifest_hash,
            dependencies: Vec::new(),
        }
    }

    /// Add an entry point
    pub fn add_entry_point(&mut self, route: String, file_path: String) -> Result<(), String> {
        // Verify the file exists in the directory tree
        if self.root_directory.find_node(&file_path).is_none() {
            return Err(format!("File not found: {}", file_path));
        }

        self.entry_points.insert(route, file_path);
        Ok(())
    }

    /// Get file path for a route
    pub fn resolve_route(&self, route: &str) -> Option<&DirectoryNode> {
        // Try to find exact route match
        if let Some(file_path) = self.entry_points.get(route) {
            return self.root_directory.find_node(file_path);
        }

        // Try direct path resolution
        self.root_directory.find_node(route)
    }

    /// Validate manifest integrity
    pub fn validate(&self) -> Result<(), String> {
        // Check total size matches
        let calculated_size = self.root_directory.total_size();
        if calculated_size != self.total_size {
            return Err(format!(
                "Size mismatch: manifest says {} but calculated {}",
                self.total_size, calculated_size
            ));
        }

        // Check file count matches
        let calculated_count = self.root_directory.file_count();
        if calculated_count != self.file_count {
            return Err(format!(
                "File count mismatch: manifest says {} but calculated {}",
                self.file_count, calculated_count
            ));
        }

        // Verify default entry exists
        if self.root_directory.find_node(&self.default_entry).is_none() {
            return Err(format!("Default entry not found: {}", self.default_entry));
        }

        // Verify all entry points exist
        for (route, file_path) in &self.entry_points {
            if self.root_directory.find_node(file_path).is_none() {
                return Err(format!("Entry point '{}' references non-existent file: {}", route, file_path));
            }
        }

        Ok(())
    }
}

/// Dependency reference for external libraries/contracts
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyRef {
    /// Dependency name
    pub name: String,
    /// Dependency version
    pub version: String,
    /// DHT hash or contract address
    pub reference: String,
    /// Dependency type
    pub dep_type: DependencyType,
}

/// Dependency types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyType {
    /// JavaScript/CSS library
    Library,
    /// WASM module
    WasmModule,
    /// Another Web4 contract
    Web4Contract,
    /// External API
    ExternalApi,
}

/// Deployment package for bundled uploads
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPackage {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Website manifest
    pub manifest: WebsiteManifest,
    /// Website metadata
    pub metadata: WebsiteMetadata,
    /// Domain to deploy to
    pub domain: String,
    /// Owner identity
    pub owner: String,
    /// Deployment configuration
    pub config: HashMap<String, String>,
    /// Package hash for integrity
    pub package_hash: String,
}

// ============================================================================
// WASM EXECUTABLE STRUCTURES - For hosting WebAssembly modules
// ============================================================================

/// WebAssembly executable reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableRef {
    /// Executable name/identifier
    pub name: String,
    /// DHT hash of the WASM binary
    pub wasm_hash: String,
    /// Entry point function name
    pub entry_point: String,
    /// WASM module size in bytes
    pub size: u64,
    /// Permissions granted to this executable
    pub permissions: Vec<WasmPermission>,
    /// Executable version
    pub version: String,
    /// Executable metadata
    pub metadata: WasmMetadata,
    /// Deployment timestamp
    pub deployed_at: u64,
}

/// WASM module permissions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmPermission {
    /// Can read contract state
    ReadState,
    /// Can write to contract state
    WriteState,
    /// Can make network requests
    Network,
    /// Can access storage/DHT
    Storage,
    /// Can call other contracts
    CallContract,
    /// Can emit events
    EmitEvents,
    /// Can access cryptographic functions
    Crypto,
    /// Custom permission
    Custom(String),
}

/// WebAssembly module metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmMetadata {
    /// Module author
    pub author: String,
    /// Module description
    pub description: String,
    /// Module license
    pub license: String,
    /// Source code repository
    pub repository: Option<String>,
    /// Documentation URL
    pub documentation: Option<String>,
    /// Module tags for discovery
    pub tags: Vec<String>,
    /// Exported functions
    pub exports: Vec<String>,
    /// Required imports
    pub imports: Vec<String>,
    /// Memory requirements (pages)
    pub memory_pages: u32,
    /// Maximum execution time (milliseconds)
    pub max_execution_time: u64,
    /// Gas limit for execution
    pub gas_limit: u64,
}

impl WasmMetadata {
    /// Create default WASM metadata
    pub fn default() -> Self {
        Self {
            author: String::new(),
            description: String::new(),
            license: "MIT".to_string(),
            repository: None,
            documentation: None,
            tags: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            memory_pages: 16, // 1MB default
            max_execution_time: 5000, // 5 seconds
            gas_limit: 100_000_000,
        }
    }
}

/// WASM deployment configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmDeployment {
    /// Deployment name
    pub name: String,
    /// WASM binary content hash
    pub wasm_hash: String,
    /// WASM binary size
    pub size: u64,
    /// Entry point function
    pub entry_point: String,
    /// Permissions to grant
    pub permissions: Vec<WasmPermission>,
    /// Module metadata
    pub metadata: WasmMetadata,
    /// Initialization parameters
    pub init_params: HashMap<String, String>,
    /// Owner of this deployment
    pub owner: String,
}

impl WasmDeployment {
    /// Create a new WASM deployment
    pub fn new(
        name: String,
        wasm_hash: String,
        size: u64,
        entry_point: String,
        owner: String,
    ) -> Self {
        Self {
            name,
            wasm_hash,
            size,
            entry_point,
            permissions: vec![
                WasmPermission::ReadState,
                WasmPermission::EmitEvents,
            ],
            metadata: WasmMetadata::default(),
            init_params: HashMap::new(),
            owner,
        }
    }

    /// Add permission to the deployment
    pub fn with_permission(mut self, permission: WasmPermission) -> Self {
        if !self.permissions.contains(&permission) {
            self.permissions.push(permission);
        }
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: WasmMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Add initialization parameter
    pub fn with_param(mut self, key: String, value: String) -> Self {
        self.init_params.insert(key, value);
        self
    }

    /// Validate deployment configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Deployment name cannot be empty".to_string());
        }

        if self.wasm_hash.is_empty() {
            return Err("WASM hash cannot be empty".to_string());
        }

        if self.size == 0 {
            return Err("WASM size must be greater than 0".to_string());
        }

        if self.size > 10 * 1024 * 1024 {
            return Err("WASM binary too large (max 10MB)".to_string());
        }

        if self.entry_point.is_empty() {
            return Err("Entry point cannot be empty".to_string());
        }

        if self.metadata.memory_pages > 256 {
            return Err("Memory pages exceed limit (max 256 = 16MB)".to_string());
        }

        if self.metadata.gas_limit > 1_000_000_000 {
            return Err("Gas limit exceeds maximum (1B)".to_string());
        }

        Ok(())
    }
}

/// WASM execution result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmExecutionResult {
    /// Execution success status
    pub success: bool,
    /// Return data from execution
    pub return_data: Vec<u8>,
    /// Gas consumed
    pub gas_used: u64,
    /// Execution time (milliseconds)
    pub execution_time: u64,
    /// Error message if failed
    pub error: Option<String>,
    /// Events emitted during execution
    pub events: Vec<String>,
}

/// WASM module registry entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmModuleEntry {
    /// Module identifier
    pub id: String,
    /// Executable reference
    pub executable: ExecutableRef,
    /// Associated routes (URL paths that trigger this module)
    pub routes: Vec<String>,
    /// Activation status
    pub is_active: bool,
    /// Last execution timestamp
    pub last_executed: Option<u64>,
    /// Total execution count
    pub execution_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_website_metadata_serialization() {
        let metadata = WebsiteMetadata {
            title: "My Web4 Site".to_string(),
            description: "A decentralized website".to_string(),
            author: "test@example.com".to_string(),
            version: "1.0.0".to_string(),
            tags: vec!["web4".to_string(), "zhtp".to_string()],
            language: "en".to_string(),
            created_at: 1633024800,
            updated_at: 1633024800,
            custom: HashMap::new(),
        };

        let serialized = serde_json::to_string(&metadata).unwrap();
        let deserialized: WebsiteMetadata = serde_json::from_str(&serialized).unwrap();
        assert_eq!(metadata, deserialized);
    }

    #[test]
    fn test_content_route_serialization() {
        let mut route_metadata = HashMap::new();
        route_metadata.insert("layout".to_string(), "default".to_string());

        let route = ContentRoute {
            path: "/about".to_string(),
            content_hash: "QmXoYpo9YdJkX8kGd7YtT6yC2FJLzMQvE5rE7Nvh4eJnX5".to_string(),
            content_type: "text/html".to_string(),
            size: 2048,
            metadata: route_metadata,
            updated_at: 1633024800,
        };

        let serialized = serde_json::to_string(&route).unwrap();
        let deserialized: ContentRoute = serde_json::from_str(&serialized).unwrap();
        assert_eq!(route, deserialized);
    }

    #[test]
    fn test_domain_status() {
        assert_eq!(DomainStatus::Active, DomainStatus::Active);
        assert_ne!(DomainStatus::Active, DomainStatus::Expired);
    }

    #[test]
    fn test_web4_error_display() {
        let error = Web4Error::DomainNotFound("test.zhtp".to_string());
        assert_eq!(error.to_string(), "Domain not found: test.zhtp");

        let error = Web4Error::Unauthorized;
        assert_eq!(error.to_string(), "Unauthorized operation");
    }

    #[test]
    fn test_directory_node_creation() {
        let file_node = DirectoryNode::new_file(
            "index.html".to_string(),
            "/index.html".to_string(),
            "QmHash123".to_string(),
            "text/html".to_string(),
            1024,
            "owner123".to_string(),
            false,
        );

        assert_eq!(file_node.name, "index.html");
        assert_eq!(file_node.path, "/index.html");
        assert!(matches!(file_node.node_type, NodeType::File { .. }));
        assert_eq!(file_node.content_hash, Some("QmHash123".to_string()));
    }

    #[test]
    fn test_directory_tree_operations() {
        let mut root = DirectoryNode::new_directory("/".to_string(), "/".to_string(), "owner".to_string());
        
        let index = DirectoryNode::new_file(
            "index.html".to_string(),
            "/index.html".to_string(),
            "QmIndex".to_string(),
            "text/html".to_string(),
            2048,
            "owner".to_string(),
            false,
        );

        assert!(root.add_child(index).is_ok());
        assert_eq!(root.file_count(), 1);
        assert_eq!(root.total_size(), 2048);

        let found = root.find_node("/index.html");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "index.html");
    }

    #[test]
    fn test_website_manifest() {
        let mut root = DirectoryNode::new_directory("/".to_string(), "/".to_string(), "owner".to_string());
        
        let index = DirectoryNode::new_file(
            "index.html".to_string(),
            "/index.html".to_string(),
            "QmIndex".to_string(),
            "text/html".to_string(),
            1024,
            "owner".to_string(),
            false,
        );
        root.add_child(index).unwrap();

        let mut manifest = WebsiteManifest::new(root, "/index.html".to_string());
        
        assert_eq!(manifest.file_count, 1);
        assert_eq!(manifest.total_size, 1024);
        assert!(manifest.validate().is_ok());

        // Test route resolution
        manifest.add_entry_point("/".to_string(), "/index.html".to_string()).unwrap();
        let resolved = manifest.resolve_route("/");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().name, "index.html");
    }

    #[test]
    fn test_nested_directory_structure() {
        let mut root = DirectoryNode::new_directory("/".to_string(), "/".to_string(), "owner".to_string());
        
        let mut assets_dir = DirectoryNode::new_directory("assets".to_string(), "/assets".to_string(), "owner".to_string());
        
        let css_file = DirectoryNode::new_file(
            "style.css".to_string(),
            "/assets/style.css".to_string(),
            "QmCss".to_string(),
            "text/css".to_string(),
            512,
            "owner".to_string(),
            false,
        );
        
        assets_dir.add_child(css_file).unwrap();
        root.add_child(assets_dir).unwrap();

        assert_eq!(root.file_count(), 1);
        assert_eq!(root.total_size(), 512);

        let found = root.find_node("/assets/style.css");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "style.css");
    }
}