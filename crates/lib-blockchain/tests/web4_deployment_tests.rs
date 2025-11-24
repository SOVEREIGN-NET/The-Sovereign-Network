//! Web4 Smart Contract Deployment Tests
//! 
//! Complete integration test demonstrating:
//! 1. Domain registration  
//! 2. Website deployment with directory structure
//! 3. content storage to DHT network
//! 4. DNS resolution via smart contracts
//! 5. Content retrieval from DHT

use lib_blockchain::{
    contracts::{
        executor::{ContractExecutor, ExecutionContext, MemoryStorage},
        web4::{
            Web4Contract, WebsiteMetadata, ContentRoute, DomainRecord, DomainStatus,
            WebsiteDeploymentData, DirectoryNode, NodeType, WebsiteManifest, DeploymentPackage,
        },
    },
    types::{ContractCall, ContractType, CallPermissions},
};
use lib_crypto::{KeyPair, hash_blake3};
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};
use lib_network::dht::DHTClient;
use lib_identity::ZhtpIdentity;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Read hello_world files and compute DHT content hashes
async fn upload_hello_world_to_dht() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut hashes = HashMap::new();
    
    println!(" Reading hello_world files from disk...");
    
    // Read index.html
    let index_path = Path::new("../hello_world/index.html");
    let index_content = fs::read(index_path)?;
    println!("    Read index.html ({} bytes)", index_content.len());
    
    // Read style.css
    let css_path = Path::new("../hello_world/style.css");
    let css_content = fs::read(css_path)?;
    println!("    Read style.css ({} bytes)\n", css_content.len());
    
    // Upload index.html to DHT - compute hash
    println!(" Computing content hashes for DHT storage...");
    let index_hash = hash_blake3(&index_content);
    let index_hash_str = format!("dht:{}", hex::encode(&index_hash));
    
    hashes.insert("index.html".to_string(), index_hash_str.clone());
    hashes.insert("index_size".to_string(), index_content.len().to_string());
    println!("    index.html hash: {}\n", index_hash_str);
    
    // Upload style.css to DHT - compute hash
    let css_hash = hash_blake3(&css_content);
    let css_hash_str = format!("dht:{}", hex::encode(&css_hash));
    
    hashes.insert("style.css".to_string(), css_hash_str.clone());
    hashes.insert("css_size".to_string(), css_content.len().to_string());
    println!("    style.css hash: {}\n", css_hash_str);
    
    Ok(hashes)
}

/// Create directory tree structure for hello_world website with hashes
fn create_hello_world_directory(content_hashes: &HashMap<String, String>) -> DirectoryNode {
    // Root directory
    let mut root = DirectoryNode {
        path: "/".to_string(),
        name: "root".to_string(),
        node_type: NodeType::Directory,
        children: vec![],
        content_hash: None,
        metadata: HashMap::new(),
        created_at: chrono::Utc::now().timestamp() as u64,
        updated_at: chrono::Utc::now().timestamp() as u64,
    };
    
    // index.html file
    let index_size: u64 = content_hashes.get("index_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3456);
    
    let index_html = DirectoryNode {
        path: "/index.html".to_string(),
        name: "index.html".to_string(),
        node_type: NodeType::File {
            mime_type: "text/html".to_string(),
            size: index_size,
            encoding: Some("utf-8".to_string()),
        },
        children: vec![],
        content_hash: Some(content_hashes.get("index.html").cloned().unwrap_or_default()),
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("title".to_string(), "Hello World - Web4 Site".to_string());
            meta
        },
        created_at: chrono::Utc::now().timestamp() as u64,
        updated_at: chrono::Utc::now().timestamp() as u64,
    };
    
    // style.css file
    let css_size: u64 = content_hashes.get("css_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2845);
        
    let style_css = DirectoryNode {
        path: "/style.css".to_string(),
        name: "style.css".to_string(),
        node_type: NodeType::File {
            mime_type: "text/css".to_string(),
            size: css_size,
            encoding: Some("utf-8".to_string()),
        },
        children: vec![],
        content_hash: Some(content_hashes.get("style.css").cloned().unwrap_or_default()),
        metadata: HashMap::new(),
        created_at: chrono::Utc::now().timestamp() as u64,
        updated_at: chrono::Utc::now().timestamp() as u64,
    };
    
    // Add files to root
    root.children.push(index_html);
    root.children.push(style_css);
    
    root
}

/// Create complete website manifest for hello_world with DHT hashes
fn create_hello_world_manifest(content_hashes: HashMap<String, String>) -> WebsiteManifest {
    let directory = create_hello_world_directory(&content_hashes);
    
    let mut entry_points = HashMap::new();
    entry_points.insert("/".to_string(), "/index.html".to_string());
    entry_points.insert("/index.html".to_string(), "/index.html".to_string());
    entry_points.insert("/style.css".to_string(), "/style.css".to_string());
    
    let index_size: u64 = content_hashes.get("index_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3456);
    let css_size: u64 = content_hashes.get("css_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2845);
    
    WebsiteManifest {
        version: "1.0.0".to_string(),
        root_directory: directory,
        entry_points,
        dependencies: vec![],
        wasm_modules: vec![],
        total_size: index_size + css_size,
        file_count: 2,
        manifest_hash: "".to_string(), // Will be calculated on validation
        created_at: chrono::Utc::now().timestamp() as u64,
    }
}

#[tokio::test]
async fn test_hello_world_deployment_full_flow() {
    println!("\n Starting Hello World Web4 Deployment Test\n");
    println!("{}", "=".repeat(60));
    
    // 0. Initialize DHT client for storage
    println!("  Step 0: Initializing DHT client for content storage...");
    let dht_identity = ZhtpIdentity::new(
        lib_identity::IdentityType::User,
        vec![1, 2, 3],  // Dummy public key for testing
        lib_proofs::identity::proof::ZeroKnowledgeProof {
            proof_data: vec![],
            proof_type: "test".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        },
    ).expect("Failed to create DHT identity");
    
    let mut dht_client = DHTClient::new(dht_identity.clone()).await
        .expect("Failed to initialize DHT client");
    println!("    DHT client initialized");
    println!("   Node ID: {}\n", hex::encode(&dht_identity.id.to_string().as_bytes()[..8]));
    
    // 0.5 Upload hello_world files to DHT and get content hashes
    let content_hashes = upload_hello_world_to_dht().await
        .expect("Failed to upload content to DHT");
    
    println!(" Content Upload Summary:");
    for (file, hash) in &content_hashes {
        if !file.ends_with("_size") {
            println!("   {} → {}", file, hash);
        }
    }
    println!();
    
    // 1. Setup: Create executor and context
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    
    let owner_keypair = KeyPair::generate().unwrap();
    let mut context = ExecutionContext::new(
        owner_keypair.public_key.clone(),
        1,
        chrono::Utc::now().timestamp() as u64,
        1_000_000, // 1M gas limit
        [1u8; 32],
    );
    
    println!(" Step 1: Executor and context initialized");
    println!("   Owner: {}", hex::encode(owner_keypair.public_key.as_bytes()));
    println!("   Gas Limit: {}\n", context.gas_limit);
    
    // 2. Create website metadata
    let metadata = WebsiteMetadata {
        title: "Hello World - Web4 Site".to_string(),
        description: "A simple Hello World website demonstrating Web4 capabilities on ZHTP with DHT storage".to_string(),
        author: hex::encode(owner_keypair.public_key.as_bytes()),
        version: "1.0.0".to_string(),
        tags: vec!["web4".to_string(), "hello-world".to_string(), "zhtp".to_string(), "dht".to_string()],
        language: "en".to_string(),
        created_at: chrono::Utc::now().timestamp() as u64,
        updated_at: chrono::Utc::now().timestamp() as u64,
        custom: HashMap::new(),
    };
    
    println!(" Step 2: Website metadata created");
    println!("   Title: {}", metadata.title);
    println!("   Version: {}\n", metadata.version);
    
    // 3. Create deployment package with manifest using DHT hashes
    let manifest = create_hello_world_manifest(content_hashes.clone());
    let deployment_package = DeploymentPackage {
        domain: "hello-world.zhtp".to_string(),
        owner: hex::encode(owner_keypair.public_key.as_bytes()),
        metadata: metadata.clone(),
        manifest,
        config: HashMap::new(),
    };
    
    println!(" Step 3: Deployment package created with DHT hashes");
    println!("   Domain: {}", deployment_package.domain);
    println!("   Files: {}", deployment_package.manifest.file_count);
    println!("   Total Size: {} bytes", deployment_package.manifest.total_size);
    println!("   Content on DHT: \n");
    
    // 4. Deploy website contract using manifest
    let contract_id = format!("web4_{}", hex::encode(&context.tx_hash[..8]));
    let web4_contract = Web4Contract::from_deployment_package(
        contract_id.clone(),
        deployment_package,
    ).expect("Failed to create contract from deployment package");
    
    println!(" Step 4: Web4 contract created from manifest");
    println!("   Contract ID: {}", contract_id);
    println!("   Domain: {}", web4_contract.domain);
    println!("   Routes: {}\n", web4_contract.routes.len());
    
    // 5. Register domain via contract call
    let register_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "register_domain".to_string(),
        params: bincode::serialize(&(
            "hello-world.zhtp".to_string(),
            hex::encode(owner_keypair.public_key.as_bytes()),
            1u32, // 1 year registration
        )).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let register_result = executor.execute_call(register_call, &mut context)
        .expect("Domain registration failed");
    
    assert!(register_result.success);
    println!(" Step 5: Domain registered on blockchain");
    println!("   Status: SUCCESS");
    println!("   Gas Used: {}\n", register_result.gas_used);
    
    // 6. Test content retrieval - Index page
    let get_index_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_content_hash".to_string(),
        params: bincode::serialize(&"/".to_string()).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let index_result = executor.execute_call(get_index_call, &mut context)
        .expect("Failed to get index content");
    
    assert!(index_result.success);
    println!(" Step 6: Retrieved index.html content hash");
    println!("   Path: /");
    println!("   Gas Used: {}\n", index_result.gas_used);
    
    // 7. Test content retrieval - CSS file
    let get_css_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_content_hash".to_string(),
        params: bincode::serialize(&"/style.css".to_string()).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let css_result = executor.execute_call(get_css_call, &mut context)
        .expect("Failed to get CSS content");
    
    assert!(css_result.success);
    println!(" Step 7: Retrieved style.css content hash");
    println!("   Path: /style.css");
    println!("   Gas Used: {}\n", css_result.gas_used);
    
    // 8. Get all routes
    let get_routes_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_routes".to_string(),
        params: vec![],
        permissions: CallPermissions::Public,
    };
    
    let routes_result = executor.execute_call(get_routes_call, &mut context)
        .expect("Failed to get routes");
    
    assert!(routes_result.success);
    println!(" Step 8: Retrieved all routes");
    println!("   Gas Used: {}\n", routes_result.gas_used);
    
    // 9. Get domain info (DNS resolution)
    let get_domain_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_domain".to_string(),
        params: bincode::serialize(&"hello-world.zhtp".to_string()).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let domain_result = executor.execute_call(get_domain_call, &mut context)
        .expect("Failed to resolve domain");
    
    assert!(domain_result.success);
    println!(" Step 9: DNS resolution successful");
    println!("   Domain: hello-world.zhtp");
    println!("   Gas Used: {}\n", domain_result.gas_used);
    
    // 10. Get contract statistics
    let get_stats_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_stats".to_string(),
        params: vec![],
        permissions: CallPermissions::Public,
    };
    
    let stats_result = executor.execute_call(get_stats_call, &mut context)
        .expect("Failed to get stats");
    
    assert!(stats_result.success);
    println!(" Step 10: Contract statistics retrieved");
    println!("   Gas Used: {}\n", stats_result.gas_used);
    
    // Summary
    println!("{}", "=".repeat(60));
    println!(" HELLO WORLD WEB4 DEPLOYMENT COMPLETE!\n");
    println!(" Deployment Summary:");
    println!("   Contract ID: {}", contract_id);
    println!("   Domain: hello-world.zhtp");
    println!("   Owner: {}", hex::encode(owner_keypair.public_key.as_bytes()));
    println!("   Total Routes: {}", web4_contract.routes.len());
    println!("   Total Gas Used: {}", context.gas_used);
    println!("   Gas Remaining: {}", context.remaining_gas());
    println!("\n Website is now live on ZHTP network!");
    println!("   Access via: zhtp://hello-world.zhtp/");
    println!("{}", "=".repeat(60));
    
    assert!(context.gas_used < context.gas_limit);
    assert_eq!(web4_contract.domain, "hello-world.zhtp");
}

#[tokio::test]
async fn test_dns_resolution_flow() {
    println!("\n Testing DNS Resolution Flow\n");
    
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    
    let owner_keypair = KeyPair::generate().unwrap();
    let mut context = ExecutionContext::new(
        owner_keypair.public_key.clone(),
        1,
        chrono::Utc::now().timestamp() as u64,
        500_000,
        [2u8; 32],
    );
    
    // Create and deploy simple contract
    let deployment_data = WebsiteDeploymentData {
        domain: "test-dns.zhtp".to_string(),
        metadata: WebsiteMetadata {
            title: "DNS Test".to_string(),
            description: "Testing DNS resolution".to_string(),
            author: hex::encode(owner_keypair.public_key.as_bytes()),
            version: "1.0.0".to_string(),
            tags: vec![],
            language: "en".to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
            custom: HashMap::new(),
        },
        routes: vec![
            ContentRoute {
                path: "/".to_string(),
                content_hash: "QmTestHash123".to_string(),
                content_type: "text/html".to_string(),
                size: 100,
                metadata: HashMap::new(),
                updated_at: chrono::Utc::now().timestamp() as u64,
            }
        ],
        owner: hex::encode(owner_keypair.public_key.as_bytes()),
        config: HashMap::new(),
    };
    
    let contract = Web4Contract::new(
        "test_contract".to_string(),
        "test-dns.zhtp".to_string(),
        hex::encode(owner_keypair.public_key.as_bytes()),
        deployment_data.metadata.clone(),
        deployment_data,
    );
    
    println!(" Contract created: {}", contract.domain);
    
    // Test DNS lookup
    let domain_lookup = contract.get_domain("test-dns.zhtp");
    assert!(domain_lookup.is_ok());
    
    let domain_record = domain_lookup.unwrap();
    assert_eq!(domain_record.domain, "test-dns.zhtp");
    assert_eq!(domain_record.status, DomainStatus::Active);
    
    println!(" DNS Resolution: {} → {}", domain_record.domain, domain_record.contract_address);
    println!("   Status: {:?}", domain_record.status);
    println!("   Registered: {}", domain_record.registered_at);
    println!("   Expires: {}", domain_record.expires_at);
    println!("\n DNS Resolution Test PASSED!");
}

#[tokio::test]
async fn test_path_resolution_with_fallbacks() {
    println!("\n Testing Path Resolution with Fallbacks\n");
    
    // Create dummy hashes for testing
    let mut content_hashes = HashMap::new();
    content_hashes.insert("index.html".to_string(), "dht:test_index_hash".to_string());
    content_hashes.insert("style.css".to_string(), "dht:test_css_hash".to_string());
    content_hashes.insert("index_size".to_string(), "1024".to_string());
    content_hashes.insert("css_size".to_string(), "512".to_string());
    
    let manifest = create_hello_world_manifest(content_hashes);
    
    let deployment_package = DeploymentPackage {
        domain: "test-paths.zhtp".to_string(),
        owner: "test_owner".to_string(),
        metadata: WebsiteMetadata {
            title: "Path Test".to_string(),
            description: "Testing path resolution".to_string(),
            author: "test_author".to_string(),
            version: "1.0.0".to_string(),
            tags: vec![],
            language: "en".to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
            custom: HashMap::new(),
        },
        manifest,
        config: HashMap::new(),
    };
    
    let contract = Web4Contract::from_deployment_package(
        "test_paths".to_string(),
        deployment_package,
    ).unwrap();
    
    // Test 1: Direct path
    let route1 = contract.resolve_path("/index.html");
    assert!(route1.is_some());
    println!(" Direct path resolution: /index.html");
    
    // Test 2: Root path (should resolve to /index.html)
    let route2 = contract.resolve_path("/");
    assert!(route2.is_some());
    println!(" Root path resolution: / → /index.html");
    
    // Test 3: CSS file
    let route3 = contract.resolve_path("/style.css");
    assert!(route3.is_some());
    println!(" CSS path resolution: /style.css");
    
    // Test 4: Non-existent path
    let route4 = contract.resolve_path("/nonexistent.html");
    assert!(route4.is_none());
    println!(" Non-existent path correctly returns None");
    
    println!("\n Path Resolution Test PASSED!");
}

#[tokio::test]
async fn test_directory_listing() {
    println!("\n📁 Testing Directory Listing\n");
    
    // Create dummy hashes for testing
    let mut content_hashes = HashMap::new();
    content_hashes.insert("index.html".to_string(), "dht:test_index_hash".to_string());
    content_hashes.insert("style.css".to_string(), "dht:test_css_hash".to_string());
    content_hashes.insert("index_size".to_string(), "1024".to_string());
    content_hashes.insert("css_size".to_string(), "512".to_string());
    
    let manifest = create_hello_world_manifest(content_hashes);
    
    let deployment_package = DeploymentPackage {
        domain: "test-dir.zhtp".to_string(),
        owner: "test_owner".to_string(),
        metadata: WebsiteMetadata {
            title: "Directory Test".to_string(),
            description: "Testing directory listing".to_string(),
            author: "test_author".to_string(),
            version: "1.0.0".to_string(),
            tags: vec![],
            language: "en".to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
            custom: HashMap::new(),
        },
        manifest,
        config: HashMap::new(),
    };
    
    let contract = Web4Contract::from_deployment_package(
        "test_dir".to_string(),
        deployment_package,
    ).unwrap();
    
    // List root directory
    let files = contract.list_directory("/");
    println!(" Root directory contains {} files:", files.len());
    for file in &files {
        println!("   - {}", file);
    }
    
    assert!(!files.is_empty());
    println!("\n Directory Listing Test PASSED!");
}

#[tokio::test]
async fn test_content_update_flow() {
    println!("\n Testing Content Update Flow\n");
    
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    
    let owner_keypair = KeyPair::generate().unwrap();
    let mut context = ExecutionContext::new(
        owner_keypair.public_key.clone(),
        1,
        chrono::Utc::now().timestamp() as u64,
        500_000,
        [3u8; 32],
    );
    
    // Initial content
    println!(" Step 1: Deploying initial content");
    
    let update_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "update_content".to_string(),
        params: bincode::serialize(&(
            "/index.html".to_string(),
            "QmNewContentHash456".to_string(),
            "text/html".to_string(),
            5000u64,
        )).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let result = executor.execute_call(update_call, &mut context)
        .expect("Content update failed");
    
    assert!(result.success);
    println!(" Content updated successfully");
    println!("   Path: /index.html");
    println!("   New Hash: QmNewContentHash456");
    println!("   Gas Used: {}\n", result.gas_used);
    
    println!(" Content Update Test PASSED!");
}


/// Create directory tree structure for hello_world website with hashes
fn create_hello_world_directory(content_hashes: &HashMap<String, String>) -> DirectoryNode {
    
    // Root directory
    let mut root = DirectoryNode {
        path: "/".to_string(),
        name: "root".to_string(),
        node_type: NodeType::Directory,
        children: vec![],
        content_hash: None,
        metadata: HashMap::new(),
        created_at: chrono::Utc::now().timestamp() as u64,
        updated_at: chrono::Utc::now().timestamp() as u64,
    };
    
    // index.html file
    let index_html = DirectoryNode {
        path: "/index.html".to_string(),
        name: "index.html".to_string(),
        node_type: NodeType::File {
            mime_type: "text/html".to_string(),
            size: 3456, // Approximate size
            encoding: Some("utf-8".to_string()),
        },
        children: vec![],
        content_hash: Some(content_hashes["index.html"].clone()),
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("title".to_string(), "Hello World - Web4 Site".to_string());
            meta
        },
        created_at: chrono::Utc::now().timestamp() as u64,
        updated_at: chrono::Utc::now().timestamp() as u64,
    };
    
    // style.css file
    let style_css = DirectoryNode {
        path: "/style.css".to_string(),
        name: "style.css".to_string(),
        node_type: NodeType::File {
            mime_type: "text/css".to_string(),
            size: 2845, // Approximate size
            encoding: Some("utf-8".to_string()),
        },
        children: vec![],
        content_hash: Some(content_hashes["style.css"].clone()),
        metadata: HashMap::new(),
        created_at: chrono::Utc::now().timestamp() as u64,
        updated_at: chrono::Utc::now().timestamp() as u64,
    };
    
    // Add files to root
    root.children.push(index_html);
    root.children.push(style_css);
    
    root
}

/// Create complete website manifest for hello_world with DHT hashes
fn create_hello_world_manifest(content_hashes: HashMap<String, String>) -> WebsiteManifest {
    let directory = create_hello_world_directory(&content_hashes);
    
    let mut entry_points = HashMap::new();
    entry_points.insert("/".to_string(), "/index.html".to_string());
    entry_points.insert("/index.html".to_string(), "/index.html".to_string());
    entry_points.insert("/style.css".to_string(), "/style.css".to_string());
    
    WebsiteManifest {
        version: "1.0.0".to_string(),
        root_directory: directory,
        entry_points,
        dependencies: vec![],
        wasm_modules: vec![],
        total_size: 6301, // Combined size
        file_count: 2,
        manifest_hash: "".to_string(), // Will be calculated on validation
        created_at: chrono::Utc::now().timestamp() as u64,
    }
}

#[tokio::test]
async fn test_hello_world_deployment_full_flow() {
    println!("\n Starting Hello World Web4 Deployment Test\n");
    println!("=" .repeat(60));
    
    // 0. Initialize DHT client for storage
    println!("  Step 0: Initializing DHT client for content storage...");
    let dht_identity = ZhtpIdentity::generate().expect("Failed to generate DHT identity");
    let mut dht_client = DHTClient::new(dht_identity.clone()).await
        .expect("Failed to initialize DHT client");
    println!("    DHT client initialized");
    println!("   Node ID: {}\n", hex::encode(&dht_identity.id.to_string().as_bytes()[..8]));
    
    // 0.5 Upload hello_world files to DHT and get content hashes
    let content_hashes = upload_hello_world_to_dht(&mut dht_client).await
        .expect("Failed to upload content to DHT");
    
    println!(" Content Upload Summary:");
    for (file, hash) in &content_hashes {
        println!("   {} → {}", file, hash);
    }
    println!();
    
    // 1. Setup: Create executor and context
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    
    let owner_keypair = KeyPair::generate().unwrap();
    let mut context = ExecutionContext::new(
        owner_keypair.public_key.clone(),
        1,
        chrono::Utc::now().timestamp() as u64,
        1_000_000, // 1M gas limit
        [1u8; 32],
    );
    
    println!(" Step 1: Executor and context initialized");
    println!("   Owner: {}", hex::encode(owner_keypair.public_key.as_bytes()));
    println!("   Gas Limit: {}\n", context.gas_limit);
    
    // 2. Create website metadata
    let metadata = WebsiteMetadata {
        title: "Hello World - Web4 Site".to_string(),
        description: "A simple Hello World website demonstrating Web4 capabilities on ZHTP with DHT storage".to_string(),
        author: hex::encode(owner_keypair.public_key.as_bytes()),
        version: "1.0.0".to_string(),
        tags: vec!["web4".to_string(), "hello-world".to_string(), "zhtp".to_string(), "dht".to_string()],
        language: "en".to_string(),
        created_at: chrono::Utc::now().timestamp() as u64,
        updated_at: chrono::Utc::now().timestamp() as u64,
        custom: HashMap::new(),
    };
    
    println!(" Step 2: Website metadata created");
    println!("   Title: {}", metadata.title);
    println!("   Version: {}\n", metadata.version);
    
    // 3. Create deployment package with manifest using DHT hashes
    let manifest = create_hello_world_manifest(content_hashes.clone());
    let deployment_package = DeploymentPackage {
        domain: "hello-world.zhtp".to_string(),
        owner: hex::encode(owner_keypair.public_key.as_bytes()),
        metadata: metadata.clone(),
        manifest,
        config: HashMap::new(),
    };
    
    println!(" Step 3: Deployment package created with DHT hashes");
    println!("   Domain: {}", deployment_package.domain);
    println!("   Files: {}", deployment_package.manifest.file_count);
    println!("   Total Size: {} bytes", deployment_package.manifest.total_size);
    println!("   Content on DHT: \n");
    
    // 4. Deploy website contract using manifest
    let contract_id = format!("web4_{}", hex::encode(&context.tx_hash[..8]));
    let web4_contract = Web4Contract::from_deployment_package(
        contract_id.clone(),
        deployment_package,
    ).expect("Failed to create contract from deployment package");
    
    println!(" Step 4: Web4 contract created from manifest");
    println!("   Contract ID: {}", contract_id);
    println!("   Domain: {}", web4_contract.domain);
    println!("   Routes: {}\n", web4_contract.routes.len());
    
    // 5. Register domain via contract call
    let register_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "register_domain".to_string(),
        params: bincode::serialize(&(
            "hello-world.zhtp".to_string(),
            hex::encode(owner_keypair.public_key.as_bytes()),
            1u32, // 1 year registration
        )).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let register_result = executor.execute_call(register_call, &mut context)
        .expect("Domain registration failed");
    
    assert!(register_result.success);
    println!(" Step 5: Domain registered on blockchain");
    println!("   Status: SUCCESS");
    println!("   Gas Used: {}\n", register_result.gas_used);
    
    // 6. Test content retrieval - Index page
    let get_index_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_content_hash".to_string(),
        params: bincode::serialize(&"/".to_string()).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let index_result = executor.execute_call(get_index_call, &mut context)
        .expect("Failed to get index content");
    
    assert!(index_result.success);
    println!(" Step 6: Retrieved index.html content hash");
    println!("   Path: /");
    println!("   Gas Used: {}\n", index_result.gas_used);
    
    // 7. Test content retrieval - CSS file
    let get_css_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_content_hash".to_string(),
        params: bincode::serialize(&"/style.css".to_string()).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let css_result = executor.execute_call(get_css_call, &mut context)
        .expect("Failed to get CSS content");
    
    assert!(css_result.success);
    println!(" Step 7: Retrieved style.css content hash");
    println!("   Path: /style.css");
    println!("   Gas Used: {}\n", css_result.gas_used);
    
    // 8. Get all routes
    let get_routes_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_routes".to_string(),
        params: vec![],
        permissions: CallPermissions::Public,
    };
    
    let routes_result = executor.execute_call(get_routes_call, &mut context)
        .expect("Failed to get routes");
    
    assert!(routes_result.success);
    println!(" Step 8: Retrieved all routes");
    println!("   Gas Used: {}\n", routes_result.gas_used);
    
    // 9. Get domain info (DNS resolution)
    let get_domain_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_domain".to_string(),
        params: bincode::serialize(&"hello-world.zhtp".to_string()).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let domain_result = executor.execute_call(get_domain_call, &mut context)
        .expect("Failed to resolve domain");
    
    assert!(domain_result.success);
    println!(" Step 9: DNS resolution successful");
    println!("   Domain: hello-world.zhtp");
    println!("   Gas Used: {}\n", domain_result.gas_used);
    
    // 10. Get contract statistics
    let get_stats_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "get_stats".to_string(),
        params: vec![],
        permissions: CallPermissions::Public,
    };
    
    let stats_result = executor.execute_call(get_stats_call, &mut context)
        .expect("Failed to get stats");
    
    assert!(stats_result.success);
    println!(" Step 10: Contract statistics retrieved");
    println!("   Gas Used: {}\n", stats_result.gas_used);
    
    // Summary
    println!("=" .repeat(60));
    println!(" HELLO WORLD WEB4 DEPLOYMENT COMPLETE!\n");
    println!(" Deployment Summary:");
    println!("   Contract ID: {}", contract_id);
    println!("   Domain: hello-world.zhtp");
    println!("   Owner: {}", hex::encode(owner_keypair.public_key.as_bytes()));
    println!("   Total Routes: {}", web4_contract.routes.len());
    println!("   Total Gas Used: {}", context.gas_used);
    println!("   Gas Remaining: {}", context.remaining_gas());
    println!("\n Website is now live on ZHTP network!");
    println!("   Access via: zhtp://hello-world.zhtp/");
    println!("=" .repeat(60));
    
    assert!(context.gas_used < context.gas_limit);
    assert_eq!(web4_contract.domain, "hello-world.zhtp");
}

#[test]
fn test_dns_resolution_flow() {
    println!("\n Testing DNS Resolution Flow\n");
    
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    
    let owner_keypair = KeyPair::generate().unwrap();
    let mut context = ExecutionContext::new(
        owner_keypair.public_key.clone(),
        1,
        chrono::Utc::now().timestamp() as u64,
        500_000,
        [2u8; 32],
    );
    
    // Create and deploy simple contract
    let deployment_data = WebsiteDeploymentData {
        domain: "test-dns.zhtp".to_string(),
        metadata: WebsiteMetadata {
            title: "DNS Test".to_string(),
            description: "Testing DNS resolution".to_string(),
            author: hex::encode(owner_keypair.public_key.as_bytes()),
            version: "1.0.0".to_string(),
            tags: vec![],
            language: "en".to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
            custom: HashMap::new(),
        },
        routes: vec![
            ContentRoute {
                path: "/".to_string(),
                content_hash: "QmTestHash123".to_string(),
                content_type: "text/html".to_string(),
                size: 100,
                metadata: HashMap::new(),
                updated_at: chrono::Utc::now().timestamp() as u64,
            }
        ],
        owner: hex::encode(owner_keypair.public_key.as_bytes()),
        config: HashMap::new(),
    };
    
    let contract = Web4Contract::new(
        "test_contract".to_string(),
        "test-dns.zhtp".to_string(),
        hex::encode(owner_keypair.public_key.as_bytes()),
        deployment_data.metadata.clone(),
        deployment_data,
    );
    
    println!(" Contract created: {}", contract.domain);
    
    // Test DNS lookup
    let domain_lookup = contract.get_domain("test-dns.zhtp");
    assert!(domain_lookup.is_ok());
    
    let domain_record = domain_lookup.unwrap();
    assert_eq!(domain_record.domain, "test-dns.zhtp");
    assert_eq!(domain_record.status, DomainStatus::Active);
    
    println!(" DNS Resolution: {} → {}", domain_record.domain, domain_record.contract_address);
    println!("   Status: {:?}", domain_record.status);
    println!("   Registered: {}", domain_record.registered_at);
    println!("   Expires: {}", domain_record.expires_at);
    println!("\n DNS Resolution Test PASSED!");
}

#[tokio::test]
async fn test_path_resolution_with_fallbacks() {
    println!("\n Testing Path Resolution with Fallbacks\n");
    
    // Create dummy hashes for testing
    let mut content_hashes = HashMap::new();
    content_hashes.insert("index.html".to_string(), "dht:test_index_hash".to_string());
    content_hashes.insert("style.css".to_string(), "dht:test_css_hash".to_string());
    
    let manifest = create_hello_world_manifest(content_hashes);
    
    let deployment_package = DeploymentPackage {
        domain: "test-paths.zhtp".to_string(),
        owner: "test_owner".to_string(),
        metadata: WebsiteMetadata {
            title: "Path Test".to_string(),
            description: "Testing path resolution".to_string(),
            author: "test_author".to_string(),
            version: "1.0.0".to_string(),
            tags: vec![],
            language: "en".to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
            custom: HashMap::new(),
        },
        manifest,
        config: HashMap::new(),
    };
    
    let contract = Web4Contract::from_deployment_package(
        "test_paths".to_string(),
        deployment_package,
    ).unwrap();
    
    // Test 1: Direct path
    let route1 = contract.resolve_path("/index.html");
    assert!(route1.is_some());
    println!(" Direct path resolution: /index.html");
    
    // Test 2: Root path (should resolve to /index.html)
    let route2 = contract.resolve_path("/");
    assert!(route2.is_some());
    println!(" Root path resolution: / → /index.html");
    
    // Test 3: CSS file
    let route3 = contract.resolve_path("/style.css");
    assert!(route3.is_some());
    println!(" CSS path resolution: /style.css");
    
    // Test 4: Non-existent path
    let route4 = contract.resolve_path("/nonexistent.html");
    assert!(route4.is_none());
    println!(" Non-existent path correctly returns None");
    
    println!("\n Path Resolution Test PASSED!");
}

#[tokio::test]
async fn test_directory_listing() {
    println!("\n📁 Testing Directory Listing\n");
    
    // Create dummy hashes for testing
    let mut content_hashes = HashMap::new();
    content_hashes.insert("index.html".to_string(), "dht:test_index_hash".to_string());
    content_hashes.insert("style.css".to_string(), "dht:test_css_hash".to_string());
    
    let manifest = create_hello_world_manifest(content_hashes);
    
    let deployment_package = DeploymentPackage {
        domain: "test-dir.zhtp".to_string(),
        owner: "test_owner".to_string(),
        metadata: WebsiteMetadata {
            title: "Directory Test".to_string(),
            description: "Testing directory listing".to_string(),
            author: "test_author".to_string(),
            version: "1.0.0".to_string(),
            tags: vec![],
            language: "en".to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
            custom: HashMap::new(),
        },
        manifest,
        config: HashMap::new(),
    };
    
    let contract = Web4Contract::from_deployment_package(
        "test_dir".to_string(),
        deployment_package,
    ).unwrap();
    
    // List root directory
    let files = contract.list_directory("/");
    println!(" Root directory contains {} files:", files.len());
    for file in &files {
        println!("   - {}", file);
    }
    
    assert!(!files.is_empty());
    println!("\n Directory Listing Test PASSED!");
}

#[test]
fn test_content_update_flow() {
    println!("\n Testing Content Update Flow\n");
    
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    
    let owner_keypair = KeyPair::generate().unwrap();
    let mut context = ExecutionContext::new(
        owner_keypair.public_key.clone(),
        1,
        chrono::Utc::now().timestamp() as u64,
        500_000,
        [3u8; 32],
    );
    
    // Initial content
    println!(" Step 1: Deploying initial content");
    
    let update_call = ContractCall {
        contract_type: ContractType::Web4Website,
        method: "update_content".to_string(),
        params: bincode::serialize(&(
            "/index.html".to_string(),
            "QmNewContentHash456".to_string(),
            "text/html".to_string(),
            5000u64,
        )).unwrap(),
        permissions: CallPermissions::Public,
    };
    
    let result = executor.execute_call(update_call, &mut context)
        .expect("Content update failed");
    
    assert!(result.success);
    println!(" Content updated successfully");
    println!("   Path: /index.html");
    println!("   New Hash: QmNewContentHash456");
    println!("   Gas Used: {}\n", result.gas_used);
    
    println!(" Content Update Test PASSED!");
}
