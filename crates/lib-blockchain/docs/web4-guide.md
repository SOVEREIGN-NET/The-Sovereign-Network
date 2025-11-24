# Web4 Decentralized Web Guide - lib-blockchain

## Overview

Web4 is the ZHTP blockchain's decentralized web hosting system, enabling fully decentralized websites stored on the blockchain with content distributed through DHT (Distributed Hash Table) storage. Unlike traditional web hosting, Web4 websites are censorship-resistant, always available, and truly owned by their creators.

## Core Concepts

### 1. Decentralized Domains

Web4 uses `.zhtp` domains that are registered and managed on the blockchain:

- **On-Chain Registration**: Domain ownership is recorded on the blockchain
- **Cryptographic Ownership**: Domain control through private key ownership
- **Transfer and Updates**: Domains can be transferred or updated by the owner
- **Hierarchical Structure**: Support for subdomains and domain hierarchies

### 2. Content Distribution

Website content is stored using a hybrid approach:

- **Blockchain Metadata**: Domain registration and routing information on-chain
- **DHT Content Storage**: Actual website files stored in distributed hash table
- **Content Addressing**: Files referenced by cryptographic hashes
- **Version Control**: Multiple versions of websites can coexist

### 3. Smart Contract Integration

Web4 is powered by smart contracts that handle:

- **Domain Management**: Registration, transfer, and expiration
- **Access Control**: Token-gated content and permission management
- **Content Routing**: Map domain paths to DHT content hashes
- **Economic Incentives**: Payments for hosting and bandwidth

## Getting Started

### 1. Deploy Web4 Contract

First, deploy a Web4 contract to manage your domains:

```rust
use lib_blockchain::contracts::{Web4Contract, ContractCall};
use lib_crypto::generate_keypair;

#[tokio::main]
async fn main() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    let deployer_keypair = generate_keypair()?;
    
    // Create and deploy Web4 contract
    let web4_contract = Web4Contract::new();
    let deployment_call = ContractCall::deploy_web4_contract(web4_contract);
    
    let result = blockchain.execute_contract_call(deployment_call, &deployer_keypair)?;
    println!("Web4 contract deployed at: {:?}", result.contract_address);
    
    Ok(())
}
```

### 2. Register a Domain

Register your `.zhtp` domain on the blockchain:

```rust
use lib_blockchain::contracts::ContractCall;

async fn register_domain(
    blockchain: &mut Blockchain,
    contract_address: [u8; 32],
    domain: &str,
    owner_keypair: &KeyPair,
) -> Result<()> {
    let register_call = ContractCall::register_web4_domain(
        contract_address,
        domain.to_string(),
    );
    
    let result = blockchain.execute_contract_call(register_call, owner_keypair)?;
    
    if result.success {
        println!("Domain '{}' registered successfully!", domain);
    } else {
        println!("Domain registration failed: {}", result.error.unwrap_or_default());
    }
    
    Ok(())
}

// Usage
register_domain(&mut blockchain, contract_address, "mysite.zhtp", &owner_keypair).await?;
```

### 3. Upload Website Content

Upload your website files to DHT storage:

```rust
use lib_storage::{UnifiedStorageSystem, UploadRequest};
use std::collections::HashMap;

async fn upload_website_content(
    storage: &mut UnifiedStorageSystem,
    website_files: HashMap<String, Vec<u8>>, // filename -> content
) -> Result<HashMap<String, ContentHash>> {
    let mut content_hashes = HashMap::new();
    
    for (filename, content) in website_files {
        let upload_request = UploadRequest {
            content,
            filename: filename.clone(),
            mime_type: get_mime_type(&filename),
            description: format!("Web4 website file: {}", filename),
            tags: vec!["web4".to_string(), "website".to_string()],
            encrypt: false, // Public website content
            compress: true,
            access_control: AccessControlSettings::public(),
            storage_requirements: ContentStorageRequirements::web4_default(),
        };
        
        let system_identity = create_system_identity().await?;
        let content_hash = storage.upload_content(upload_request, system_identity).await?;
        content_hashes.insert(filename, content_hash);
    }
    
    Ok(content_hashes)
}

// Example usage
let mut website_files = HashMap::new();
website_files.insert("index.html".to_string(), include_bytes!("../website/index.html").to_vec());
website_files.insert("style.css".to_string(), include_bytes!("../website/style.css").to_vec());
website_files.insert("app.js".to_string(), include_bytes!("../website/app.js").to_vec());

let content_hashes = upload_website_content(&mut storage_system, website_files).await?;
```

### 4. Create Website Manifest

Create a manifest that maps your domain to the content:

```rust
use lib_blockchain::contracts::{WebsiteManifest, RoutingRule, AccessControlList};

fn create_website_manifest(
    domain: &str,
    content_hashes: &HashMap<String, ContentHash>,
) -> WebsiteManifest {
    let routing_rules = vec![
        RoutingRule::new("/", content_hashes["index.html"].clone()),
        RoutingRule::new("/index.html", content_hashes["index.html"].clone()),
        RoutingRule::new("/style.css", content_hashes["style.css"].clone()),
        RoutingRule::new("/app.js", content_hashes["app.js"].clone()),
        RoutingRule::new_directory("/assets/", "assets/"),
    ];
    
    WebsiteManifest {
        domain: domain.to_string(),
        version: 1,
        routing_rules,
        access_control: AccessControlList::public(),
        metadata: WebsiteMetadata {
            title: "My Decentralized Website".to_string(),
            description: "A website hosted on ZHTP blockchain".to_string(),
            keywords: vec!["blockchain", "decentralized", "zhtp"],
            author: "Website Owner".to_string(),
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
        },
        default_content_type: "text/html".to_string(),
        error_pages: HashMap::from([
            (404, content_hashes.get("404.html").cloned().unwrap_or_default()),
            (500, content_hashes.get("500.html").cloned().unwrap_or_default()),
        ]),
    }
}
```

### 5. Deploy Website Manifest

Deploy the manifest to make your website live:

```rust
async fn deploy_website(
    blockchain: &mut Blockchain,
    contract_address: [u8; 32],
    domain: &str,
    manifest: WebsiteManifest,
    owner_keypair: &KeyPair,
) -> Result<()> {
    let deploy_call = ContractCall::deploy_web4_manifest(
        contract_address,
        domain.to_string(),
        manifest,
    );
    
    let result = blockchain.execute_contract_call(deploy_call, owner_keypair)?;
    
    if result.success {
        println!("Website deployed! Visit https://{}", domain);
    } else {
        println!("Deployment failed: {}", result.error.unwrap_or_default());
    }
    
    Ok(())
}

// Usage
let manifest = create_website_manifest("mysite.zhtp", &content_hashes);
deploy_website(&mut blockchain, contract_address, "mysite.zhtp", manifest, &owner_keypair).await?;
```

## Advanced Features

### 1. Subdomain Management

Create and manage subdomains for organized content:

```rust
use lib_blockchain::contracts::ContractCall;

async fn create_subdomain(
    blockchain: &mut Blockchain,
    contract_address: [u8; 32],
    parent_domain: &str,
    subdomain: &str,
    subdomain_manifest: WebsiteManifest,
    owner_keypair: &KeyPair,
) -> Result<()> {
    let full_subdomain = format!("{}.{}", subdomain, parent_domain);
    
    let subdomain_call = ContractCall::add_web4_subdomain(
        contract_address,
        full_subdomain.clone(),
        subdomain_manifest,
    );
    
    let result = blockchain.execute_contract_call(subdomain_call, owner_keypair)?;
    
    if result.success {
        println!("Subdomain '{}' created successfully!", full_subdomain);
    }
    
    Ok(())
}

// Example: Create blog.mysite.zhtp
let blog_manifest = create_blog_manifest(&blog_content_hashes);
create_subdomain(
    &mut blockchain,
    contract_address,
    "mysite.zhtp",
    "blog",
    blog_manifest,
    &owner_keypair,
).await?;
```

### 2. Token-Gated Content

Restrict access to content based on token ownership:

```rust
use lib_blockchain::contracts::{AccessControlList, TokenGate};

fn create_token_gated_manifest(
    domain: &str,
    content_hashes: &HashMap<String, ContentHash>,
    token_contract_address: [u8; 32],
    required_tokens: u64,
) -> WebsiteManifest {
    let token_gate = TokenGate {
        token_contract: token_contract_address,
        minimum_balance: required_tokens,
        gate_type: GateType::Balance,
    };
    
    let access_control = AccessControlList {
        public_read: false,
        token_gates: vec![token_gate],
        whitelist: vec![],
        blacklist: vec![],
    };
    
    WebsiteManifest {
        domain: domain.to_string(),
        version: 1,
        routing_rules: create_routing_rules(content_hashes),
        access_control, // Token-gated access
        metadata: WebsiteMetadata::default(),
        default_content_type: "text/html".to_string(),
        error_pages: HashMap::new(),
    }
}

// Deploy token-gated website
let gated_manifest = create_token_gated_manifest(
    "premium.zhtp",
    &premium_content_hashes,
    token_contract_address,
    100, // Require 100 tokens for access
);
```

### 3. Dynamic Content Updates

Update website content without changing the domain:

```rust
async fn update_website_content(
    blockchain: &mut Blockchain,
    storage: &mut UnifiedStorageSystem,
    contract_address: [u8; 32],
    domain: &str,
    new_files: HashMap<String, Vec<u8>>,
    owner_keypair: &KeyPair,
) -> Result<()> {
    // Upload new content to DHT
    let new_content_hashes = upload_website_content(storage, new_files).await?;
    
    // Create updated manifest
    let updated_manifest = create_website_manifest(domain, &new_content_hashes);
    
    // Update website
    let update_call = ContractCall::update_web4_content(
        contract_address,
        domain.to_string(),
        updated_manifest,
        2, // Version 2
    );
    
    let result = blockchain.execute_contract_call(update_call, owner_keypair)?;
    
    if result.success {
        println!("Website '{}' updated to version 2", domain);
    }
    
    Ok(())
}
```

### 4. Multi-Version Support

Maintain multiple versions of your website:

```rust
async fn deploy_versioned_website(
    blockchain: &mut Blockchain,
    contract_address: [u8; 32],
    domain: &str,
    manifest: WebsiteManifest,
    version: u32,
    owner_keypair: &KeyPair,
) -> Result<()> {
    let versioned_call = ContractCall::deploy_web4_manifest_version(
        contract_address,
        domain.to_string(),
        manifest,
        version,
    );
    
    blockchain.execute_contract_call(versioned_call, owner_keypair)?;
    
    // Users can access specific versions via version.domain.zhtp
    println!("Website version {} deployed at v{}.{}", version, version, domain);
    Ok(())
}

// Deploy multiple versions
deploy_versioned_website(&mut blockchain, contract_address, "mysite.zhtp", manifest_v1, 1, &owner_keypair).await?;
deploy_versioned_website(&mut blockchain, contract_address, "mysite.zhtp", manifest_v2, 2, &owner_keypair).await?;
```

## Website Gateway Integration

### 1. HTTP Gateway

Web4 websites are accessible through HTTP gateways that bridge to traditional browsers:

```rust
use lib_blockchain::web4::{GatewayServer, GatewayConfig};

async fn start_web4_gateway() -> Result<()> {
    let config = GatewayConfig {
        listen_address: "0.0.0.0:8080".to_string(),
        blockchain_node: "127.0.0.1:33445".to_string(),
        storage_node: "127.0.0.1:33446".to_string(),
        cache_size: 100 * 1024 * 1024, // 100MB cache
        enable_cors: true,
        enable_compression: true,
    };
    
    let mut gateway = GatewayServer::new(config).await?;
    
    println!("Web4 gateway started on http://0.0.0.0:8080");
    println!("Access Web4 sites at: http://domain.zhtp.localhost:8080");
    
    gateway.serve().await?;
    Ok(())
}
```

### 2. DNS Bridge

Bridge .zhtp domains with traditional DNS:

```rust
use lib_blockchain::web4::DnsBridge;

async fn setup_dns_bridge() -> Result<()> {
    let bridge = DnsBridge::new("8.8.8.8:53").await?; // Use Google DNS as upstream
    
    // Register .zhtp TLD
    bridge.register_tld("zhtp", "127.0.0.1:8080").await?;
    
    println!("DNS bridge configured for .zhtp domains");
    Ok(())
}
```

## Content Management

### 1. File Organization

Organize website files efficiently:

```rust
use std::path::Path;

fn organize_website_files(website_dir: &Path) -> HashMap<String, Vec<u8>> {
    let mut files = HashMap::new();
    
    // HTML files
    for html_file in glob(&format!("{}/**/*.html", website_dir.display())).unwrap() {
        if let Ok(path) = html_file {
            let content = std::fs::read(&path).unwrap();
            let relative_path = path.strip_prefix(website_dir).unwrap().display().to_string();
            files.insert(relative_path, content);
        }
    }
    
    // CSS files
    for css_file in glob(&format!("{}/**/*.css", website_dir.display())).unwrap() {
        if let Ok(path) = css_file {
            let content = std::fs::read(&path).unwrap();
            let relative_path = path.strip_prefix(website_dir).unwrap().display().to_string();
            files.insert(relative_path, content);
        }
    }
    
    // JavaScript files
    for js_file in glob(&format!("{}/**/*.js", website_dir.display())).unwrap() {
        if let Ok(path) = js_file {
            let content = std::fs::read(&path).unwrap();
            let relative_path = path.strip_prefix(website_dir).unwrap().display().to_string();
            files.insert(relative_path, content);
        }
    }
    
    // Images and other assets
    for asset_file in glob(&format!("{}/**/assets/**/*", website_dir.display())).unwrap() {
        if let Ok(path) = asset_file {
            if path.is_file() {
                let content = std::fs::read(&path).unwrap();
                let relative_path = path.strip_prefix(website_dir).unwrap().display().to_string();
                files.insert(relative_path, content);
            }
        }
    }
    
    files
}
```

### 2. Content Optimization

Optimize content for DHT storage:

```rust
use flate2::{Compression, write::GzEncoder};
use std::io::Write;

fn optimize_content(files: HashMap<String, Vec<u8>>) -> HashMap<String, Vec<u8>> {
    let mut optimized = HashMap::new();
    
    for (filename, content) in files {
        let optimized_content = match get_file_extension(&filename).as_str() {
            "html" => minify_html(&content),
            "css" => minify_css(&content),
            "js" => minify_javascript(&content),
            "json" => minify_json(&content),
            _ => content, // Don't optimize binary files
        };
        
        // Compress text files
        let final_content = if is_text_file(&filename) {
            compress_content(&optimized_content).unwrap_or(optimized_content)
        } else {
            optimized_content
        };
        
        optimized.insert(filename, final_content);
    }
    
    optimized
}

fn compress_content(content: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content)?;
    Ok(encoder.finish()?)
}
```

### 3. CDN Integration

Integrate with CDN for performance:

```rust
use lib_blockchain::web4::{CdnProvider, CdnConfig};

async fn setup_web4_cdn() -> Result<()> {
    let cdn_config = CdnConfig {
        providers: vec![
            CdnProvider::,
            CdnProvider::Storj,
            CdnProvider::Arweave,
        ],
        cache_duration: 3600, // 1 hour
        auto_sync: true,
        geographic_distribution: true,
    };
    
    let cdn = Web4Cdn::new(cdn_config).await?;
    
    // Automatically sync Web4 content to CDN providers
    cdn.sync_all_domains().await?;
    
    println!("CDN integration configured for Web4");
    Ok(())
}
```

## Performance Optimization

### 1. Caching Strategies

Implement efficient caching:

```rust
use lib_blockchain::web4::Cache;

struct Web4Cache {
    content_cache: HashMap<ContentHash, Vec<u8>>,
    manifest_cache: HashMap<String, WebsiteManifest>,
    dns_cache: HashMap<String, [u8; 32]>,
    max_size: usize,
}

impl Web4Cache {
    fn new(max_size: usize) -> Self {
        Self {
            content_cache: HashMap::new(),
            manifest_cache: HashMap::new(),
            dns_cache: HashMap::new(),
            max_size,
        }
    }
    
    fn get_content(&self, hash: &ContentHash) -> Option<&Vec<u8>> {
        self.content_cache.get(hash)
    }
    
    fn cache_content(&mut self, hash: ContentHash, content: Vec<u8>) {
        if self.estimate_size() + content.len() > self.max_size {
            self.evict_oldest();
        }
        self.content_cache.insert(hash, content);
    }
    
    fn get_manifest(&self, domain: &str) -> Option<&WebsiteManifest> {
        self.manifest_cache.get(domain)
    }
    
    fn cache_manifest(&mut self, domain: String, manifest: WebsiteManifest) {
        self.manifest_cache.insert(domain, manifest);
    }
}
```

### 2. Preloading Content

Preload frequently accessed content:

```rust
async fn preload_popular_content(
    storage: &UnifiedStorageSystem,
    cache: &mut Web4Cache,
    popular_domains: Vec<String>,
) -> Result<()> {
    for domain in popular_domains {
        // Get domain manifest
        let manifest = resolve_domain_manifest(&domain).await?;
        
        // Preload core content files
        for rule in &manifest.routing_rules {
            if is_core_file(&rule.path) {
                let content = storage.download_content(DownloadRequest {
                    content_hash: rule.content_hash.clone(),
                    requester: create_system_identity().await?,
                    version: None,
                }).await?;
                
                cache.cache_content(rule.content_hash.clone(), content);
            }
        }
        
        cache.cache_manifest(domain, manifest);
    }
    
    Ok(())
}

fn is_core_file(path: &str) -> bool {
    matches!(path, "/" | "/index.html" | "/style.css" | "/app.js")
}
```

## Security Considerations

### 1. Content Validation

Validate uploaded content for security:

```rust
use lib_blockchain::web4::ContentValidator;

fn validate_website_content(files: &HashMap<String, Vec<u8>>) -> Result<()> {
    let validator = ContentValidator::new();
    
    for (filename, content) in files {
        // Check file size limits
        if content.len() > 10 * 1024 * 1024 {
            return Err(anyhow::anyhow!("File {} exceeds 10MB limit", filename));
        }
        
        // Validate content based on file type
        match get_file_extension(filename).as_str() {
            "html" => validator.validate_html(content)?,
            "css" => validator.validate_css(content)?,
            "js" => validator.validate_javascript(content)?,
            "svg" => validator.validate_svg(content)?,
            _ => {}, // Allow other file types
        }
        
        // Scan for malicious content
        if validator.scan_for_malware(content)? {
            return Err(anyhow::anyhow!("Malicious content detected in {}", filename));
        }
    }
    
    Ok(())
}
```

### 2. Access Control

Implement robust access controls:

```rust
use lib_blockchain::web4::AccessController;

async fn check_access_permissions(
    domain: &str,
    visitor_address: Option<[u8; 32]>,
    access_control: &AccessControlList,
) -> Result<bool> {
    // Check public access
    if access_control.public_read {
        return Ok(true);
    }
    
    // Check if visitor is in whitelist
    if let Some(address) = visitor_address {
        if access_control.whitelist.contains(&address) {
            return Ok(true);
        }
        
        // Check if visitor is blacklisted
        if access_control.blacklist.contains(&address) {
            return Ok(false);
        }
        
        // Check token gates
        for token_gate in &access_control.token_gates {
            let balance = get_token_balance(token_gate.token_contract, address).await?;
            if balance >= token_gate.minimum_balance {
                return Ok(true);
            }
        }
    }
    
    Ok(false)
}
```

## Monitoring and Analytics

### 1. Website Analytics

Track website usage and performance:

```rust
use lib_blockchain::web4::Analytics;

struct Web4Analytics {
    page_views: HashMap<String, u64>,
    visitor_count: HashMap<String, HashSet<[u8; 32]>>,
    bandwidth_usage: HashMap<String, u64>,
    response_times: HashMap<String, Vec<u64>>,
}

impl Web4Analytics {
    fn record_page_view(&mut self, domain: &str, path: &str, visitor: Option<[u8; 32]>) {
        let key = format!("{}:{}", domain, path);
        *self.page_views.entry(key).or_insert(0) += 1;
        
        if let Some(visitor_addr) = visitor {
            self.visitor_count.entry(domain.to_string()).or_insert_with(HashSet::new).insert(visitor_addr);
        }
    }
    
    fn record_bandwidth(&mut self, domain: &str, bytes: u64) {
        *self.bandwidth_usage.entry(domain.to_string()).or_insert(0) += bytes;
    }
    
    fn record_response_time(&mut self, domain: &str, response_time_ms: u64) {
        self.response_times.entry(domain.to_string()).or_insert_with(Vec::new).push(response_time_ms);
    }
    
    fn get_analytics_summary(&self, domain: &str) -> AnalyticsSummary {
        let total_views = self.page_views.iter()
            .filter(|(k, _)| k.starts_with(domain))
            .map(|(_, v)| *v)
            .sum();
        
        let unique_visitors = self.visitor_count.get(domain).map(|v| v.len()).unwrap_or(0);
        let total_bandwidth = self.bandwidth_usage.get(domain).copied().unwrap_or(0);
        
        let avg_response_time = self.response_times.get(domain)
            .and_then(|times| {
                if times.is_empty() {
                    None
                } else {
                    Some(times.iter().sum::<u64>() / times.len() as u64)
                }
            })
            .unwrap_or(0);
        
        AnalyticsSummary {
            domain: domain.to_string(),
            total_page_views: total_views,
            unique_visitors,
            total_bandwidth_bytes: total_bandwidth,
            average_response_time_ms: avg_response_time,
        }
    }
}
```

## Best Practices

### 1. Domain Management

- **Choose Memorable Names**: Use clear, memorable domain names
- **Secure Your Keys**: Protect your domain ownership keys
- **Regular Backups**: Back up your content and manifests
- **Monitor Expiration**: Keep track of domain expiration dates

### 2. Content Optimization

- **Minimize File Sizes**: Compress and minify content
- **Optimize Images**: Use appropriate image formats and compression
- **Use CDN**: Leverage CDN integration for global performance
- **Cache Strategy**: Implement intelligent caching

### 3. Security

- **Validate Uploads**: Always validate content before uploading
- **Access Controls**: Use appropriate access restrictions
- **Regular Updates**: Keep manifests and content updated
- **Monitor Access**: Track and monitor website access patterns

### 4. Performance

- **Preload Content**: Preload critical content for faster access
- **Batch Operations**: Group related operations together
- **Efficient Routing**: Optimize routing rules for common patterns
- **Monitor Metrics**: Track performance metrics and optimize accordingly

## Troubleshooting

### Common Issues

1. **Domain Registration Failed**: Check ownership and fees
2. **Content Upload Failed**: Verify file sizes and DHT connectivity
3. **Website Not Loading**: Check manifest deployment and content hashes
4. **Access Denied**: Verify token balances and access controls
5. **Slow Loading**: Check CDN configuration and caching

### Debugging Tools

```rust
use lib_blockchain::web4::DebugTools;

async fn debug_web4_domain(domain: &str) -> Result<()> {
    let debug = DebugTools::new().await?;
    
    // Check domain registration
    let domain_info = debug.check_domain_registration(domain).await?;
    println!("Domain info: {:?}", domain_info);
    
    // Check manifest deployment
    let manifest_status = debug.check_manifest_status(domain).await?;
    println!("Manifest status: {:?}", manifest_status);
    
    // Test content resolution
    let content_test = debug.test_content_resolution(domain, "/").await?;
    println!("Content test: {:?}", content_test);
    
    // Check gateway connectivity
    let gateway_test = debug.test_gateway_connectivity().await?;
    println!("Gateway test: {:?}", gateway_test);
    
    Ok(())
}
```