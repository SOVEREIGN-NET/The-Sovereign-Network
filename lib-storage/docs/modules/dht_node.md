<<<<<<< HEAD
# DHT Node Management (`dht/node.rs`)

The DHT Node Management module handles the lifecycle, capabilities, and reputation of nodes in the distributed hash table network. It provides the foundation for peer discovery, network health monitoring, and quality-based node selection.

##  Overview

The `DhtNodeManager` is responsible for:
- Managing local node information and capabilities
- Tracking reputation scores for network participants  
- Coordinating with storage and network layers
- Monitoring node performance and connectivity
- Handling node addition, removal, and maintenance

## 🏗️ Core Structure

### DhtNodeManager

```rust
pub struct DhtNodeManager {
    /// Local node information
    local_node: DhtNode,
    /// DHT storage with networking
    storage: Option<DhtStorage>,
    /// Direct network interface for advanced operations
    network: Option<DhtNetwork>,
    /// Node reputation tracking
    reputation_scores: HashMap<NodeId, u32>,
    /// Local nodes collection when storage is not available
    local_nodes: HashMap<NodeId, DhtNode>,
    /// Message statistics
    message_stats: MessageStats,
}
```

### DhtNode Structure

```rust
pub struct DhtNode {
    pub id: NodeId,                           // Cryptographic node identifier
    pub addresses: Vec<String>,               // Network addresses (IP:Port)
    pub public_key: PostQuantumSignature,    // Post-quantum cryptographic key
    pub last_seen: u64,                      // Last activity timestamp
    pub reputation: u32,                     // Reputation score (0-∞)
    pub storage_info: Option<StorageCapabilities>, // Storage capacity info
}
```

### StorageCapabilities

```rust
pub struct StorageCapabilities {
    pub available_space: u64,                // Available storage in bytes
    pub total_capacity: u64,                 // Total storage capacity
    pub price_per_gb_day: u64,              // Pricing in SOV tokens
    pub supported_tiers: Vec<StorageTier>,   // Supported storage tiers
    pub region: String,                      // Geographic region
    pub uptime: f64,                        // Historical uptime percentage
}
```

##  Key Operations

### Node Creation and Initialization

#### new()
```rust
pub fn new(local_id: NodeId, addresses: Vec<String>) -> Result<Self>
```

Creates a new DHT node manager with basic functionality.

**Example:**
```rust
let node_id = Hash::from_bytes(&[1u8; 32]);
let addresses = vec!["127.0.0.1:33442".to_string()];
let manager = DhtNodeManager::new(node_id, addresses)?;
```

#### new_with_network()
```rust
pub async fn new_with_network(
    local_id: NodeId, 
    addresses: Vec<String>,
    bind_addr: SocketAddr,
    max_storage_size: u64
) -> Result<Self>
```

Creates a DHT node manager with full networking capabilities.

**Example:**
```rust
let bind_addr = "127.0.0.1:33442".parse()?;
let manager = DhtNodeManager::new_with_network(
    node_id,
    addresses,
    bind_addr,
    1_000_000_000 // 1GB storage
).await?;
```

### Node Management

#### add_node()
```rust
pub async fn add_node(&mut self, node: DhtNode) -> Result<()>
```

Add a new node to the DHT network with connectivity testing.

**Example:**
```rust
let new_node = DhtNode {
    id: Hash::from_bytes(&[2u8; 32]),
    addresses: vec!["192.168.1.100:33442".to_string()],
    public_key: generate_post_quantum_key()?,
    last_seen: current_timestamp(),
    reputation: 1000, // Starting reputation
    storage_info: Some(StorageCapabilities {
        available_space: 500_000_000, // 500MB
        total_capacity: 1_000_000_000, // 1GB
        price_per_gb_day: 100,
        supported_tiers: vec![StorageTier::Hot, StorageTier::Warm],
        region: "US-East".to_string(),
        uptime: 0.95,
    }),
};

manager.add_node(new_node).await?;
```

#### get_node()
```rust
pub fn get_node(&self, node_id: &NodeId) -> Option<&DhtNode>
```

Retrieve node information by ID.

**Example:**
```rust
if let Some(node) = manager.get_node(&node_id) {
    println!("Node {} has {} bytes available", 
             hex::encode(&node.id.as_bytes()[..4]),
             node.storage_info.as_ref().unwrap().available_space);
}
```

### Reputation Management

#### update_reputation()
```rust
pub fn update_reputation(&mut self, node_id: &NodeId, delta: i32)
```

Update a node's reputation score based on performance.

**Example:**
```rust
// Reward good performance
manager.update_reputation(&node_id, 100);

// Penalize poor performance  
manager.update_reputation(&node_id, -200);
```

#### get_reputation()
```rust
pub fn get_reputation(&self, node_id: &NodeId) -> u32
```

Get current reputation score for a node.

**Reputation Scale:**
- **1000+**: Excellent reputation, preferred for important operations
- **500-999**: Good reputation, reliable for most operations
- **100-499**: Fair reputation, acceptable with monitoring
- **0-99**: Poor reputation, requires careful consideration

### Node Selection and Filtering

#### all_nodes()
```rust
pub fn all_nodes(&self) -> Vec<&DhtNode>
```

Get all known nodes in the network.

#### storage_nodes()
```rust
pub fn storage_nodes(&self) -> Vec<&DhtNode>
```

Get nodes that offer storage capabilities.

**Example:**
```rust
let storage_providers = manager.storage_nodes();
for node in storage_providers {
    if let Some(storage_info) = &node.storage_info {
        println!("Storage node {} offers {}GB at {} tokens/GB/day",
                 hex::encode(&node.id.as_bytes()[..4]),
                 storage_info.total_capacity / (1024*1024*1024),
                 storage_info.price_per_gb_day);
    }
}
```

#### high_reputation_nodes()
```rust
pub fn high_reputation_nodes(&self, min_reputation: u32) -> Vec<&DhtNode>
```

Get nodes with reputation above specified threshold.

**Example:**
```rust
// Get highly trusted nodes for critical operations
let trusted_nodes = manager.high_reputation_nodes(800);
println!("Found {} highly trusted nodes", trusted_nodes.len());
```

##  Statistics and Monitoring

### get_statistics()
```rust
pub fn get_statistics(&self) -> DhtStats
```

Get comprehensive DHT network statistics.

**Example:**
```rust
let stats = manager.get_statistics();
println!("DHT Network Statistics:");
println!("  Total nodes: {}", stats.total_nodes);
println!("  Total connections: {}", stats.total_connections);
println!("  Messages sent: {}", stats.total_messages_sent);
println!("  Messages received: {}", stats.total_messages_received);
println!("  Storage utilization: {:.1}%", stats.storage_utilization);
println!("  Network health: {:.2}", stats.network_health);
```

### DhtStats Structure
```rust
pub struct DhtStats {
    pub total_nodes: usize,
    pub total_connections: usize,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub routing_table_size: usize,
    pub storage_utilization: f64,
    pub network_health: f64,
}
```

##  Network Operations

### start_network_processing()
```rust
pub async fn start_network_processing(&mut self) -> Result<()>
```

Start background network message processing. Should be run in a separate task.

**Example:**
```rust
// Start network processing in background
let mut manager_clone = manager.clone();
tokio::spawn(async move {
    if let Err(e) = manager_clone.start_network_processing().await {
        eprintln!("Network processing error: {}", e);
    }
});
```

### perform_maintenance()
```rust
pub async fn perform_maintenance(&mut self) -> Result<()>
```

Perform periodic maintenance tasks including node health checks.

**Example:**
```rust
// Run maintenance every 5 minutes
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        if let Err(e) = manager.perform_maintenance().await {
            eprintln!("Maintenance error: {}", e);
        }
    }
});
```

### Direct Network Operations

#### ping_node()
```rust
pub async fn ping_node(&self, target: &DhtNode) -> Result<bool>
```

Ping a specific node to check connectivity.

#### send_network_message()
```rust
pub async fn send_network_message(
    &self, 
    target: &DhtNode, 
    message: DhtMessage
) -> Result<()>
```

Send a direct message to another node.

#### find_network_nodes()
```rust
pub async fn find_network_nodes(
    &self, 
    target: &DhtNode, 
    query_id: NodeId
) -> Result<Vec<DhtNode>>
```

Query a node for other nodes it knows about.

##  Security Features

### Node Authentication
- **Post-Quantum Keys**: All nodes use post-quantum cryptographic signatures
- **Identity Verification**: Nodes are authenticated using ZHTP identity system
- **Reputation Tracking**: Poor behavior results in reputation penalties

### Network Security
- **Message Verification**: All network messages are cryptographically signed
- **Replay Protection**: Timestamps prevent message replay attacks
- **DoS Protection**: Rate limiting and reputation-based filtering

##  Best Practices

### Node Selection
```rust
// Select high-reputation nodes for critical operations
let critical_nodes = manager.high_reputation_nodes(900);

// Select storage nodes with sufficient capacity
let suitable_storage = manager.storage_nodes()
    .into_iter()
    .filter(|node| {
        node.storage_info.as_ref()
            .map(|info| info.available_space > required_space)
            .unwrap_or(false)
    })
    .collect::<Vec<_>>();
```

### Reputation Management
```rust
// Reward successful operations
manager.update_reputation(&node_id, 50);

// Penalize failures proportionally
match error_severity {
    ErrorSeverity::Minor => manager.update_reputation(&node_id, -10),
    ErrorSeverity::Major => manager.update_reputation(&node_id, -100),
    ErrorSeverity::Critical => manager.update_reputation(&node_id, -500),
}
```

### Health Monitoring
```rust
// Regular health checks
let stats = manager.get_statistics();
if stats.network_health < 0.8 {
    eprintln!("Warning: Network health degraded to {:.2}", stats.network_health);
    // Take corrective action
}
```

##  Testing

### Unit Tests
```rust
#[tokio::test]
async fn test_node_management() {
    let node_id = Hash::from_bytes(&[1u8; 32]);
    let addresses = vec!["127.0.0.1:33442".to_string()];
    
    let mut manager = DhtNodeManager::new(node_id, addresses).unwrap();
    
    // Test node addition
    let test_node = create_test_node();
    manager.add_node(test_node.clone()).await.unwrap();
    
    // Verify node was added
    assert_eq!(manager.all_nodes().len(), 1);
    assert!(manager.get_node(&test_node.id).is_some());
}
```

### Integration Examples
- **Multi-Node Networks**: Test with multiple interconnected nodes
- **Failure Scenarios**: Test node failures and network partitions
- **Performance Tests**: Measure scaling characteristics
- **Security Tests**: Verify cryptographic operations and reputation system

---

=======
# DHT Node Management (`dht/node.rs`)

The DHT Node Management module handles the lifecycle, capabilities, and reputation of nodes in the distributed hash table network. It provides the foundation for peer discovery, network health monitoring, and quality-based node selection.

##  Overview

The `DhtNodeManager` is responsible for:
- Managing local node information and capabilities
- Tracking reputation scores for network participants  
- Coordinating with storage and network layers
- Monitoring node performance and connectivity
- Handling node addition, removal, and maintenance

## 🏗️ Core Structure

### DhtNodeManager

```rust
pub struct DhtNodeManager {
    /// Local node information
    local_node: DhtNode,
    /// DHT storage with networking
    storage: Option<DhtStorage>,
    /// Direct network interface for advanced operations
    network: Option<DhtNetwork>,
    /// Node reputation tracking
    reputation_scores: HashMap<NodeId, u32>,
    /// Local nodes collection when storage is not available
    local_nodes: HashMap<NodeId, DhtNode>,
    /// Message statistics
    message_stats: MessageStats,
}
```

### DhtNode Structure

```rust
pub struct DhtNode {
    pub id: NodeId,                           // Cryptographic node identifier
    pub addresses: Vec<String>,               // Network addresses (IP:Port)
    pub public_key: PostQuantumSignature,    // Post-quantum cryptographic key
    pub last_seen: u64,                      // Last activity timestamp
    pub reputation: u32,                     // Reputation score (0-∞)
    pub storage_info: Option<StorageCapabilities>, // Storage capacity info
}
```

### StorageCapabilities

```rust
pub struct StorageCapabilities {
    pub available_space: u64,                // Available storage in bytes
    pub total_capacity: u64,                 // Total storage capacity
    pub price_per_gb_day: u64,              // Pricing in SOV tokens
    pub supported_tiers: Vec<StorageTier>,   // Supported storage tiers
    pub region: String,                      // Geographic region
    pub uptime: f64,                        // Historical uptime percentage
}
```

##  Key Operations

### Node Creation and Initialization

#### new()
```rust
pub fn new(local_id: NodeId, addresses: Vec<String>) -> Result<Self>
```

Creates a new DHT node manager with basic functionality.

**Example:**
```rust
let node_id = Hash::from_bytes(&[1u8; 32]);
let addresses = vec!["127.0.0.1:33442".to_string()];
let manager = DhtNodeManager::new(node_id, addresses)?;
```

#### new_with_network()
```rust
pub async fn new_with_network(
    local_id: NodeId, 
    addresses: Vec<String>,
    bind_addr: SocketAddr,
    max_storage_size: u64
) -> Result<Self>
```

Creates a DHT node manager with full networking capabilities.

**Example:**
```rust
let bind_addr = "127.0.0.1:33442".parse()?;
let manager = DhtNodeManager::new_with_network(
    node_id,
    addresses,
    bind_addr,
    1_000_000_000 // 1GB storage
).await?;
```

### Node Management

#### add_node()
```rust
pub async fn add_node(&mut self, node: DhtNode) -> Result<()>
```

Add a new node to the DHT network with connectivity testing.

**Example:**
```rust
let new_node = DhtNode {
    id: Hash::from_bytes(&[2u8; 32]),
    addresses: vec!["192.168.1.100:33442".to_string()],
    public_key: generate_post_quantum_key()?,
    last_seen: current_timestamp(),
    reputation: 1000, // Starting reputation
    storage_info: Some(StorageCapabilities {
        available_space: 500_000_000, // 500MB
        total_capacity: 1_000_000_000, // 1GB
        price_per_gb_day: 100,
        supported_tiers: vec![StorageTier::Hot, StorageTier::Warm],
        region: "US-East".to_string(),
        uptime: 0.95,
    }),
};

manager.add_node(new_node).await?;
```

#### get_node()
```rust
pub fn get_node(&self, node_id: &NodeId) -> Option<&DhtNode>
```

Retrieve node information by ID.

**Example:**
```rust
if let Some(node) = manager.get_node(&node_id) {
    println!("Node {} has {} bytes available", 
             hex::encode(&node.id.as_bytes()[..4]),
             node.storage_info.as_ref().unwrap().available_space);
}
```

### Reputation Management

#### update_reputation()
```rust
pub fn update_reputation(&mut self, node_id: &NodeId, delta: i32)
```

Update a node's reputation score based on performance.

**Example:**
```rust
// Reward good performance
manager.update_reputation(&node_id, 100);

// Penalize poor performance  
manager.update_reputation(&node_id, -200);
```

#### get_reputation()
```rust
pub fn get_reputation(&self, node_id: &NodeId) -> u32
```

Get current reputation score for a node.

**Reputation Scale:**
- **1000+**: Excellent reputation, preferred for important operations
- **500-999**: Good reputation, reliable for most operations
- **100-499**: Fair reputation, acceptable with monitoring
- **0-99**: Poor reputation, requires careful consideration

### Node Selection and Filtering

#### all_nodes()
```rust
pub fn all_nodes(&self) -> Vec<&DhtNode>
```

Get all known nodes in the network.

#### storage_nodes()
```rust
pub fn storage_nodes(&self) -> Vec<&DhtNode>
```

Get nodes that offer storage capabilities.

**Example:**
```rust
let storage_providers = manager.storage_nodes();
for node in storage_providers {
    if let Some(storage_info) = &node.storage_info {
        println!("Storage node {} offers {}GB at {} tokens/GB/day",
                 hex::encode(&node.id.as_bytes()[..4]),
                 storage_info.total_capacity / (1024*1024*1024),
                 storage_info.price_per_gb_day);
    }
}
```

#### high_reputation_nodes()
```rust
pub fn high_reputation_nodes(&self, min_reputation: u32) -> Vec<&DhtNode>
```

Get nodes with reputation above specified threshold.

**Example:**
```rust
// Get highly trusted nodes for critical operations
let trusted_nodes = manager.high_reputation_nodes(800);
println!("Found {} highly trusted nodes", trusted_nodes.len());
```

##  Statistics and Monitoring

### get_statistics()
```rust
pub fn get_statistics(&self) -> DhtStats
```

Get comprehensive DHT network statistics.

**Example:**
```rust
let stats = manager.get_statistics();
println!("DHT Network Statistics:");
println!("  Total nodes: {}", stats.total_nodes);
println!("  Total connections: {}", stats.total_connections);
println!("  Messages sent: {}", stats.total_messages_sent);
println!("  Messages received: {}", stats.total_messages_received);
println!("  Storage utilization: {:.1}%", stats.storage_utilization);
println!("  Network health: {:.2}", stats.network_health);
```

### DhtStats Structure
```rust
pub struct DhtStats {
    pub total_nodes: usize,
    pub total_connections: usize,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub routing_table_size: usize,
    pub storage_utilization: f64,
    pub network_health: f64,
}
```

##  Network Operations

### start_network_processing()
```rust
pub async fn start_network_processing(&mut self) -> Result<()>
```

Start background network message processing. Should be run in a separate task.

**Example:**
```rust
// Start network processing in background
let mut manager_clone = manager.clone();
tokio::spawn(async move {
    if let Err(e) = manager_clone.start_network_processing().await {
        eprintln!("Network processing error: {}", e);
    }
});
```

### perform_maintenance()
```rust
pub async fn perform_maintenance(&mut self) -> Result<()>
```

Perform periodic maintenance tasks including node health checks.

**Example:**
```rust
// Run maintenance every 5 minutes
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        if let Err(e) = manager.perform_maintenance().await {
            eprintln!("Maintenance error: {}", e);
        }
    }
});
```

### Direct Network Operations

#### ping_node()
```rust
pub async fn ping_node(&self, target: &DhtNode) -> Result<bool>
```

Ping a specific node to check connectivity.

#### send_network_message()
```rust
pub async fn send_network_message(
    &self, 
    target: &DhtNode, 
    message: DhtMessage
) -> Result<()>
```

Send a direct message to another node.

#### find_network_nodes()
```rust
pub async fn find_network_nodes(
    &self, 
    target: &DhtNode, 
    query_id: NodeId
) -> Result<Vec<DhtNode>>
```

Query a node for other nodes it knows about.

##  Security Features

### Node Authentication
- **Post-Quantum Keys**: All nodes use post-quantum cryptographic signatures
- **Identity Verification**: Nodes are authenticated using ZHTP identity system
- **Reputation Tracking**: Poor behavior results in reputation penalties

### Network Security
- **Message Verification**: All network messages are cryptographically signed
- **Replay Protection**: Timestamps prevent message replay attacks
- **DoS Protection**: Rate limiting and reputation-based filtering

##  Best Practices

### Node Selection
```rust
// Select high-reputation nodes for critical operations
let critical_nodes = manager.high_reputation_nodes(900);

// Select storage nodes with sufficient capacity
let suitable_storage = manager.storage_nodes()
    .into_iter()
    .filter(|node| {
        node.storage_info.as_ref()
            .map(|info| info.available_space > required_space)
            .unwrap_or(false)
    })
    .collect::<Vec<_>>();
```

### Reputation Management
```rust
// Reward successful operations
manager.update_reputation(&node_id, 50);

// Penalize failures proportionally
match error_severity {
    ErrorSeverity::Minor => manager.update_reputation(&node_id, -10),
    ErrorSeverity::Major => manager.update_reputation(&node_id, -100),
    ErrorSeverity::Critical => manager.update_reputation(&node_id, -500),
}
```

### Health Monitoring
```rust
// Regular health checks
let stats = manager.get_statistics();
if stats.network_health < 0.8 {
    eprintln!("Warning: Network health degraded to {:.2}", stats.network_health);
    // Take corrective action
}
```

##  Testing

### Unit Tests
```rust
#[tokio::test]
async fn test_node_management() {
    let node_id = Hash::from_bytes(&[1u8; 32]);
    let addresses = vec!["127.0.0.1:33442".to_string()];
    
    let mut manager = DhtNodeManager::new(node_id, addresses).unwrap();
    
    // Test node addition
    let test_node = create_test_node();
    manager.add_node(test_node.clone()).await.unwrap();
    
    // Verify node was added
    assert_eq!(manager.all_nodes().len(), 1);
    assert!(manager.get_node(&test_node.id).is_some());
}
```

### Integration Examples
- **Multi-Node Networks**: Test with multiple interconnected nodes
- **Failure Scenarios**: Test node failures and network partitions
- **Performance Tests**: Measure scaling characteristics
- **Security Tests**: Verify cryptographic operations and reputation system

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
The DHT Node Management system provides a robust foundation for building reliable, secure, and performant distributed storage networks with built-in economic incentives and reputation tracking.