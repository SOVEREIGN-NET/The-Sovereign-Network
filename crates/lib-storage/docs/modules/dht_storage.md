<<<<<<< HEAD
# DHT Storage Operations (`dht/storage.rs`)

The DHT Storage module implements the core key-value storage operations with cryptographic integrity, zero-knowledge privacy, and smart contract support. It provides the foundation for all storage operations in the ZHTP network.

##  Overview

The `DhtStorage` system provides:
- **Cryptographic Storage**: All data secured with BLAKE3 hashing and zero-knowledge proofs
- **Network Integration**: Automatic replication across DHT nodes
- **Smart Contract Support**: Store and execute WASM smart contracts
- **Integrity Verification**: Comprehensive data validation and proof systems
- **Capacity Management**: Automatic storage limit enforcement

## 🏗️ Core Structure

### DhtStorage

```rust
pub struct DhtStorage {
    /// Local storage for key-value pairs
    storage: HashMap<String, StorageEntry>,
    /// Maximum storage size per node (in bytes)  
    max_storage_size: u64,
    /// Current storage usage (in bytes)
    current_usage: u64,
    /// Local node ID
    local_node_id: NodeId,
    /// Network layer for DHT communication
    network: Option<DhtNetwork>,
    /// Kademlia router for finding closest nodes
    router: KademliaRouter,
    /// Messaging system for reliable communication
    messaging: DhtMessaging,
    /// Known DHT nodes
    known_nodes: HashMap<NodeId, DhtNode>,
    /// Contract index for fast discovery by tags and metadata
    contract_index: HashMap<String, Vec<String>>,
}
```

### StorageEntry

```rust
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub timestamp: u64,
    pub expiry: Option<u64>,
    pub metadata: ChunkMetadata,
    pub proof: Option<ZkProof>,
    pub replicas: Vec<NodeId>,
    pub access_control: Option<AccessControl>,
}
```

### ZkDhtValue (Zero-Knowledge Enhanced)

```rust
pub struct ZkDhtValue {
    pub encrypted_data: Vec<u8>,
    pub validity_proof: ZeroKnowledgeProof,
    pub access_level: AccessLevel,
    pub nonce: Vec<u8>,
}
```

##  Core Storage Operations

### Basic Storage Operations

#### store_data()
```rust
pub async fn store_data(&mut self, content_hash: Hash, data: Vec<u8>) -> Result<()>
```

Store data using content hash as key with automatic DHT replication.

**Example:**
```rust
let data = b"Hello, ZHTP Storage!".to_vec();
let content_hash = blake3::hash(&data);
let hash_key = Hash::from_bytes(content_hash.as_bytes());

storage.store_data(hash_key, data).await?;
```

#### retrieve_data()
```rust
pub async fn retrieve_data(&mut self, content_hash: Hash) -> Result<Option<Vec<u8>>>
```

Retrieve data by content hash, checking local storage first, then querying DHT.

**Example:**
```rust
if let Some(data) = storage.retrieve_data(content_hash).await? {
    println!("Retrieved {} bytes", data.len());
} else {
    println!("Content not found");
}
```

#### remove_data()
```rust
pub async fn remove_data(&mut self, content_hash: Hash) -> Result<bool>
```

Remove data from storage by content hash.

### Advanced Storage Operations

#### store()
```rust
pub async fn store(
    &mut self, 
    key: String, 
    value: Vec<u8>, 
    proof: Option<ZkProof>
) -> Result<()>
```

Store key-value pair with optional zero-knowledge proof verification.

**Example:**
```rust
let key = "user_document_123".to_string();
let data = document_bytes;
let zk_proof = generate_storage_proof(&key, &data)?;

storage.store(key, data, Some(zk_proof)).await?;
```

#### get()
```rust
pub async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>>
```

Retrieve value by key with automatic access tracking and expiry checking.

**Example:**
```rust
if let Some(data) = storage.get("user_document_123").await? {
    println!("Document retrieved: {} bytes", data.len());
}
```

##  Zero-Knowledge Storage

### store_zk_value()
```rust
pub async fn store_zk_value(&mut self, key: DhtKey, zk_value: ZkDhtValue) -> Result<()>
```

Store zero-knowledge enhanced value with cryptographic proof verification.

**Example:**
```rust
// Create ZK-enhanced value
let zk_value = ZkDhtValue {
    encrypted_data: encrypt_data(&sensitive_data, &encryption_key)?,
    validity_proof: generate_validity_proof(&data, &access_credentials)?,
    access_level: AccessLevel::Private,
    nonce: generate_crypto_nonce(),
};

// Store with ZK proof verification
storage.store_zk_value(content_key, zk_value).await?;
```

### retrieve_zk_value()
```rust
pub async fn retrieve_zk_value(&mut self, key: DhtKey) -> Result<Option<ZkDhtValue>>
```

Retrieve zero-knowledge value with automatic proof verification.

**Example:**
```rust
if let Some(zk_value) = storage.retrieve_zk_value(content_key).await? {
    // Proof is automatically verified during retrieval
    let decrypted_data = decrypt_data(&zk_value.encrypted_data, &decryption_key)?;
    println!("Retrieved secure data: {} bytes", decrypted_data.len());
}
```

### Zero-Knowledge Proof Verification

The system supports multiple proof types:

#### Storage Access Proofs
```rust
// Verify right to store/access data
let proof_valid = storage.verify_zk_proof(&zk_proof, &zk_value).await?;
```

#### Data Integrity Proofs  
```rust
// Prove data hasn't been tampered with
let integrity_proof = zk_system.prove_data_integrity(
    data_hash,
    original_hash,
    timestamp
)?;
```

#### Identity Proofs
```rust
// Verify user identity without revealing details
let identity_proof = zk_system.prove_identity(
    user_secret,
    public_commitment,
    access_level
)?;
```

## 🤖 Smart Contract Support

### Contract Deployment

#### handle_contract_deploy()
```rust
async fn handle_contract_deploy(
    &mut self, 
    contract_data: &ContractDhtData, 
    sender_id: &NodeId
)
```

Deploy smart contracts to the DHT with metadata indexing.

**Example:**
```rust
let contract_data = ContractDhtData {
    contract_id: "payment_processor_v1".to_string(),
    bytecode: Some(wasm_bytecode),
    metadata: Some(ContractMetadata {
        name: "Payment Processor".to_string(),
        version: "1.0.0".to_string(),
        description: "Automated payment processing contract".to_string(),
        tags: vec!["payment".to_string(), "automation".to_string()],
        author: "ZHTP Dev Team".to_string(),
    }),
    function_name: None,
    function_args: vec![],
};

// Deploy contract (handled automatically by DHT message processing)
storage.handle_contract_deploy(&contract_data, &deployer_node_id).await;
```

### Contract Operations

#### get_contract_bytecode()
```rust
pub async fn get_contract_bytecode(&mut self, contract_id: &str) -> Result<Option<Vec<u8>>>
```

Retrieve contract bytecode for execution.

#### get_contract_metadata()
```rust
pub async fn get_contract_metadata(
    &mut self, 
    contract_id: &str
) -> Result<Option<ContractMetadata>>
```

Get contract metadata and information.

#### find_contracts_by_tags()
```rust
pub async fn find_contracts_by_tags(
    &self, 
    tags: &[String], 
    limit: usize
) -> Result<Vec<String>>
```

Search for contracts by tags for discovery.

**Example:**
```rust
// Find all payment-related contracts
let payment_contracts = storage.find_contracts_by_tags(
    &["payment".to_string(), "escrow".to_string()], 
    10
).await?;

for contract_id in payment_contracts {
    if let Some(metadata) = storage.get_contract_metadata(&contract_id).await? {
        println!("Found contract: {} v{}", metadata.name, metadata.version);
    }
}
```

##  Network Integration

### DHT Replication

#### replicate_to_dht()
```rust
async fn replicate_to_dht(&mut self, key: &str, data: &[u8]) -> Result<()>
```

Automatically replicate data to closest DHT nodes.

**Process:**
1. **Find Closest Nodes**: Use Kademlia routing to find 3 closest nodes
2. **Send Store Messages**: Distribute data to selected nodes
3. **Verify Storage**: Confirm successful storage with acknowledgments
4. **Handle Failures**: Mark failed nodes and find alternatives

#### retrieve_from_dht()
```rust
async fn retrieve_from_dht(&mut self, key: &str) -> Result<Option<Vec<u8>>>
```

Query DHT network for content not available locally.

**Process:**
1. **Query Closest Nodes**: Ask closest nodes for content
2. **Follow Node References**: Discover additional nodes that might have content
3. **Verify Integrity**: Check content integrity upon retrieval
4. **Cache Locally**: Store retrieved content for future access

### Network Message Handling

#### start_network_processing()
```rust
pub async fn start_network_processing(&mut self) -> Result<()>
```

Start continuous network message processing loop.

**Handles:**
- **Store Messages**: Store data from other nodes
- **Find Value**: Respond to content queries
- **Find Node**: Provide routing information
- **Contract Messages**: Deploy, query, and execute smart contracts

##  Storage Management

### Capacity Management

#### Storage Limits
```rust
// Check capacity before storing
if self.current_usage + total_size > self.max_storage_size {
    return Err(anyhow!("Storage capacity exceeded"));
}
```

#### Storage Statistics
```rust
pub fn get_storage_stats(&self) -> StorageStats {
    StorageStats {
        total_entries: self.storage.len(),
        total_size: self.current_usage,
        available_space: self.max_storage_size - self.current_usage,
        max_capacity: self.max_storage_size,
        avg_access_count: self.calculate_avg_access_count(),
    }
}
```

### Data Lifecycle Management

#### cleanup_expired()
```rust
pub async fn cleanup_expired(&mut self) -> Result<usize>
```

Remove expired storage entries automatically.

#### set_expiry()
```rust
pub fn set_expiry(&mut self, key: &str, expiry: u64) -> Result<()>
```

Set expiration time for stored content.

**Example:**
```rust
// Set content to expire in 30 days
let expiry_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)?
    .as_secs() + (30 * 24 * 60 * 60);

storage.set_expiry("temporary_data", expiry_time)?;
```

##  Security and Integrity

### Cryptographic Features

#### Content Addressing
- **BLAKE3 Hashing**: Fast, secure content addressing
- **Collision Resistance**: Cryptographically secure hash function
- **Verification**: Automatic integrity checking on retrieval

#### Access Control
```rust
pub struct AccessControl {
    pub owner: NodeId,
    pub read_permissions: Vec<NodeId>,
    pub write_permissions: Vec<NodeId>,
    pub access_level: AccessLevel,
}
```

#### Proof Verification Pipeline
1. **Proof Validation**: Verify ZK proof structure and completeness
2. **Cryptographic Verification**: Use lib-proofs for proof verification
3. **Context Validation**: Ensure proof matches storage context
4. **Access Control**: Verify permissions for storage operation

### Data Integrity

#### Checksum Calculation
```rust
fn calculate_checksum(&self, data: &[u8]) -> Vec<u8> {
    let hash = blake3::hash(data);
    let node_authenticated_hash = blake3::hash(&[
        hash.as_bytes(),
        self.local_node_id.as_bytes(),
    ].concat());
    node_authenticated_hash.as_bytes().to_vec()
}
```

##  Testing and Development

### Unit Tests
```rust
#[tokio::test]
async fn test_store_and_retrieve() {
    let mut storage = DhtStorage::new_default();
    
    let key = "test_key".to_string();
    let value = b"test_value".to_vec();
    
    // Test storage
    storage.store(key.clone(), value.clone(), None).await.unwrap();
    
    // Test retrieval
    let retrieved = storage.get(&key).await.unwrap();
    assert_eq!(retrieved, Some(value));
}
```

### Integration Testing
- **Multi-Node Replication**: Test data replication across nodes
- **Network Failure Recovery**: Test automatic failure handling
- **Smart Contract Deployment**: Test contract storage and execution
- **Zero-Knowledge Operations**: Test ZK proof verification

##  Best Practices

### Storage Operations
```rust
// Always use content hashing for addressable content
let content_hash = blake3::hash(&data);
let key = Hash::from_bytes(content_hash.as_bytes());

// Include metadata for better management
let metadata = ChunkMetadata {
    chunk_id: hex::encode(&key.as_bytes()),
    size: data.len() as u64,
    checksum: calculate_checksum(&data),
    tier: StorageTier::Hot,
    // ... other fields
};
```

### Zero-Knowledge Operations
```rust
// Always verify proofs before storing sensitive data
if let Some(proof) = &zk_proof {
    if !storage.verify_zk_proof(proof, &zk_value).await? {
        return Err(anyhow!("Invalid zero-knowledge proof"));
    }
}
```

### Network Operations
```rust
// Handle network failures gracefully
match storage.store_data(hash, data.clone()).await {
    Ok(_) => println!("Data stored successfully"),
    Err(e) => {
        eprintln!("Storage failed: {}", e);
        // Implement retry logic or fallback storage
    }
}
```

---

=======
# DHT Storage Operations (`dht/storage.rs`)

The DHT Storage module implements the core key-value storage operations with cryptographic integrity, zero-knowledge privacy, and smart contract support. It provides the foundation for all storage operations in the ZHTP network.

##  Overview

The `DhtStorage` system provides:
- **Cryptographic Storage**: All data secured with BLAKE3 hashing and zero-knowledge proofs
- **Network Integration**: Automatic replication across DHT nodes
- **Smart Contract Support**: Store and execute WASM smart contracts
- **Integrity Verification**: Comprehensive data validation and proof systems
- **Capacity Management**: Automatic storage limit enforcement

## 🏗️ Core Structure

### DhtStorage

```rust
pub struct DhtStorage {
    /// Local storage for key-value pairs
    storage: HashMap<String, StorageEntry>,
    /// Maximum storage size per node (in bytes)  
    max_storage_size: u64,
    /// Current storage usage (in bytes)
    current_usage: u64,
    /// Local node ID
    local_node_id: NodeId,
    /// Network layer for DHT communication
    network: Option<DhtNetwork>,
    /// Kademlia router for finding closest nodes
    router: KademliaRouter,
    /// Messaging system for reliable communication
    messaging: DhtMessaging,
    /// Known DHT nodes
    known_nodes: HashMap<NodeId, DhtNode>,
    /// Contract index for fast discovery by tags and metadata
    contract_index: HashMap<String, Vec<String>>,
}
```

### StorageEntry

```rust
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub timestamp: u64,
    pub expiry: Option<u64>,
    pub metadata: ChunkMetadata,
    pub proof: Option<ZkProof>,
    pub replicas: Vec<NodeId>,
    pub access_control: Option<AccessControl>,
}
```

### ZkDhtValue (Zero-Knowledge Enhanced)

```rust
pub struct ZkDhtValue {
    pub encrypted_data: Vec<u8>,
    pub validity_proof: ZeroKnowledgeProof,
    pub access_level: AccessLevel,
    pub nonce: Vec<u8>,
}
```

##  Core Storage Operations

### Basic Storage Operations

#### store_data()
```rust
pub async fn store_data(&mut self, content_hash: Hash, data: Vec<u8>) -> Result<()>
```

Store data using content hash as key with automatic DHT replication.

**Example:**
```rust
let data = b"Hello, ZHTP Storage!".to_vec();
let content_hash = blake3::hash(&data);
let hash_key = Hash::from_bytes(content_hash.as_bytes());

storage.store_data(hash_key, data).await?;
```

#### retrieve_data()
```rust
pub async fn retrieve_data(&mut self, content_hash: Hash) -> Result<Option<Vec<u8>>>
```

Retrieve data by content hash, checking local storage first, then querying DHT.

**Example:**
```rust
if let Some(data) = storage.retrieve_data(content_hash).await? {
    println!("Retrieved {} bytes", data.len());
} else {
    println!("Content not found");
}
```

#### remove_data()
```rust
pub async fn remove_data(&mut self, content_hash: Hash) -> Result<bool>
```

Remove data from storage by content hash.

### Advanced Storage Operations

#### store()
```rust
pub async fn store(
    &mut self, 
    key: String, 
    value: Vec<u8>, 
    proof: Option<ZkProof>
) -> Result<()>
```

Store key-value pair with optional zero-knowledge proof verification.

**Example:**
```rust
let key = "user_document_123".to_string();
let data = document_bytes;
let zk_proof = generate_storage_proof(&key, &data)?;

storage.store(key, data, Some(zk_proof)).await?;
```

#### get()
```rust
pub async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>>
```

Retrieve value by key with automatic access tracking and expiry checking.

**Example:**
```rust
if let Some(data) = storage.get("user_document_123").await? {
    println!("Document retrieved: {} bytes", data.len());
}
```

##  Zero-Knowledge Storage

### store_zk_value()
```rust
pub async fn store_zk_value(&mut self, key: DhtKey, zk_value: ZkDhtValue) -> Result<()>
```

Store zero-knowledge enhanced value with cryptographic proof verification.

**Example:**
```rust
// Create ZK-enhanced value
let zk_value = ZkDhtValue {
    encrypted_data: encrypt_data(&sensitive_data, &encryption_key)?,
    validity_proof: generate_validity_proof(&data, &access_credentials)?,
    access_level: AccessLevel::Private,
    nonce: generate_crypto_nonce(),
};

// Store with ZK proof verification
storage.store_zk_value(content_key, zk_value).await?;
```

### retrieve_zk_value()
```rust
pub async fn retrieve_zk_value(&mut self, key: DhtKey) -> Result<Option<ZkDhtValue>>
```

Retrieve zero-knowledge value with automatic proof verification.

**Example:**
```rust
if let Some(zk_value) = storage.retrieve_zk_value(content_key).await? {
    // Proof is automatically verified during retrieval
    let decrypted_data = decrypt_data(&zk_value.encrypted_data, &decryption_key)?;
    println!("Retrieved secure data: {} bytes", decrypted_data.len());
}
```

### Zero-Knowledge Proof Verification

The system supports multiple proof types:

#### Storage Access Proofs
```rust
// Verify right to store/access data
let proof_valid = storage.verify_zk_proof(&zk_proof, &zk_value).await?;
```

#### Data Integrity Proofs  
```rust
// Prove data hasn't been tampered with
let integrity_proof = zk_system.prove_data_integrity(
    data_hash,
    original_hash,
    timestamp
)?;
```

#### Identity Proofs
```rust
// Verify user identity without revealing details
let identity_proof = zk_system.prove_identity(
    user_secret,
    public_commitment,
    access_level
)?;
```

## 🤖 Smart Contract Support

### Contract Deployment

#### handle_contract_deploy()
```rust
async fn handle_contract_deploy(
    &mut self, 
    contract_data: &ContractDhtData, 
    sender_id: &NodeId
)
```

Deploy smart contracts to the DHT with metadata indexing.

**Example:**
```rust
let contract_data = ContractDhtData {
    contract_id: "payment_processor_v1".to_string(),
    bytecode: Some(wasm_bytecode),
    metadata: Some(ContractMetadata {
        name: "Payment Processor".to_string(),
        version: "1.0.0".to_string(),
        description: "Automated payment processing contract".to_string(),
        tags: vec!["payment".to_string(), "automation".to_string()],
        author: "ZHTP Dev Team".to_string(),
    }),
    function_name: None,
    function_args: vec![],
};

// Deploy contract (handled automatically by DHT message processing)
storage.handle_contract_deploy(&contract_data, &deployer_node_id).await;
```

### Contract Operations

#### get_contract_bytecode()
```rust
pub async fn get_contract_bytecode(&mut self, contract_id: &str) -> Result<Option<Vec<u8>>>
```

Retrieve contract bytecode for execution.

#### get_contract_metadata()
```rust
pub async fn get_contract_metadata(
    &mut self, 
    contract_id: &str
) -> Result<Option<ContractMetadata>>
```

Get contract metadata and information.

#### find_contracts_by_tags()
```rust
pub async fn find_contracts_by_tags(
    &self, 
    tags: &[String], 
    limit: usize
) -> Result<Vec<String>>
```

Search for contracts by tags for discovery.

**Example:**
```rust
// Find all payment-related contracts
let payment_contracts = storage.find_contracts_by_tags(
    &["payment".to_string(), "escrow".to_string()], 
    10
).await?;

for contract_id in payment_contracts {
    if let Some(metadata) = storage.get_contract_metadata(&contract_id).await? {
        println!("Found contract: {} v{}", metadata.name, metadata.version);
    }
}
```

##  Network Integration

### DHT Replication

#### replicate_to_dht()
```rust
async fn replicate_to_dht(&mut self, key: &str, data: &[u8]) -> Result<()>
```

Automatically replicate data to closest DHT nodes.

**Process:**
1. **Find Closest Nodes**: Use Kademlia routing to find 3 closest nodes
2. **Send Store Messages**: Distribute data to selected nodes
3. **Verify Storage**: Confirm successful storage with acknowledgments
4. **Handle Failures**: Mark failed nodes and find alternatives

#### retrieve_from_dht()
```rust
async fn retrieve_from_dht(&mut self, key: &str) -> Result<Option<Vec<u8>>>
```

Query DHT network for content not available locally.

**Process:**
1. **Query Closest Nodes**: Ask closest nodes for content
2. **Follow Node References**: Discover additional nodes that might have content
3. **Verify Integrity**: Check content integrity upon retrieval
4. **Cache Locally**: Store retrieved content for future access

### Network Message Handling

#### start_network_processing()
```rust
pub async fn start_network_processing(&mut self) -> Result<()>
```

Start continuous network message processing loop.

**Handles:**
- **Store Messages**: Store data from other nodes
- **Find Value**: Respond to content queries
- **Find Node**: Provide routing information
- **Contract Messages**: Deploy, query, and execute smart contracts

##  Storage Management

### Capacity Management

#### Storage Limits
```rust
// Check capacity before storing
if self.current_usage + total_size > self.max_storage_size {
    return Err(anyhow!("Storage capacity exceeded"));
}
```

#### Storage Statistics
```rust
pub fn get_storage_stats(&self) -> StorageStats {
    StorageStats {
        total_entries: self.storage.len(),
        total_size: self.current_usage,
        available_space: self.max_storage_size - self.current_usage,
        max_capacity: self.max_storage_size,
        avg_access_count: self.calculate_avg_access_count(),
    }
}
```

### Data Lifecycle Management

#### cleanup_expired()
```rust
pub async fn cleanup_expired(&mut self) -> Result<usize>
```

Remove expired storage entries automatically.

#### set_expiry()
```rust
pub fn set_expiry(&mut self, key: &str, expiry: u64) -> Result<()>
```

Set expiration time for stored content.

**Example:**
```rust
// Set content to expire in 30 days
let expiry_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)?
    .as_secs() + (30 * 24 * 60 * 60);

storage.set_expiry("temporary_data", expiry_time)?;
```

##  Security and Integrity

### Cryptographic Features

#### Content Addressing
- **BLAKE3 Hashing**: Fast, secure content addressing
- **Collision Resistance**: Cryptographically secure hash function
- **Verification**: Automatic integrity checking on retrieval

#### Access Control
```rust
pub struct AccessControl {
    pub owner: NodeId,
    pub read_permissions: Vec<NodeId>,
    pub write_permissions: Vec<NodeId>,
    pub access_level: AccessLevel,
}
```

#### Proof Verification Pipeline
1. **Proof Validation**: Verify ZK proof structure and completeness
2. **Cryptographic Verification**: Use lib-proofs for proof verification
3. **Context Validation**: Ensure proof matches storage context
4. **Access Control**: Verify permissions for storage operation

### Data Integrity

#### Checksum Calculation
```rust
fn calculate_checksum(&self, data: &[u8]) -> Vec<u8> {
    let hash = blake3::hash(data);
    let node_authenticated_hash = blake3::hash(&[
        hash.as_bytes(),
        self.local_node_id.as_bytes(),
    ].concat());
    node_authenticated_hash.as_bytes().to_vec()
}
```

##  Testing and Development

### Unit Tests
```rust
#[tokio::test]
async fn test_store_and_retrieve() {
    let mut storage = DhtStorage::new_default();
    
    let key = "test_key".to_string();
    let value = b"test_value".to_vec();
    
    // Test storage
    storage.store(key.clone(), value.clone(), None).await.unwrap();
    
    // Test retrieval
    let retrieved = storage.get(&key).await.unwrap();
    assert_eq!(retrieved, Some(value));
}
```

### Integration Testing
- **Multi-Node Replication**: Test data replication across nodes
- **Network Failure Recovery**: Test automatic failure handling
- **Smart Contract Deployment**: Test contract storage and execution
- **Zero-Knowledge Operations**: Test ZK proof verification

##  Best Practices

### Storage Operations
```rust
// Always use content hashing for addressable content
let content_hash = blake3::hash(&data);
let key = Hash::from_bytes(content_hash.as_bytes());

// Include metadata for better management
let metadata = ChunkMetadata {
    chunk_id: hex::encode(&key.as_bytes()),
    size: data.len() as u64,
    checksum: calculate_checksum(&data),
    tier: StorageTier::Hot,
    // ... other fields
};
```

### Zero-Knowledge Operations
```rust
// Always verify proofs before storing sensitive data
if let Some(proof) = &zk_proof {
    if !storage.verify_zk_proof(proof, &zk_value).await? {
        return Err(anyhow!("Invalid zero-knowledge proof"));
    }
}
```

### Network Operations
```rust
// Handle network failures gracefully
match storage.store_data(hash, data.clone()).await {
    Ok(_) => println!("Data stored successfully"),
    Err(e) => {
        eprintln!("Storage failed: {}", e);
        // Implement retry logic or fallback storage
    }
}
```

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
The DHT Storage system provides a robust, secure, and scalable foundation for distributed storage operations with integrated smart contract support and zero-knowledge privacy features.