# Integration Guide

This guide covers integrating lib-proofs with the SOVEREIGN_NET ecosystem and other components.

## Integration with lib-crypto

### Setting Up Dependencies

```toml
[dependencies]
lib-proofs = { path = "../lib-proofs" }
lib-crypto = { path = "../lib-crypto" }
anyhow = "1.0"
```

### Using ZK Proofs with Cryptographic Keys

```rust
use lib_crypto::KeyPair;
use lib_proofs::zk_integration;
use anyhow::Result;

fn crypto_integration_example() -> Result<()> {
    // Generate cryptographic keypair
    let keypair = KeyPair::generate()?;
    
    // Use the keypair with ZK proofs
    let identity_proof = zk_integration::prove_identity(
        &keypair.private_key,
        25,   // age
        840,  // jurisdiction (US)
        9999, // credential hash
        18,   // min age requirement
        840,  // required jurisdiction
    )?;
    
    println!("Identity proof generated using crypto keypair");
    Ok(())
}
```

### Key Derivation and ZK Proofs

```rust
use lib_crypto::KeyPair;
use lib_proofs::zk_integration;

fn key_derivation_integration() -> Result<()> {
    let master_keypair = KeyPair::generate()?;
    
    // Derive specialized keys for ZK proofs
    // Note: This example shows the intended pattern
    // Actual key derivation methods may need to be implemented
    
    // Use master key material for ZK proof generation
    let proof = zk_integration::prove_pqc_key_properties(&master_keypair.private_key)?;
    
    println!("PQC key properties proven with ZK");
    Ok(())
}
```

## Blockchain Integration

### Transaction Privacy

```rust
use lib_proofs::ZkProofSystem;
use lib_crypto::KeyPair;

struct PrivateTransaction {
    sender_keypair: KeyPair,
    receiver_public_key: lib_crypto::PublicKey,
    amount: u64,
    fee: u64,
}

impl PrivateTransaction {
    fn generate_proof(&self) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        let zk_system = ZkProofSystem::new()?;
        
        // In a implementation, you'd derive these from the keypairs
        let sender_balance = 1000; // Retrieved from blockchain state
        let sender_secret = 12345;  // Derived from keypair
        let nullifier_seed = 67890; // Generated deterministically
        
        zk_system.prove_transaction(
            sender_balance,
            self.amount,
            self.fee,
            sender_secret,
            nullifier_seed,
        )
    }
    
    fn submit_to_blockchain(&self) -> Result<()> {
        let proof = self.generate_proof()?;
        
        // Serialize proof for blockchain submission
        let proof_data = bincode::serialize(&proof)?;
        
        // Submit to blockchain (pseudo-code)
        // blockchain.submit_private_transaction(proof_data)?;
        
        println!("Private transaction submitted with proof");
        println!("Proof size: {} bytes", proof_data.len());
        
        Ok(())
    }
}
```

### Smart Contract Integration

```rust
use lib_proofs::{ZkProofSystem, types::ZkProof};

pub struct SmartContractContext {
    zk_system: ZkProofSystem,
}

impl SmartContractContext {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
        })
    }
    
    pub fn verify_contract_execution(&self, proof: &ZkProof) -> Result<bool> {
        // Verify proof matches expected contract constraints
        proof.verify()
    }
    
    pub fn execute_private_contract(
        &self,
        contract_data: &[u8],
        private_inputs: &[u64],
        public_inputs: &[u64],
    ) -> Result<ZkProof> {
        // Generate proof of correct contract execution
        ZkProof::from_public_inputs(public_inputs.to_vec())
    }
}
```

### Consensus Integration

```rust
use lib_proofs::{ZkProofSystem, verifiers::RecursiveProofAggregator};

pub struct ConsensusValidator {
    zk_system: ZkProofSystem,
    aggregator: RecursiveProofAggregator,
}

impl ConsensusValidator {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
            aggregator: RecursiveProofAggregator::new()?,
        })
    }
    
    pub fn validate_block_proofs(&self, proofs: &[lib_proofs::plonky2::Plonky2Proof]) -> Result<bool> {
        // Validate individual transaction proofs
        for proof in proofs {
            if !self.zk_system.verify_transaction(proof)? {
                return Ok(false);
            }
        }
        
        // Aggregate proofs for efficient verification
        // let aggregated = self.aggregator.aggregate_proofs(proofs)?;
        
        Ok(true)
    }
}
```

## Mesh Network Integration

### Anonymous Routing

```rust
use lib_proofs::ZkProofSystem;

pub struct MeshRouter {
    zk_system: ZkProofSystem,
    node_id: u64,
}

impl MeshRouter {
    pub fn new(node_id: u64) -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
            node_id,
        })
    }
    
    pub fn prove_routing_capability(
        &self,
        destination: u64,
        max_hops: u64,
        min_bandwidth: u64,
    ) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        // Generate proof that this node can route to destination
        // without revealing the exact path or node capabilities
        
        let hop_count = 3; // Actual hop count (private)
        let bandwidth = 1000; // Available bandwidth (private)
        let latency = 50; // Route latency (private)
        let routing_secret = 99999; // Node's routing secret (private)
        
        self.zk_system.prove_routing(
            self.node_id,
            destination,
            hop_count,
            bandwidth,
            latency,
            routing_secret,
            max_hops,
            min_bandwidth,
        )
    }
    
    pub fn verify_route_proof(&self, proof: &lib_proofs::plonky2::Plonky2Proof) -> Result<bool> {
        self.zk_system.verify_routing(proof)
    }
}
```

### Data Storage Proofs

```rust
use lib_proofs::ZkProofSystem;

pub struct DistributedStorage {
    zk_system: ZkProofSystem,
}

impl DistributedStorage {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
        })
    }
    
    pub fn prove_data_storage(
        &self,
        data_hash: u64,
        storage_node_secret: u64,
    ) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        // Prove data is stored correctly without revealing data content
        
        let chunk_count = 100;
        let total_size = 1048576; // 1MB
        let checksum = 0xDEADBEEF;
        let timestamp = 1672531200;
        let max_chunks = 1000;
        let max_size = 10485760; // 10MB
        
        self.zk_system.prove_data_integrity(
            data_hash,
            chunk_count,
            total_size,
            checksum,
            storage_node_secret,
            timestamp,
            max_chunks,
            max_size,
        )
    }
    
    pub fn verify_storage_proof(&self, proof: &lib_proofs::plonky2::Plonky2Proof) -> Result<bool> {
        self.zk_system.verify_data_integrity(proof)
    }
}
```

## Identity and Access Management

### Decentralized Identity

```rust
use lib_crypto::KeyPair;
use lib_proofs::zk_integration;

pub struct DecentralizedIdentity {
    keypair: KeyPair,
    age: u64,
    jurisdiction: u64,
    credentials: Vec<u64>,
}

impl DecentralizedIdentity {
    pub fn new(age: u64, jurisdiction: u64) -> Result<Self> {
        Ok(Self {
            keypair: KeyPair::generate()?,
            age,
            jurisdiction,
            credentials: Vec::new(),
        })
    }
    
    pub fn prove_age_requirement(&self, min_age: u64) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        zk_integration::prove_identity(
            &self.keypair.private_key,
            self.age,
            self.jurisdiction,
            9999, // credential hash
            min_age,
            0, // no jurisdiction requirement
        )
    }
    
    pub fn prove_jurisdiction(&self, required_jurisdiction: u64) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        zk_integration::prove_identity(
            &self.keypair.private_key,
            self.age,
            self.jurisdiction,
            9999, // credential hash
            0, // no age requirement
            required_jurisdiction,
        )
    }
    
    pub fn prove_full_identity(
        &self,
        min_age: u64,
        required_jurisdiction: u64,
    ) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        zk_integration::prove_identity(
            &self.keypair.private_key,
            self.age,
            self.jurisdiction,
            9999, // credential hash
            min_age,
            required_jurisdiction,
        )
    }
}
```

### Access Control

```rust
use lib_proofs::ZkProofSystem;

pub struct AccessControlSystem {
    zk_system: ZkProofSystem,
}

impl AccessControlSystem {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
        })
    }
    
    pub fn prove_access_rights(
        &self,
        user_secret: u64,
        resource_hash: u64,
        user_permission_level: u64,
        required_permission: u64,
    ) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        let access_key = 11111; // Derived from user credentials
        
        self.zk_system.prove_storage_access(
            access_key,
            user_secret,
            resource_hash,
            user_permission_level,
            required_permission,
        )
    }
    
    pub fn verify_access(&self, proof: &lib_proofs::plonky2::Plonky2Proof) -> Result<bool> {
        self.zk_system.verify_storage_access(proof)
    }
}
```

## Cross-Component Communication

### Proof Serialization

```rust
use lib_proofs::types::ZkProof;
use serde_json;

pub fn serialize_proof(proof: &ZkProof) -> Result<Vec<u8>> {
    // Binary serialization for efficiency
    bincode::serialize(proof).map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))
}

pub fn deserialize_proof(data: &[u8]) -> Result<ZkProof> {
    bincode::deserialize(data).map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))
}

pub fn proof_to_json(proof: &ZkProof) -> Result<String> {
    // JSON serialization for debugging/APIs
    serde_json::to_string(proof).map_err(|e| anyhow::anyhow!("JSON serialization failed: {}", e))
}

pub fn proof_from_json(json: &str) -> Result<ZkProof> {
    serde_json::from_str(json).map_err(|e| anyhow::anyhow!("JSON deserialization failed: {}", e))
}
```

### Network Protocol Integration

```rust
use lib_proofs::types::ZkProof;

pub struct NetworkMessage {
    pub message_type: String,
    pub proof: Option<ZkProof>,
    pub data: Vec<u8>,
}

impl NetworkMessage {
    pub fn new_with_proof(message_type: String, proof: ZkProof, data: Vec<u8>) -> Self {
        Self {
            message_type,
            proof: Some(proof),
            data,
        }
    }
    
    pub fn verify_message(&self) -> Result<bool> {
        match &self.proof {
            Some(proof) => proof.verify(),
            None => Ok(true), // No proof required
        }
    }
    
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!("Message serialization failed: {}", e))
    }
    
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow::anyhow!("Message deserialization failed: {}", e))
    }
}
```

## Performance Optimization

### Batch Processing

```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof};
use std::time::Instant;

pub struct BatchProcessor {
    zk_system: ZkProofSystem,
}

impl BatchProcessor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
        })
    }
    
    pub fn process_transaction_batch(&self, transactions: &[TransactionData]) -> Result<Vec<lib_proofs::plonky2::Plonky2Proof>> {
        let start = Instant::now();
        let mut proofs = Vec::new();
        
        for tx in transactions {
            let proof = self.zk_system.prove_transaction(
                tx.sender_balance,
                tx.amount,
                tx.fee,
                tx.sender_secret,
                tx.nullifier_seed,
            )?;
            proofs.push(proof);
        }
        
        let elapsed = start.elapsed();
        println!("Processed {} transactions in {:?}", transactions.len(), elapsed);
        println!("Average: {:?} per transaction", elapsed / transactions.len() as u32);
        
        Ok(proofs)
    }
    
    pub fn verify_proof_batch(&self, proofs: &[lib_proofs::plonky2::Plonky2Proof]) -> Result<bool> {
        let start = Instant::now();
        
        for proof in proofs {
            if !self.zk_system.verify_transaction(proof)? {
                return Ok(false);
            }
        }
        
        let elapsed = start.elapsed();
        println!("Verified {} proofs in {:?}", proofs.len(), elapsed);
        println!("Average: {:?} per verification", elapsed / proofs.len() as u32);
        
        Ok(true)
    }
}

pub struct TransactionData {
    pub sender_balance: u64,
    pub amount: u64,
    pub fee: u64,
    pub sender_secret: u64,
    pub nullifier_seed: u64,
}
```

### Memory Management

```rust
use lib_proofs::ZkProofSystem;
use std::sync::Arc;

pub struct SharedZkSystem {
    system: Arc<ZkProofSystem>,
}

impl SharedZkSystem {
    pub fn new() -> Result<Self> {
        Ok(Self {
            system: Arc::new(ZkProofSystem::new()?),
        })
    }
    
    pub fn clone_system(&self) -> Arc<ZkProofSystem> {
        Arc::clone(&self.system)
    }
}

// Usage across multiple threads
use std::thread;

pub fn parallel_proof_generation() -> Result<()> {
    let shared_system = SharedZkSystem::new()?;
    let mut handles = Vec::new();
    
    for i in 0..4 {
        let system = shared_system.clone_system();
        let handle = thread::spawn(move || {
            // Each thread uses the same ZK system instance
            let proof = system.prove_range(
                100 + i * 50,
                12345,
                0,
                1000,
            ).unwrap();
            
            println!("Thread {} generated proof", i);
            proof
        });
        handles.push(handle);
    }
    
    for handle in handles {
        let _proof = handle.join().unwrap();
    }
    
    Ok(())
}
```

## Error Handling Patterns

### Comprehensive Error Context

```rust
use anyhow::{Result, Context};
use lib_proofs::{ZkProofSystem, ZkRangeProof};

pub fn robust_integration_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()
        .context("Failed to initialize ZK proof system - check system resources")?;
    
    let range_proof = ZkRangeProof::generate_simple(500, 0, 1000)
        .context("Failed to generate range proof - check input values")?;
    
    let is_valid = range_proof.verify()
        .context("Failed to verify range proof - check proof integrity")?;
    
    if !is_valid {
        anyhow::bail!("Range proof verification failed - proof may be corrupted");
    }
    
    let tx_proof = zk_system.prove_transaction(1000, 100, 10, 12345, 67890)
        .context("Failed to generate transaction proof - check balance constraints")?;
    
    let tx_valid = zk_system.verify_transaction(&tx_proof)
        .context("Failed to verify transaction proof - check proof format")?;
    
    if !tx_valid {
        anyhow::bail!("Transaction proof verification failed - transaction may be invalid");
    }
    
    println!("All proofs generated and verified successfully");
    Ok(())
}
```

### Retry Logic

```rust
use lib_proofs::ZkProofSystem;
use std::time::Duration;
use std::thread;

pub fn robust_proof_generation_with_retry(
    zk_system: &ZkProofSystem,
    max_retries: u32,
) -> Result<lib_proofs::plonky2::Plonky2Proof> {
    let mut last_error = None;
    
    for attempt in 0..max_retries {
        match zk_system.prove_transaction(1000, 100, 10, 12345, 67890) {
            Ok(proof) => return Ok(proof),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_retries - 1 {
                    println!("Proof generation failed, retrying... (attempt {})", attempt + 1);
                    thread::sleep(Duration::from_millis(100 * (attempt + 1) as u64));
                }
            }
        }
    }
    
    Err(last_error.unwrap().context(format!("Failed to generate proof after {} attempts", max_retries)))
}
```

## Testing Integration

### Integration Test Structure

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use lib_crypto::KeyPair;
    use lib_proofs::{ZkProofSystem, zk_integration};
    
    #[test]
    fn test_crypto_zk_integration() -> Result<()> {
        let keypair = KeyPair::generate()?;
        let zk_system = ZkProofSystem::new()?;
        
        // Test identity proof with crypto keypair
        let identity_proof = zk_integration::prove_identity(
            &keypair.private_key,
            25, 840, 9999, 18, 840,
        )?;
        
        // Verify through ZK system
        // Note: This may require additional verification methods
        assert!(identity_proof.proof.len() > 0);
        
        Ok(())
    }
    
    #[test]
    fn test_transaction_proof_flow() -> Result<()> {
        let zk_system = ZkProofSystem::new()?;
        
        // Generate proof
        let proof = zk_system.prove_transaction(1000, 100, 10, 12345, 67890)?;
        
        // Serialize and deserialize
        let serialized = bincode::serialize(&proof)?;
        let deserialized: lib_proofs::plonky2::Plonky2Proof = bincode::deserialize(&serialized)?;
        
        // Verify deserialized proof
        let is_valid = zk_system.verify_transaction(&deserialized)?;
        assert!(is_valid);
        
        Ok(())
    }
    
    #[test] 
    fn test_batch_processing() -> Result<()> {
        let processor = BatchProcessor::new()?;
        
        let transactions = vec![
            TransactionData {
                sender_balance: 1000,
                amount: 100,
                fee: 10,
                sender_secret: 12345,
                nullifier_seed: 67890,
            },
            TransactionData {
                sender_balance: 2000,
                amount: 200,
                fee: 20,
                sender_secret: 23456,
                nullifier_seed: 78901,
            },
        ];
        
        let proofs = processor.process_transaction_batch(&transactions)?;
        assert_eq!(proofs.len(), 2);
        
        let all_valid = processor.verify_proof_batch(&proofs)?;
        assert!(all_valid);
        
        Ok(())
    }
}
```

# Integration Guide

This guide covers integrating lib-proofs with the SOVEREIGN_NET ecosystem and other components.

## Integration with lib-crypto

### Setting Up Dependencies

```toml
[dependencies]
lib-proofs = { path = "../lib-proofs" }
lib-crypto = { path = "../lib-crypto" }
anyhow = "1.0"
```

### Using ZK Proofs with Cryptographic Keys

```rust
use lib_crypto::KeyPair;
use lib_proofs::zk_integration;
use anyhow::Result;

fn crypto_integration_example() -> Result<()> {
    // Generate cryptographic keypair
    let keypair = KeyPair::generate()?;
    
    // Use the keypair with ZK proofs
    let identity_proof = zk_integration::prove_identity(
        &keypair.private_key,
        25,   // age
        840,  // jurisdiction (US)
        9999, // credential hash
        18,   // min age requirement
        840,  // required jurisdiction
    )?;
    
    println!("Identity proof generated using crypto keypair");
    Ok(())
}
```

### Key Derivation and ZK Proofs

```rust
use lib_crypto::KeyPair;
use lib_proofs::zk_integration;

fn key_derivation_integration() -> Result<()> {
    let master_keypair = KeyPair::generate()?;
    
    // Derive specialized keys for ZK proofs
    // Note: This example shows the intended pattern
    // Actual key derivation methods may need to be implemented
    
    // Use master key material for ZK proof generation
    let proof = zk_integration::prove_pqc_key_properties(&master_keypair.private_key)?;
    
    println!("PQC key properties proven with ZK");
    Ok(())
}
```

## Blockchain Integration

### Transaction Privacy

```rust
use lib_proofs::ZkProofSystem;
use lib_crypto::KeyPair;

struct PrivateTransaction {
    sender_keypair: KeyPair,
    receiver_public_key: lib_crypto::PublicKey,
    amount: u64,
    fee: u64,
}

impl PrivateTransaction {
    fn generate_proof(&self) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        let zk_system = ZkProofSystem::new()?;
        
        // In a real implementation, you'd derive these from the keypairs
        let sender_balance = 1000; // Retrieved from blockchain state
        let sender_secret = 12345;  // Derived from keypair
        let nullifier_seed = 67890; // Generated deterministically
        
        zk_system.prove_transaction(
            sender_balance,
            self.amount,
            self.fee,
            sender_secret,
            nullifier_seed,
        )
    }
    
    fn submit_to_blockchain(&self) -> Result<()> {
        let proof = self.generate_proof()?;
        
        // Serialize proof for blockchain submission
        let proof_data = bincode::serialize(&proof)?;
        
        // Submit to blockchain (pseudo-code)
        // blockchain.submit_private_transaction(proof_data)?;
        
        println!("Private transaction submitted with proof");
        println!("Proof size: {} bytes", proof_data.len());
        
        Ok(())
    }
}
```

### Smart Contract Integration

```rust
use lib_proofs::{ZkProofSystem, types::ZkProof};

pub struct SmartContractContext {
    zk_system: ZkProofSystem,
}

impl SmartContractContext {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
        })
    }
    
    pub fn verify_contract_execution(&self, proof: &ZkProof) -> Result<bool> {
        // Verify proof matches expected contract constraints
        proof.verify()
    }
    
    pub fn execute_private_contract(
        &self,
        contract_data: &[u8],
        private_inputs: &[u64],
        public_inputs: &[u64],
    ) -> Result<ZkProof> {
        // Generate proof of correct contract execution
        ZkProof::from_public_inputs(public_inputs.to_vec())
    }
}
```

### Consensus Integration

```rust
use lib_proofs::{ZkProofSystem, verifiers::RecursiveProofAggregator};

pub struct ConsensusValidator {
    zk_system: ZkProofSystem,
    aggregator: RecursiveProofAggregator,
}

impl ConsensusValidator {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
            aggregator: RecursiveProofAggregator::new()?,
        })
    }
    
    pub fn validate_block_proofs(&self, proofs: &[lib_proofs::plonky2::Plonky2Proof]) -> Result<bool> {
        // Validate individual transaction proofs
        for proof in proofs {
            if !self.zk_system.verify_transaction(proof)? {
                return Ok(false);
            }
        }
        
        // Aggregate proofs for efficient verification
        // let aggregated = self.aggregator.aggregate_proofs(proofs)?;
        
        Ok(true)
    }
}
```

## Mesh Network Integration

### Anonymous Routing

```rust
use lib_proofs::ZkProofSystem;

pub struct MeshRouter {
    zk_system: ZkProofSystem,
    node_id: u64,
}

impl MeshRouter {
    pub fn new(node_id: u64) -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
            node_id,
        })
    }
    
    pub fn prove_routing_capability(
        &self,
        destination: u64,
        max_hops: u64,
        min_bandwidth: u64,
    ) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        // Generate proof that this node can route to destination
        // without revealing the exact path or node capabilities
        
        let hop_count = 3; // Actual hop count (private)
        let bandwidth = 1000; // Available bandwidth (private)
        let latency = 50; // Route latency (private)
        let routing_secret = 99999; // Node's routing secret (private)
        
        self.zk_system.prove_routing(
            self.node_id,
            destination,
            hop_count,
            bandwidth,
            latency,
            routing_secret,
            max_hops,
            min_bandwidth,
        )
    }
    
    pub fn verify_route_proof(&self, proof: &lib_proofs::plonky2::Plonky2Proof) -> Result<bool> {
        self.zk_system.verify_routing(proof)
    }
}
```

### Data Storage Proofs

```rust
use lib_proofs::ZkProofSystem;

pub struct DistributedStorage {
    zk_system: ZkProofSystem,
}

impl DistributedStorage {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
        })
    }
    
    pub fn prove_data_storage(
        &self,
        data_hash: u64,
        storage_node_secret: u64,
    ) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        // Prove data is stored correctly without revealing data content
        
        let chunk_count = 100;
        let total_size = 1048576; // 1MB
        let checksum = 0xDEADBEEF;
        let timestamp = 1672531200;
        let max_chunks = 1000;
        let max_size = 10485760; // 10MB
        
        self.zk_system.prove_data_integrity(
            data_hash,
            chunk_count,
            total_size,
            checksum,
            storage_node_secret,
            timestamp,
            max_chunks,
            max_size,
        )
    }
    
    pub fn verify_storage_proof(&self, proof: &lib_proofs::plonky2::Plonky2Proof) -> Result<bool> {
        self.zk_system.verify_data_integrity(proof)
    }
}
```

## Identity and Access Management

### Decentralized Identity

```rust
use lib_crypto::KeyPair;
use lib_proofs::zk_integration;

pub struct DecentralizedIdentity {
    keypair: KeyPair,
    age: u64,
    jurisdiction: u64,
    credentials: Vec<u64>,
}

impl DecentralizedIdentity {
    pub fn new(age: u64, jurisdiction: u64) -> Result<Self> {
        Ok(Self {
            keypair: KeyPair::generate()?,
            age,
            jurisdiction,
            credentials: Vec::new(),
        })
    }
    
    pub fn prove_age_requirement(&self, min_age: u64) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        zk_integration::prove_identity(
            &self.keypair.private_key,
            self.age,
            self.jurisdiction,
            9999, // credential hash
            min_age,
            0, // no jurisdiction requirement
        )
    }
    
    pub fn prove_jurisdiction(&self, required_jurisdiction: u64) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        zk_integration::prove_identity(
            &self.keypair.private_key,
            self.age,
            self.jurisdiction,
            9999, // credential hash
            0, // no age requirement
            required_jurisdiction,
        )
    }
    
    pub fn prove_full_identity(
        &self,
        min_age: u64,
        required_jurisdiction: u64,
    ) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        zk_integration::prove_identity(
            &self.keypair.private_key,
            self.age,
            self.jurisdiction,
            9999, // credential hash
            min_age,
            required_jurisdiction,
        )
    }
}
```

### Access Control

```rust
use lib_proofs::ZkProofSystem;

pub struct AccessControlSystem {
    zk_system: ZkProofSystem,
}

impl AccessControlSystem {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
        })
    }
    
    pub fn prove_access_rights(
        &self,
        user_secret: u64,
        resource_hash: u64,
        user_permission_level: u64,
        required_permission: u64,
    ) -> Result<lib_proofs::plonky2::Plonky2Proof> {
        let access_key = 11111; // Derived from user credentials
        
        self.zk_system.prove_storage_access(
            access_key,
            user_secret,
            resource_hash,
            user_permission_level,
            required_permission,
        )
    }
    
    pub fn verify_access(&self, proof: &lib_proofs::plonky2::Plonky2Proof) -> Result<bool> {
        self.zk_system.verify_storage_access(proof)
    }
}
```

## Cross-Component Communication

### Proof Serialization

```rust
use lib_proofs::types::ZkProof;
use serde_json;

pub fn serialize_proof(proof: &ZkProof) -> Result<Vec<u8>> {
    // Binary serialization for efficiency
    bincode::serialize(proof).map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))
}

pub fn deserialize_proof(data: &[u8]) -> Result<ZkProof> {
    bincode::deserialize(data).map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))
}

pub fn proof_to_json(proof: &ZkProof) -> Result<String> {
    // JSON serialization for debugging/APIs
    serde_json::to_string(proof).map_err(|e| anyhow::anyhow!("JSON serialization failed: {}", e))
}

pub fn proof_from_json(json: &str) -> Result<ZkProof> {
    serde_json::from_str(json).map_err(|e| anyhow::anyhow!("JSON deserialization failed: {}", e))
}
```

### Network Protocol Integration

```rust
use lib_proofs::types::ZkProof;

pub struct NetworkMessage {
    pub message_type: String,
    pub proof: Option<ZkProof>,
    pub data: Vec<u8>,
}

impl NetworkMessage {
    pub fn new_with_proof(message_type: String, proof: ZkProof, data: Vec<u8>) -> Self {
        Self {
            message_type,
            proof: Some(proof),
            data,
        }
    }
    
    pub fn verify_message(&self) -> Result<bool> {
        match &self.proof {
            Some(proof) => proof.verify(),
            None => Ok(true), // No proof required
        }
    }
    
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!("Message serialization failed: {}", e))
    }
    
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow::anyhow!("Message deserialization failed: {}", e))
    }
}
```

## Performance Optimization

### Batch Processing

```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof};
use std::time::Instant;

pub struct BatchProcessor {
    zk_system: ZkProofSystem,
}

impl BatchProcessor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
        })
    }
    
    pub fn process_transaction_batch(&self, transactions: &[TransactionData]) -> Result<Vec<lib_proofs::plonky2::Plonky2Proof>> {
        let start = Instant::now();
        let mut proofs = Vec::new();
        
        for tx in transactions {
            let proof = self.zk_system.prove_transaction(
                tx.sender_balance,
                tx.amount,
                tx.fee,
                tx.sender_secret,
                tx.nullifier_seed,
            )?;
            proofs.push(proof);
        }
        
        let elapsed = start.elapsed();
        println!("Processed {} transactions in {:?}", transactions.len(), elapsed);
        println!("Average: {:?} per transaction", elapsed / transactions.len() as u32);
        
        Ok(proofs)
    }
    
    pub fn verify_proof_batch(&self, proofs: &[lib_proofs::plonky2::Plonky2Proof]) -> Result<bool> {
        let start = Instant::now();
        
        for proof in proofs {
            if !self.zk_system.verify_transaction(proof)? {
                return Ok(false);
            }
        }
        
        let elapsed = start.elapsed();
        println!("Verified {} proofs in {:?}", proofs.len(), elapsed);
        println!("Average: {:?} per verification", elapsed / proofs.len() as u32);
        
        Ok(true)
    }
}

pub struct TransactionData {
    pub sender_balance: u64,
    pub amount: u64,
    pub fee: u64,
    pub sender_secret: u64,
    pub nullifier_seed: u64,
}
```

### Memory Management

```rust
use lib_proofs::ZkProofSystem;
use std::sync::Arc;

pub struct SharedZkSystem {
    system: Arc<ZkProofSystem>,
}

impl SharedZkSystem {
    pub fn new() -> Result<Self> {
        Ok(Self {
            system: Arc::new(ZkProofSystem::new()?),
        })
    }
    
    pub fn clone_system(&self) -> Arc<ZkProofSystem> {
        Arc::clone(&self.system)
    }
}

// Usage across multiple threads
use std::thread;

pub fn parallel_proof_generation() -> Result<()> {
    let shared_system = SharedZkSystem::new()?;
    let mut handles = Vec::new();
    
    for i in 0..4 {
        let system = shared_system.clone_system();
        let handle = thread::spawn(move || {
            // Each thread uses the same ZK system instance
            let proof = system.prove_range(
                100 + i * 50,
                12345,
                0,
                1000,
            ).unwrap();
            
            println!("Thread {} generated proof", i);
            proof
        });
        handles.push(handle);
    }
    
    for handle in handles {
        let _proof = handle.join().unwrap();
    }
    
    Ok(())
}
```

## Error Handling Patterns

### Comprehensive Error Context

```rust
use anyhow::{Result, Context};
use lib_proofs::{ZkProofSystem, ZkRangeProof};

pub fn robust_integration_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()
        .context("Failed to initialize ZK proof system - check system resources")?;
    
    let range_proof = ZkRangeProof::generate_simple(500, 0, 1000)
        .context("Failed to generate range proof - check input values")?;
    
    let is_valid = range_proof.verify()
        .context("Failed to verify range proof - check proof integrity")?;
    
    if !is_valid {
        anyhow::bail!("Range proof verification failed - proof may be corrupted");
    }
    
    let tx_proof = zk_system.prove_transaction(1000, 100, 10, 12345, 67890)
        .context("Failed to generate transaction proof - check balance constraints")?;
    
    let tx_valid = zk_system.verify_transaction(&tx_proof)
        .context("Failed to verify transaction proof - check proof format")?;
    
    if !tx_valid {
        anyhow::bail!("Transaction proof verification failed - transaction may be invalid");
    }
    
    println!("All proofs generated and verified successfully");
    Ok(())
}
```

### Retry Logic

```rust
use lib_proofs::ZkProofSystem;
use std::time::Duration;
use std::thread;

pub fn robust_proof_generation_with_retry(
    zk_system: &ZkProofSystem,
    max_retries: u32,
) -> Result<lib_proofs::plonky2::Plonky2Proof> {
    let mut last_error = None;
    
    for attempt in 0..max_retries {
        match zk_system.prove_transaction(1000, 100, 10, 12345, 67890) {
            Ok(proof) => return Ok(proof),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_retries - 1 {
                    println!("Proof generation failed, retrying... (attempt {})", attempt + 1);
                    thread::sleep(Duration::from_millis(100 * (attempt + 1) as u64));
                }
            }
        }
    }
    
    Err(last_error.unwrap().context(format!("Failed to generate proof after {} attempts", max_retries)))
}
```

## Testing Integration

### Integration Test Structure

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use lib_crypto::KeyPair;
    use lib_proofs::{ZkProofSystem, zk_integration};
    
    #[test]
    fn test_crypto_zk_integration() -> Result<()> {
        let keypair = KeyPair::generate()?;
        let zk_system = ZkProofSystem::new()?;
        
        // Test identity proof with crypto keypair
        let identity_proof = zk_integration::prove_identity(
            &keypair.private_key,
            25, 840, 9999, 18, 840,
        )?;
        
        // Verify through ZK system
        // Note: This may require additional verification methods
        assert!(identity_proof.proof.len() > 0);
        
        Ok(())
    }
    
    #[test]
    fn test_transaction_proof_flow() -> Result<()> {
        let zk_system = ZkProofSystem::new()?;
        
        // Generate proof
        let proof = zk_system.prove_transaction(1000, 100, 10, 12345, 67890)?;
        
        // Serialize and deserialize
        let serialized = bincode::serialize(&proof)?;
        let deserialized: lib_proofs::plonky2::Plonky2Proof = bincode::deserialize(&serialized)?;
        
        // Verify deserialized proof
        let is_valid = zk_system.verify_transaction(&deserialized)?;
        assert!(is_valid);
        
        Ok(())
    }
    
    #[test] 
    fn test_batch_processing() -> Result<()> {
        let processor = BatchProcessor::new()?;
        
        let transactions = vec![
            TransactionData {
                sender_balance: 1000,
                amount: 100,
                fee: 10,
                sender_secret: 12345,
                nullifier_seed: 67890,
            },
            TransactionData {
                sender_balance: 2000,
                amount: 200,
                fee: 20,
                sender_secret: 23456,
                nullifier_seed: 78901,
            },
        ];
        
        let proofs = processor.process_transaction_batch(&transactions)?;
        assert_eq!(proofs.len(), 2);
        
        let all_valid = processor.verify_proof_batch(&proofs)?;
        assert!(all_valid);
        
        Ok(())
    }
}
```

This integration guide provides comprehensive examples for using lib-proofs with other SOVEREIGN_NET components. The patterns shown here can be adapted for specific use cases and requirements.