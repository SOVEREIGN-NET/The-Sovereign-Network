use crate::zhtp::{
    zk_proofs::{ByteRoutingProof},
    crypto::{Keypair, Signature},
};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use rand::RngCore;
use pqcrypto_traits::sign::PublicKey;
use ark_ec::PrimeGroup;

/// Decentralized DNS replacement that uses zero-knowledge proofs
#[derive(Debug, Clone)]
pub struct ZhtpDNS {
    /// Root domain registry
    domain_registry: Arc<RwLock<HashMap<String, DomainRecord>>>,
    /// Subdomain registry
    subdomain_registry: Arc<RwLock<HashMap<String, SubdomainRecord>>>,
    /// Certificate authority for domain verification
    _ca_registry: Arc<RwLock<HashMap<String, CertificateRecord>>>,
    /// Reverse lookup cache
    reverse_lookup: Arc<RwLock<HashMap<SocketAddr, String>>>,
    /// Domain ownership proofs
    ownership_proofs: Arc<RwLock<HashMap<String, OwnershipProof>>>,
}

/// Domain record in decentralized DNS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    /// Domain name (e.g., "example.zhtp")
    pub domain: String,
    /// ZHTP addresses hosting this domain
    pub addresses: Vec<SocketAddr>,
    /// Content hash for integrity verification
    pub content_hash: [u8; 32],
    /// Owner's public key
    pub owner_public_key: Vec<u8>,
    /// Zero-knowledge proof of ownership
    pub ownership_proof: ByteRoutingProof,
    /// Domain signature by owner
    pub signature: Signature,
    /// Time-to-live for caching
    pub ttl: u64,
    /// Registration timestamp
    pub registered_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Domain status
    pub status: DomainStatus,
}

/// Subdomain record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainRecord {
    /// Full subdomain name (e.g., "www.example.zhtp")
    pub subdomain: String,
    /// Parent domain
    pub parent_domain: String,
    /// Subdomain-specific addresses
    pub addresses: Vec<SocketAddr>,
    /// Content hash
    pub content_hash: [u8; 32],
    /// Subdomain owner (can be different from domain owner)
    pub owner_public_key: Vec<u8>,
    /// Delegation proof from parent domain
    pub delegation_proof: ByteRoutingProof,
    /// Subdomain signature
    pub signature: Signature,
    /// TTL
    pub ttl: u64,
    /// Registration timestamp
    pub registered_at: u64,
}

/// Certificate record for domain validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    /// Domain this certificate is for
    pub domain: String,
    /// Certificate data
    pub certificate_data: Vec<u8>,
    /// Zero-knowledge proof of certificate validity
    pub validity_proof: ByteRoutingProof,
    /// Certificate authority signature
    pub ca_signature: Signature,
    /// Certificate hash
    pub cert_hash: [u8; 32],
    /// Issue timestamp
    pub issued_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
}

/// Ownership proof for domain registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipProof {
    /// Domain being claimed
    pub domain: String,
    /// Proof of ownership (e.g., DNS challenge response)
    pub proof_data: Vec<u8>,
    /// Zero-knowledge proof of ownership validity
    pub ownership_proof: ByteRoutingProof,
    /// Proof timestamp
    pub timestamp: u64,
    /// Proof signature
    pub signature: Signature,
}

/// Domain status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DomainStatus {
    Active,
    Pending,
    Suspended,
    Expired,
    Revoked,
}

/// DNS query types
#[derive(Debug, Clone, PartialEq)]
pub enum QueryType {
    A,      // Address record
    AAAA,   // IPv6 address
    CNAME,  // Canonical name
    TXT,    // Text record
    MX,     // Mail exchange
    ZHTP,   // ZHTP-specific record
}

/// DNS query structure
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub domain: String,
    pub query_type: QueryType,
    pub recursive: bool,
}

/// DNS response structure
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub domain: String,
    pub query_type: QueryType,
    pub addresses: Vec<SocketAddr>,
    pub ttl: u64,
    pub authoritative: bool,
    pub additional_data: HashMap<String, Vec<u8>>,
}

impl ZhtpDNS {
    pub fn new() -> Self {
        Self {
            domain_registry: Arc::new(RwLock::new(HashMap::new())),
            subdomain_registry: Arc::new(RwLock::new(HashMap::new())),
            _ca_registry: Arc::new(RwLock::new(HashMap::new())),
            reverse_lookup: Arc::new(RwLock::new(HashMap::new())),
            ownership_proofs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new domain with zero-knowledge proof of ownership
    pub async fn register_domain(
        &self,
        domain: String,
        addresses: Vec<SocketAddr>,
        owner_keypair: &Keypair,
        content_hash: [u8; 32],
    ) -> Result<()> {
        // Validate domain name
        self.validate_domain_name(&domain)?;

        // Check if domain already exists
        {
            let registry = self.domain_registry.read().await;
            if registry.contains_key(&domain) {
                return Err(anyhow!("Domain already registered"));
            }
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let expires_at = now + (365 * 24 * 60 * 60); // 1 year

        // Generate ownership proof
        let ownership_proof = self.generate_ownership_proof(&domain, owner_keypair).await?;

        // Create domain signature
        let domain_data = [
            domain.as_bytes(),
            &bincode::serialize(&addresses)?,
            &content_hash,
        ].concat();
        let signature = owner_keypair.sign(&domain_data)?;

        let record = DomainRecord {
            domain: domain.clone(),
            addresses: addresses.clone(),
            content_hash,
            owner_public_key: owner_keypair.public.as_bytes().to_vec(),
            ownership_proof,
            signature,
            ttl: 3600, // 1 hour default TTL
            registered_at: now,
            expires_at,
            status: DomainStatus::Active,
        };

        // Store domain record
        {
            let mut registry = self.domain_registry.write().await;
            registry.insert(domain.clone(), record);
        }

        // Update reverse lookup
        {
            let mut reverse = self.reverse_lookup.write().await;
            for addr in addresses {
                reverse.insert(addr, domain.clone());
            }
        }

        println!("Successfully registered domain: {}", domain);
        Ok(())
    }

    /// Register a subdomain
    pub async fn register_subdomain(
        &self,
        subdomain: String,
        parent_domain: String,
        addresses: Vec<SocketAddr>,
        owner_keypair: &Keypair,
        parent_delegation_proof: ByteRoutingProof,
    ) -> Result<()> {
        // Verify parent domain exists and is active
        {
            let registry = self.domain_registry.read().await;
            let parent_record = registry.get(&parent_domain)
                .ok_or_else(|| anyhow!("Parent domain not found"))?;
            
            if parent_record.status != DomainStatus::Active {
                return Err(anyhow!("Parent domain is not active"));
            }
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Generate content hash
        let mut hasher = Sha256::new();
        hasher.update(subdomain.as_bytes());
        for addr in &addresses {
            hasher.update(addr.to_string().as_bytes());
        }
        let content_hash: [u8; 32] = hasher.finalize().into();

        // Create subdomain signature
        let subdomain_data = [
            subdomain.as_bytes(),
            parent_domain.as_bytes(),
            &bincode::serialize(&addresses)?,
        ].concat();
        let signature = owner_keypair.sign(&subdomain_data)?;

        let record = SubdomainRecord {
            subdomain: subdomain.clone(),
            parent_domain,
            addresses: addresses.clone(),
            content_hash,
            owner_public_key: owner_keypair.public.as_bytes().to_vec(),
            delegation_proof: parent_delegation_proof,
            signature,
            ttl: 3600,
            registered_at: now,
        };

        // Store subdomain record
        {
            let mut registry = self.subdomain_registry.write().await;
            registry.insert(subdomain.clone(), record);
        }

        // Update reverse lookup
        {
            let mut reverse = self.reverse_lookup.write().await;
            for addr in addresses {
                reverse.insert(addr, subdomain.clone());
            }
        }

        println!("Successfully registered subdomain: {}", subdomain);
        Ok(())
    }

    /// Resolve a domain name to addresses
    pub async fn resolve(&self, query: DnsQuery) -> Result<DnsResponse> {
        match query.query_type {
            QueryType::ZHTP | QueryType::A => {
                // Try subdomain first
                if query.domain.contains('.') {
                    if let Ok(response) = self.resolve_subdomain(&query.domain).await {
                        return Ok(response);
                    }
                }

                // Try main domain
                self.resolve_domain(&query.domain).await
            }
            _ => Err(anyhow!("Query type not supported yet")),
        }
    }

    async fn resolve_domain(&self, domain: &str) -> Result<DnsResponse> {
        let registry = self.domain_registry.read().await;
        
        match registry.get(domain) {
            Some(record) => {
                if record.status != DomainStatus::Active {
                    return Err(anyhow!("Domain is not active"));
                }

                // Check if domain has expired
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                if now > record.expires_at {
                    return Err(anyhow!("Domain has expired"));
                }

                Ok(DnsResponse {
                    domain: domain.to_string(),
                    query_type: QueryType::ZHTP,
                    addresses: record.addresses.clone(),
                    ttl: record.ttl,
                    authoritative: true,
                    additional_data: HashMap::new(),
                })
            }
            None => Err(anyhow!("Domain not found: {}", domain))
        }
    }

    async fn resolve_subdomain(&self, subdomain: &str) -> Result<DnsResponse> {
        let registry = self.subdomain_registry.read().await;
        
        match registry.get(subdomain) {
            Some(record) => {
                Ok(DnsResponse {
                    domain: subdomain.to_string(),
                    query_type: QueryType::ZHTP,
                    addresses: record.addresses.clone(),
                    ttl: record.ttl,
                    authoritative: true,
                    additional_data: HashMap::new(),
                })
            }
            None => Err(anyhow!("Subdomain not found: {}", subdomain))
        }
    }

    /// Reverse lookup - get domain from address
    pub async fn reverse_lookup(&self, addr: &SocketAddr) -> Result<String> {
        let reverse = self.reverse_lookup.read().await;
        reverse.get(addr)
            .cloned()
            .ok_or_else(|| anyhow!("No domain found for address: {}", addr))
    }

    /// Update domain addresses
    pub async fn update_domain_addresses(
        &self,
        domain: String,
        new_addresses: Vec<SocketAddr>,
        owner_keypair: &Keypair,
    ) -> Result<()> {
        let mut registry = self.domain_registry.write().await;
        
        if let Some(record) = registry.get_mut(&domain) {
            // Verify ownership
            if record.owner_public_key != owner_keypair.public.as_bytes().to_vec() {
                return Err(anyhow!("Not authorized to update domain"));
            }

            // Update addresses
            record.addresses = new_addresses.clone();
            
            // Update signature
            let domain_data = [
                domain.as_bytes(),
                &bincode::serialize(&new_addresses)?,
                &record.content_hash,
            ].concat();
            record.signature = owner_keypair.sign(&domain_data)?;

            // Update reverse lookup
            drop(registry);
            let mut reverse = self.reverse_lookup.write().await;
            reverse.retain(|_, d| d != &domain); // Remove old entries
            for addr in new_addresses {
                reverse.insert(addr, domain.clone());
            }

            Ok(())
        } else {
            Err(anyhow!("Domain not found"))
        }
    }

    /// Revoke a domain
    pub async fn revoke_domain(&self, domain: String, owner_keypair: &Keypair) -> Result<()> {
        let mut registry = self.domain_registry.write().await;
        
        if let Some(record) = registry.get_mut(&domain) {
            // Verify ownership
            if record.owner_public_key != owner_keypair.public.as_bytes().to_vec() {
                return Err(anyhow!("Not authorized to revoke domain"));
            }

            record.status = DomainStatus::Revoked;
            Ok(())
        } else {
            Err(anyhow!("Domain not found"))
        }
    }

    /// Get all domains owned by a public key
    pub async fn get_domains_by_owner(&self, owner_public_key: &[u8]) -> Vec<String> {
        let registry = self.domain_registry.read().await;
        registry.values()
            .filter(|record| record.owner_public_key == owner_public_key)
            .map(|record| record.domain.clone())
            .collect()
    }

    /// Clean up expired domains
    pub async fn cleanup_expired_domains(&self) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut registry = self.domain_registry.write().await;
        
        let expired_domains: Vec<String> = registry.values()
            .filter(|record| now > record.expires_at)
            .map(|record| record.domain.clone())
            .collect();

        for domain in expired_domains {
            if let Some(record) = registry.get_mut(&domain) {
                record.status = DomainStatus::Expired;
            }
        }

        Ok(())
    }

    /// Validate domain name format
    fn validate_domain_name(&self, domain: &str) -> Result<()> {
        if domain.is_empty() || domain.len() > 253 {
            return Err(anyhow!("Invalid domain length"));
        }

        if !domain.ends_with(".zhtp") {
            return Err(anyhow!("Domain must end with .zhtp"));
        }

        // Check for valid characters
        for c in domain.chars() {
            if !c.is_ascii_alphanumeric() && c != '.' && c != '-' {
                return Err(anyhow!("Invalid character in domain name"));
            }
        }

        Ok(())
    }    
    // Generate zero-knowledge proof of domain ownership
    async fn generate_ownership_proof(&self, domain: &str, keypair: &Keypair) -> Result<ByteRoutingProof> {
        // Create a challenge-response proof
        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        
        // Create response by signing the challenge
        let response = keypair.sign(&challenge)?;
        
        // Generate secure ZK proof using UnifiedCircuit with KZG trusted setup
        let mut circuit = crate::zhtp::zk_proofs::UnifiedCircuit::new(
            domain.as_bytes().to_vec(),
            b"DNS_OWNERSHIP_VERIFICATION".to_vec(),
            vec![], // No routing path for ownership verification
            std::collections::HashMap::new(),
            challenge, // Use challenge as storage root
            vec![], // No storage proof needed
            ark_bn254::G1Projective::generator(),
            keypair.public_key().len() as u64, // Public key length as bandwidth
            vec![(challenge[0] as u64, true)], // Challenge-based uptime
            vec![(response.as_bytes().len() as u64, 0.0)], // Response length as latency
        );

        // Generate secure proof using KZG trusted setup
        let secure_proof = match circuit.generate_proof() {
            Some(proof) => ByteRoutingProof::from(proof),
            None => return Err(anyhow::anyhow!("Failed to generate DNS ownership proof"))
        };

        // Store ownership proof
        let ownership_proof = OwnershipProof {
            domain: domain.to_string(),
            proof_data: [domain.as_bytes(), &challenge, response.as_bytes()].concat(),
            ownership_proof: secure_proof.clone(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: response,
        };

        {
            let mut proofs = self.ownership_proofs.write().await;
            proofs.insert(domain.to_string(), ownership_proof);
        }

        Ok(secure_proof)
    }

    /// Verify domain ownership proof
    pub async fn verify_ownership_proof(&self, domain: &str, proof: &ByteRoutingProof) -> Result<bool> {
        let proofs = self.ownership_proofs.read().await;
        
        match proofs.get(domain) {
            Some(stored_proof) => {
                // Verify the proof matches
                Ok(stored_proof.ownership_proof.commitments == proof.commitments &&
                   stored_proof.ownership_proof.elements == proof.elements)
            }
            None => Ok(false)
        }
    }

    /// Get domain statistics
    pub async fn get_stats(&self) -> HashMap<String, u64> {
        let domain_registry = self.domain_registry.read().await;
        let subdomain_registry = self.subdomain_registry.read().await;
        
        let mut stats = HashMap::new();
        stats.insert("total_domains".to_string(), domain_registry.len() as u64);
        stats.insert("total_subdomains".to_string(), subdomain_registry.len() as u64);
        
        let active_domains = domain_registry.values()
            .filter(|r| r.status == DomainStatus::Active)
            .count() as u64;
        stats.insert("active_domains".to_string(), active_domains);
        
        stats
    }

    /// Resolve domain to get its associated addresses
    pub async fn resolve_domain_addresses(&self, domain: &str) -> Option<Vec<SocketAddr>> {
        let domain_registry = self.domain_registry.read().await;
        if let Some(record) = domain_registry.get(domain) {
            if record.status == DomainStatus::Active {
                return Some(record.addresses.clone());
            }
        }
        None
    }
}

impl Default for ZhtpDNS {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_registration() -> Result<()> {
        let dns = ZhtpDNS::new();
        let keypair = Keypair::generate();
        let addresses = vec!["127.0.0.1:8080".parse().unwrap()];
        let content_hash = [1u8; 32];

        dns.register_domain(
            "example.zhtp".to_string(),
            addresses.clone(),
            &keypair,
            content_hash,
        ).await?;

        let query = DnsQuery {
            domain: "example.zhtp".to_string(),
            query_type: QueryType::ZHTP,
            recursive: false,
        };

        let response = dns.resolve(query).await?;
        assert_eq!(response.addresses, addresses);
        assert_eq!(response.domain, "example.zhtp");

        Ok(())
    }

    #[tokio::test]
    async fn test_subdomain_registration() -> Result<()> {
        let dns = ZhtpDNS::new();
        let keypair = Keypair::generate();
        let parent_addresses = vec!["127.0.0.1:8080".parse().unwrap()];
        let sub_addresses = vec!["127.0.0.1:8081".parse().unwrap()];
        let content_hash = [1u8; 32];

        // Register parent domain
        dns.register_domain(
            "example.zhtp".to_string(),
            parent_addresses,
            &keypair,
            content_hash,
        ).await?;

        // Register subdomain
        let delegation_proof = ByteRoutingProof {
            commitments: vec![vec![1, 2, 3]],
            elements: vec![vec![4, 5, 6]],
            inputs: vec![vec![7, 8, 9]],
        };

        dns.register_subdomain(
            "www.example.zhtp".to_string(),
            "example.zhtp".to_string(),
            sub_addresses.clone(),
            &keypair,
            delegation_proof,
        ).await?;

        let query = DnsQuery {
            domain: "www.example.zhtp".to_string(),
            query_type: QueryType::ZHTP,
            recursive: false,
        };

        let response = dns.resolve(query).await?;
        assert_eq!(response.addresses, sub_addresses);

        Ok(())
    }

    #[tokio::test]
    async fn test_reverse_lookup() -> Result<()> {
        let dns = ZhtpDNS::new();
        let keypair = Keypair::generate();
        let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addresses = vec![address];
        let content_hash = [1u8; 32];

        dns.register_domain(
            "example.zhtp".to_string(),
            addresses,
            &keypair,
            content_hash,
        ).await?;

        let domain = dns.reverse_lookup(&address).await?;
        assert_eq!(domain, "example.zhtp");

        Ok(())
    }

    #[tokio::test]
    async fn test_domain_update() -> Result<()> {
        let dns = ZhtpDNS::new();
        let keypair = Keypair::generate();
        let initial_addresses = vec!["127.0.0.1:8080".parse().unwrap()];
        let updated_addresses = vec!["127.0.0.1:8081".parse().unwrap()];
        let content_hash = [1u8; 32];

        dns.register_domain(
            "example.zhtp".to_string(),
            initial_addresses,
            &keypair,
            content_hash,
        ).await?;

        dns.update_domain_addresses(
            "example.zhtp".to_string(),
            updated_addresses.clone(),
            &keypair,
        ).await?;

        let query = DnsQuery {
            domain: "example.zhtp".to_string(),
            query_type: QueryType::ZHTP,
            recursive: false,
        };

        let response = dns.resolve(query).await?;
        assert_eq!(response.addresses, updated_addresses);

        Ok(())
    }

    #[tokio::test]
    async fn test_ownership_verification() -> Result<()> {
        let dns = ZhtpDNS::new();
        let keypair = Keypair::generate();
        let domain = "example.zhtp";

        let proof = dns.generate_ownership_proof(domain, &keypair).await?;
        let is_valid = dns.verify_ownership_proof(domain, &proof).await?;
        assert!(is_valid);

        Ok(())
    }
}
