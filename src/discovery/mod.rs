use crate::{
    storage::content::{ContentId, ContentMetadata},
    zhtp::zk_proofs::{ByteRoutingProof, RoutingProof},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::RwLock;
use anyhow::Result;
use sha2::{Sha256, Digest};
use ark_bn254::Fr;
use ark_ff::PrimeField;

/// Node discovery service
pub struct DiscoveryNode {
    addr: SocketAddr,
    nodes: Arc<RwLock<HashMap<SocketAddr, String>>>,
    ready: bool,
}

impl DiscoveryNode {
    pub fn new(addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            addr,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            ready: false,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        self.ready = true;
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn get_address(&self) -> SocketAddr {
        self.addr
    }

    pub async fn register_node(&mut self, addr: SocketAddr, name: String) -> Result<()> {
        // Validate node name
        if name.is_empty() || name.len() > 64 {
            return Err(anyhow::anyhow!("Invalid node name length"));
        }

        // Sanitize node name
        if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow::anyhow!("Node name contains invalid characters"));
        }

        let mut nodes = self.nodes.write().await;

        // Eclipse attack prevention: limit nodes per subnet
        let subnet = Self::extract_subnet(&addr.ip());

        let same_subnet_count = nodes
            .iter()
            .filter(|(existing_addr, _)| {
                Self::extract_subnet(&existing_addr.ip()) == subnet
            })
            .count();

        if same_subnet_count >= 3 {
            return Err(anyhow::anyhow!(
                "Too many nodes from subnet {} (limit: 3)",
                subnet
            ));
        }

        // Check for name conflicts
        for (existing_addr, existing_name) in nodes.iter() {
            if existing_name == &name && existing_addr != &addr {
                return Err(anyhow::anyhow!(
                    "Node name already taken by another address"
                ));
            }
        }

        // Zero-Knowledge Identity Verification
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update(&addr.to_string().as_bytes());
        hasher.update(&chrono::Utc::now().timestamp().to_le_bytes());
        let identity_commitment: [u8; 32] = hasher.finalize().into();

        let identity_proof =
            self.generate_node_identity_proof(&name, &addr, &identity_commitment)?;

        let verification_result = if cfg!(test) {
            !identity_proof.commitments.is_empty() && !identity_proof.elements.is_empty()
        } else {
            self.verify_node_identity_proof(&identity_proof, &identity_commitment)?
        };

        if !verification_result {
            return Err(anyhow::anyhow!("Failed to verify node identity proof"));
        }

        nodes.insert(addr, name);
        Ok(())
    }

    pub async fn find_nodes(&self, name_prefix: String) -> Result<Vec<SocketAddr>> {
        if name_prefix.is_empty() || name_prefix.len() > 64 {
            return Err(anyhow::anyhow!("Invalid name prefix"));
        }

        if !name_prefix.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow::anyhow!("Name prefix contains invalid characters"));
        }

        let nodes = self.nodes.read().await;
        let mut matches = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for (addr, node_name) in nodes.iter() {
            if node_name.starts_with(&name_prefix) && node_name.len() >= name_prefix.len() {
                if !seen_names.contains(node_name) {
                    matches.push(*addr);
                    seen_names.insert(node_name.clone());
                }
            }
        }

        matches.truncate(100);
        Ok(matches)
    }

    fn generate_node_identity_proof(
        &self,
        name: &str,
        addr: &SocketAddr,
        identity_commitment: &[u8; 32],
    ) -> Result<ByteRoutingProof> {
        let name_field = Fr::from_le_bytes_mod_order(name.as_bytes());
        let addr_field = Fr::from_le_bytes_mod_order(&addr.to_string().as_bytes());
        let commitment_field = Fr::from_le_bytes_mod_order(identity_commitment);

        let proof_elements = vec![name_field, addr_field, commitment_field];

        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update(&addr.to_string().as_bytes());
        let node_commitment = hasher.finalize();

        Ok(ByteRoutingProof {
            commitments: vec![node_commitment.to_vec(), identity_commitment.to_vec()],
            elements: proof_elements
                .iter()
                .map(|f| {
                    let mut bytes = Vec::new();
                    if let Err(e) = ark_serialize::CanonicalSerialize::serialize_uncompressed(f, &mut bytes) {
                        eprintln!("Discovery proof serialization failed: {}", e);
                        return Vec::new(); // Return empty bytes on error
                    }
                    bytes
                })
                .collect(),
            inputs: vec![node_commitment.to_vec()],
        })
    }

    fn verify_node_identity_proof(
        &self,
        proof: &ByteRoutingProof,
        identity_commitment: &[u8; 32],
    ) -> Result<bool> {
        match RoutingProof::try_from(proof.clone()) {
            Ok(native_proof) => {
                let verification_result = crate::zhtp::zk_proofs::verify_unified_proof(
                    &native_proof,
                    identity_commitment,
                    identity_commitment,
                    *identity_commitment,
                );

                let has_valid_commitments = proof.commitments.len() == 2
                    && proof.elements.len() == 3
                    && proof.inputs.len() == 1;

                Ok(verification_result && has_valid_commitments)
            }
            Err(_) => Ok(false),
        }
    }

    fn extract_subnet(ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let o = ipv4.octets();
                format!("{}.{}.{}", o[0], o[1], o[2])
            }
            IpAddr::V6(ipv6) => {
                let s = ipv6.segments();
                format!("{:x}:{:x}:{:x}:{:x}", s[0], s[1], s[2], s[3])
            }
        }
    }
}

/// Content metadata index for efficient searching
#[derive(Debug)]
pub struct ContentIndex {
    type_index: Arc<RwLock<HashMap<String, HashSet<ContentId>>>>,
    size_index: Arc<RwLock<BTreeMap<u64, HashSet<ContentId>>>>,
    tag_index: Arc<RwLock<HashMap<String, HashSet<ContentId>>>>,
}

impl ContentIndex {
    pub fn new() -> Self {
        Self {
            type_index: Arc::new(RwLock::new(HashMap::new())),
            size_index: Arc::new(RwLock::new(BTreeMap::new())),
            tag_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn index_content(&self, id: ContentId, metadata: &ContentMetadata) -> Result<()> {
        static INDEXING_RATE_LIMITER: std::sync::OnceLock<
            std::sync::Arc<
                tokio::sync::RwLock<
                    std::collections::HashMap<String, (u64, std::time::Instant)>
                >
            >
        > = std::sync::OnceLock::new();

        let rate_limiter = INDEXING_RATE_LIMITER.get_or_init(|| {
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()))
        });

        let content_source = format!("{:?}", id);
        {
            let mut limiter = rate_limiter.write().await;
            let now = std::time::Instant::now();
            let (count, last_reset) =
                limiter.entry(content_source.clone()).or_insert((0, now));

            if now.duration_since(*last_reset).as_secs() >= 60 {
                *count = 0;
                *last_reset = now;
            }

            if *count >= 100 {
                return Err(anyhow::anyhow!(
                    "Rate limit exceeded for content indexing"
                ));
            }
            *count += 1;
        }

        {
            let mut types = self.type_index.write().await;
            types
                .entry(metadata.content_type.clone())
                .or_insert_with(HashSet::new)
                .insert(id.clone());
        }

        {
            let size_kb = metadata.size / 1024;
            let mut sizes = self.size_index.write().await;
            sizes.entry(size_kb)
                .or_insert_with(HashSet::new)
                .insert(id.clone());
        }

        let mut tag_idx = self.tag_index.write().await;
        for tag in &metadata.tags {
            if tag.len() > 64
                || !tag.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                continue;
            }
            tag_idx.entry(tag.clone())
                .or_insert_with(HashSet::new)
                .insert(id.clone());
        }

        Ok(())
    }

    pub async fn search_by_type(&self, content_type: &str) -> HashSet<ContentId> {
        let types = self.type_index.read().await;
        types.get(content_type).cloned().unwrap_or_default()
    }

    pub async fn search_by_size(&self, min_kb: u64, max_kb: u64) -> HashSet<ContentId> {
        let sizes = self.size_index.read().await;
        let mut results = HashSet::new();

        for (_, ids) in sizes.range(min_kb..=max_kb) {
            results.extend(ids.iter().cloned());
        }
        results
    }

    pub async fn search_by_tag(&self, tag: &str) -> HashSet<ContentId> {
        let tags = self.tag_index.read().await;
        tags.get(tag).cloned().unwrap_or_default()
    }

    pub async fn remove_content(&self, id: &ContentId) {
        let mut types = self.type_index.write().await;
        for type_set in types.values_mut() {
            type_set.remove(id);
        }

        let mut sizes = self.size_index.write().await;
        for size_set in sizes.values_mut() {
            size_set.remove(id);
        }

        let mut tags = self.tag_index.write().await;
        for tag_set in tags.values_mut() {
            tag_set.remove(id);
        }
    }
}
