//! Content Management Types for ZHTP
//! 
//! Content structures with metadata, integrity verification,
//! encryption support, and Web4 protocol integration.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::storage_stub::ContentHash;
use lib_proofs::ZeroKnowledgeProof;
use lib_identity::IdentityId;
use crate::types::{AccessPolicy, EconomicAssessment, StorageRequirements};

/// Content hosted by ZHTP server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerContent {
    /// Content identifier (merged from types/mod.rs)
    pub id: Option<String>,
    /// Content data (may be encrypted)
    pub data: Vec<u8>,
    /// Content metadata
    pub metadata: ContentMetadata,
    /// Content hash for integrity verification
    pub hash: ContentHash,
    /// Zero-knowledge proof of content validity
    pub validity_proof: ZeroKnowledgeProof,
    /// Access control policy for this content
    pub access_policy: AccessPolicy,
    /// Economic requirements (merged from types/mod.rs)
    pub economic_data: Option<EconomicAssessment>,
    /// Storage requirements (merged from types/mod.rs)
    pub storage_requirements: Option<StorageRequirements>,
    /// Content encryption status
    pub encryption_info: Option<EncryptionInfo>,
    /// Content compression info
    pub compression_info: Option<CompressionInfo>,
    /// Content chunks (for large files)
    pub chunks: Option<Vec<ContentChunk>>,
    /// Replication information
    pub replication_info: Option<ReplicationInfo>,
}

/// Content metadata with Web4 extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Content type (MIME type)
    pub content_type: String,
    /// Content encoding (gzip, deflate, br, etc.)
    pub encoding: Option<String>,
    /// Content language
    pub language: Option<String>,
    /// Last modified timestamp
    pub last_modified: u64,
    /// Content creation timestamp
    pub created_at: u64,
    /// Content size in bytes (original, before compression/encryption)
    pub size: u64,
    /// Content version
    pub version: Option<String>,
    /// Content tags for categorization
    pub tags: Vec<String>,
    /// Content author/creator
    pub author: Option<IdentityId>,
    /// Content license information
    pub license: Option<String>,
    /// Content description
    pub description: Option<String>,
    /// Content title
    pub title: Option<String>,
    /// Content category
    pub category: Option<String>,
    /// Maturity rating
    pub maturity_rating: Option<MaturityRating>,
    /// Content quality score (0.0-1.0)
    pub quality_score: Option<f64>,
    /// Popularity metrics
    pub popularity_metrics: Option<PopularityMetrics>,
    /// Economic information
    pub economic_info: Option<ContentEconomicInfo>,
    /// Privacy level (0-100)
    pub privacy_level: u8,
    /// Content integrity checksum
    pub hash: ContentHash,
    /// Encryption information
    pub encryption_info: Option<EncryptionInfo>,
    /// Compression information
    pub compression_info: Option<CompressionInfo>,
    pub integrity_checksum: Option<Vec<u8>>,
    /// Related content references
    pub related_content: Vec<String>,
    /// Content source attribution
    pub source_attribution: Option<SourceAttribution>,
    /// Geographic origin
    pub geographic_origin: Option<String>,
    /// Content expiration (if any)
    pub expires_at: Option<u64>,
}

/// Content encryption information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key derivation method
    pub key_derivation: String,
    /// Encryption parameters
    pub parameters: Vec<u8>,
    /// Whether content is end-to-end encrypted
    pub end_to_end: bool,
    /// Access control for decryption keys
    pub key_access_policy: Option<AccessPolicy>,
    /// Encryption key ID
    pub key_id: Option<String>,
    /// Initialization vector
    pub iv: Option<Vec<u8>>,
}

/// Content compression information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionInfo {
    /// Compression algorithm
    pub algorithm: String,
    /// Compression ratio achieved
    pub ratio: f64,
    /// Original size before compression
    pub original_size: u64,
    /// Compressed size
    pub compressed_size: u64,
    /// Compression level used
    pub level: Option<u8>,
    /// Compression ratio (alias for ratio)
    pub compression_ratio: f64,
}

/// Content chunk for large file handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentChunk {
    /// Chunk index
    pub index: u32,
    /// Chunk data
    pub data: Vec<u8>,
    /// Chunk hash
    pub hash: ContentHash,
    /// Chunk size
    pub size: u64,
    /// Chunk offset in original content
    pub offset: u64,
}

/// Replication information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationInfo {
    /// Replication factor
    pub factor: u8,
    /// Replica locations
    pub replicas: Vec<ReplicaLocation>,
    /// Consistency level
    pub consistency_level: ConsistencyLevel,
    /// Last replication timestamp
    pub last_replicated: u64,
}

/// Replica location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaLocation {
    /// Node ID hosting the replica
    pub node_id: IdentityId,
    /// Node address
    pub address: String,
    /// Replica health status
    pub health: ReplicaHealth,
    /// Last verified timestamp
    pub last_verified: u64,
}

/// Maturity rating for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaturityRating {
    /// General audience
    General,
    /// Parental guidance suggested
    PG,
    /// Parents strongly cautioned
    PG13,
    /// Restricted
    R,
    /// Adults only
    Adult,
    /// Custom rating
    Custom(String),
}

/// Popularity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopularityMetrics {
    /// View count
    pub views: u64,
    /// Like count
    pub likes: u64,
    /// Dislike count
    pub dislikes: u64,
    /// Share count
    pub shares: u64,
    /// Comment count
    pub comments: u64,
    /// Download count
    pub downloads: u64,
    /// Rating average (0.0-5.0)
    pub rating_average: Option<f64>,
    /// Number of ratings
    pub rating_count: u64,
    /// Trending score
    pub trending_score: Option<f64>,
}

/// Economic information for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentEconomicInfo {
    /// Access fee (one-time)
    pub access_fee: Option<u64>,
    /// Subscription fee (recurring)
    pub subscription_fee: Option<u64>,
    /// Revenue sharing percentage for author
    pub revenue_share: Option<f64>,
    /// Total revenue generated
    pub total_revenue: u64,
    /// DAO fee contribution
    pub dao_contribution: u64,
    /// UBI funding contribution
    pub ubi_contribution: u64,
    /// Storage cost per day
    pub storage_cost: u64,
    /// Bandwidth cost per access
    pub bandwidth_cost: u64,
}

/// Source attribution information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAttribution {
    /// Original source URL
    pub source_url: Option<String>,
    /// Original author
    pub original_author: Option<String>,
    /// Original publication date
    pub original_date: Option<u64>,
    /// License information
    pub license: Option<String>,
    /// Attribution text
    pub attribution_text: Option<String>,
}

/// Replica health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicaHealth {
    /// Healthy and accessible
    Healthy,
    /// Temporarily unavailable
    Degraded,
    /// Permanently unavailable
    Failed,
    /// Unknown status
    Unknown,
}

/// Consistency level for replication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    /// Eventual consistency
    Eventual,
    /// Strong consistency
    Strong,
    /// Weak consistency
    Weak,
}

impl ServerContent {
    /// Create new server content
    pub fn new(
        data: Vec<u8>,
        content_type: String,
        author: Option<IdentityId>,
        access_policy: AccessPolicy,
    ) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let hash = lib_crypto::hash_blake3(&data).to_vec();
        
        let metadata = ContentMetadata {
            content_type,
            encoding: None,
            language: None,
            last_modified: timestamp,
            created_at: timestamp,
            size: data.len() as u64,
            version: Some("1.0".to_string()),
            tags: vec![],
            author,
            license: None,
            description: None,
            title: None,
            category: None,
            maturity_rating: Some(MaturityRating::General),
            quality_score: None,
            popularity_metrics: Some(PopularityMetrics::default()),
            economic_info: None,
            privacy_level: 100, // Maximum privacy by default
            hash: hash.clone(),
            encryption_info: None,
            compression_info: None,
            integrity_checksum: Some(lib_crypto::hash_blake3(&data).to_vec()),
            related_content: vec![],
            source_attribution: None,
            geographic_origin: None,
            expires_at: None,
        };

        // TODO: Generate actual validity proof
        let validity_proof = ZeroKnowledgeProof::default();

        Ok(Self {
            id: None, // Will be set when stored
            data,
            metadata,
            hash,
            validity_proof,
            access_policy,
            economic_data: None,
            storage_requirements: None,
            encryption_info: None,
            compression_info: None,
            chunks: None,
            replication_info: None,
        })
    }

    /// Create content with metadata
    pub fn with_metadata(
        data: Vec<u8>,
        metadata: ContentMetadata,
        access_policy: AccessPolicy,
    ) -> anyhow::Result<Self> {
        let hash = lib_crypto::hash_blake3(&data).to_vec();
        let validity_proof = ZeroKnowledgeProof::default();

        Ok(Self {
            id: None, // Will be set when stored
            data,
            metadata,
            hash,
            validity_proof,
            access_policy,
            economic_data: None,
            storage_requirements: None,
            encryption_info: None,
            compression_info: None,
            chunks: None,
            replication_info: None,
        })
    }

    /// Create ServerContent with metadata (merged from types/mod.rs)
    pub fn with_id_and_metadata(
        id: String,
        data: Vec<u8>,
        metadata: ContentMetadata,
        access_control: AccessPolicy,
    ) -> anyhow::Result<Self> {
        let hash = lib_crypto::hash_blake3(&data).to_vec();
        let validity_proof = ZeroKnowledgeProof::default();

        Ok(Self {
            id: Some(id),
            data,
            metadata,
            hash,
            validity_proof,
            access_policy: access_control,
            economic_data: None,
            storage_requirements: Some(StorageRequirements::default()),
            encryption_info: None,
            compression_info: None,
            chunks: None,
            replication_info: None,
        })
    }

    /// Add encryption information
    pub fn with_encryption(mut self, encryption_info: EncryptionInfo) -> Self {
        self.encryption_info = Some(encryption_info);
        self
    }

    /// Add compression information
    pub fn with_compression(mut self, compression_info: CompressionInfo) -> Self {
        self.compression_info = Some(compression_info);
        self
    }

    /// Set content chunks for large files
    pub fn with_chunks(mut self, chunks: Vec<ContentChunk>) -> Self {
        self.chunks = Some(chunks);
        self
    }

    /// Set replication information
    pub fn with_replication(mut self, replication_info: ReplicationInfo) -> Self {
        self.replication_info = Some(replication_info);
        self
    }

    /// Get content size (may be compressed/encrypted)
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Get original content size (before compression/encryption)
    pub fn original_size(&self) -> u64 {
        self.metadata.size
    }

    /// Check if content is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.encryption_info.is_some()
    }

    /// Check if content is compressed
    pub fn is_compressed(&self) -> bool {
        self.compression_info.is_some()
    }

    /// Check if content is chunked
    pub fn is_chunked(&self) -> bool {
        self.chunks.is_some()
    }

    /// Verify content integrity
    pub fn verify_integrity(&self) -> anyhow::Result<bool> {
        let calculated_hash = lib_crypto::hash_blake3(&self.data).to_vec();
        Ok(calculated_hash == self.hash)
    }

    /// Update content data
    pub fn update_data(&mut self, new_data: Vec<u8>) -> anyhow::Result<()> {
        self.data = new_data;
        self.hash = lib_crypto::hash_blake3(&self.data).to_vec();
        self.metadata.size = self.data.len() as u64;
        self.metadata.last_modified = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        self.metadata.integrity_checksum = Some(lib_crypto::hash_blake3(&self.data).to_vec());
        Ok(())
    }

    /// Add tag to content
    pub fn add_tag(&mut self, tag: String) {
        if !self.metadata.tags.contains(&tag) {
            self.metadata.tags.push(tag);
        }
    }

    /// Remove tag from content
    pub fn remove_tag(&mut self, tag: &str) {
        self.metadata.tags.retain(|t| t != tag);
    }

    /// Update popularity metrics
    pub fn update_popularity(&mut self, update: PopularityUpdate) {
        if let Some(ref mut metrics) = self.metadata.popularity_metrics {
            match update {
                PopularityUpdate::View => metrics.views += 1,
                PopularityUpdate::Like => metrics.likes += 1,
                PopularityUpdate::Dislike => metrics.dislikes += 1,
                PopularityUpdate::Share => metrics.shares += 1,
                PopularityUpdate::Comment => metrics.comments += 1,
                PopularityUpdate::Download => metrics.downloads += 1,
                PopularityUpdate::Rating(rating) => {
                    let total_rating = metrics.rating_average.unwrap_or(0.0) * metrics.rating_count as f64;
                    metrics.rating_count += 1;
                    metrics.rating_average = Some((total_rating + rating) / metrics.rating_count as f64);
                }
            }
        }
    }
}

/// Popularity update types
#[derive(Debug, Clone)]
pub enum PopularityUpdate {
    View,
    Like,
    Dislike,
    Share,
    Comment,
    Download,
    Rating(f64),
}

impl Default for PopularityMetrics {
    fn default() -> Self {
        Self {
            views: 0,
            likes: 0,
            dislikes: 0,
            shares: 0,
            comments: 0,
            downloads: 0,
            rating_average: None,
            rating_count: 0,
            trending_score: None,
        }
    }
}

impl EncryptionInfo {
    /// Create standard ZHTP encryption info
    pub fn standard() -> Self {
        Self {
            algorithm: "CRYSTALS-Kyber".to_string(),
            key_derivation: "HKDF-SHA256".to_string(),
            parameters: vec![],
            end_to_end: true,
            key_access_policy: None,
            key_id: None,
            iv: None,
        }
    }

    /// Create encryption info with access policy
    pub fn with_access_policy(mut self, policy: AccessPolicy) -> Self {
        self.key_access_policy = Some(policy);
        self
    }
}

impl CompressionInfo {
    /// Create compression info for given algorithm
    pub fn new(
        algorithm: String,
        original_size: u64,
        compressed_size: u64,
        level: Option<u8>,
    ) -> Self {
        let ratio = if original_size > 0 {
            compressed_size as f64 / original_size as f64
        } else {
            1.0
        };

        Self {
            algorithm,
            ratio,
            original_size,
            compressed_size,
            level,
            compression_ratio: ratio,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_creation() {
        let data = b"Hello, ZHTP World!".to_vec();
        let access_policy = AccessPolicy::public();
        
        let content = ServerContent::new(
            data.clone(),
            "text/plain".to_string(),
            None,
            access_policy,
        ).unwrap();

        assert_eq!(content.data, data);
        assert_eq!(content.metadata.content_type, "text/plain");
        assert_eq!(content.metadata.size, data.len() as u64);
        assert!(content.verify_integrity().unwrap());
    }

    #[test]
    fn test_content_encryption() {
        let data = b"Secret content".to_vec();
        let access_policy = AccessPolicy::private();
        let encryption_info = EncryptionInfo::standard();
        
        let content = ServerContent::new(
            data,
            "text/plain".to_string(),
            None,
            access_policy,
        ).unwrap().with_encryption(encryption_info);

        assert!(content.is_encrypted());
        assert_eq!(content.encryption_info.as_ref().unwrap().algorithm, "CRYSTALS-Kyber");
    }

    #[test]
    fn test_content_compression() {
        let data = b"This is some compressible content that should compress well".to_vec();
        let access_policy = AccessPolicy::public();
        let compression_info = CompressionInfo::new(
            "gzip".to_string(),
            data.len() as u64,
            30, // Simulated compressed size
            Some(6),
        );
        
        let content = ServerContent::new(
            data,
            "text/plain".to_string(),
            None,
            access_policy,
        ).unwrap().with_compression(compression_info);

        assert!(content.is_compressed());
        assert!(content.compression_info.as_ref().unwrap().ratio < 1.0);
    }

    #[test]
    fn test_popularity_updates() {
        let data = b"Popular content".to_vec();
        let access_policy = AccessPolicy::public();
        
        let mut content = ServerContent::new(
            data,
            "text/plain".to_string(),
            None,
            access_policy,
        ).unwrap();

        content.update_popularity(PopularityUpdate::View);
        content.update_popularity(PopularityUpdate::Like);
        content.update_popularity(PopularityUpdate::Rating(4.5));

        let metrics = content.metadata.popularity_metrics.as_ref().unwrap();
        assert_eq!(metrics.views, 1);
        assert_eq!(metrics.likes, 1);
        assert_eq!(metrics.rating_count, 1);
        assert_eq!(metrics.rating_average, Some(4.5));
    }

    #[test]
    fn test_content_tags() {
        let data = b"Tagged content".to_vec();
        let access_policy = AccessPolicy::public();
        
        let mut content = ServerContent::new(
            data,
            "text/plain".to_string(),
            None,
            access_policy,
        ).unwrap();

        content.add_tag("web4".to_string());
        content.add_tag("zhtp".to_string());
        content.add_tag("web4".to_string()); // Duplicate should be ignored

        assert_eq!(content.metadata.tags.len(), 2);
        assert!(content.metadata.tags.contains(&"web4".to_string()));
        assert!(content.metadata.tags.contains(&"zhtp".to_string()));

        content.remove_tag("web4");
        assert_eq!(content.metadata.tags.len(), 1);
        assert!(!content.metadata.tags.contains(&"web4".to_string()));
    }

    #[test]
    fn test_content_update() {
        let original_data = b"Original content".to_vec();
        let access_policy = AccessPolicy::public();
        
        let mut content = ServerContent::new(
            original_data,
            "text/plain".to_string(),
            None,
            access_policy,
        ).unwrap();

        let original_hash = content.hash.clone();
        let new_data = b"Updated content".to_vec();
        
        content.update_data(new_data.clone()).unwrap();
        
        assert_eq!(content.data, new_data);
        assert_ne!(content.hash, original_hash);
        assert!(content.verify_integrity().unwrap());
    }
}
