//! # Semantic Tag Index — Tag-to-Shard Mapping
//!
//! Maps (tag_id, tag_id, ...) tuples to sets of ShardIds, enabling the
//! Semantic Channeling layer to discover which DHT shards contain content
//! matching a given set of semantic tags.
//!
//! This is the *storage-side complement* to `lib-neural-mesh::semantic_channeling`.
//! The neural mesh builds and traverses the tag graph; this module persists
//! the tag→shard mappings so they survive node restarts and are discoverable
//! via the DHT.
//!
//! ## Architecture
//!
//! ```text
//! ╔══════════════════════════════════════════════════════════════╗
//! ║                SEMANTIC TAG INDEX                            ║
//! ╠══════════════════════════════════════════════════════════════╣
//! ║                                                              ║
//! ║  TagKey([tag_a, tag_b]) ─────► ShardSet{shard1, shard2}    ║
//! ║  TagKey([tag_c])        ─────► ShardSet{shard3}             ║
//! ║  TagKey([tag_a, tag_c]) ─────► ShardSet{shard1, shard3}    ║
//! ║                                                              ║
//! ║  Single-tag index for fast lookups:                          ║
//! ║  tag_a ──► ShardSet{shard1, shard2}                         ║
//! ║  tag_b ──► ShardSet{shard1}                                  ║
//! ║                                                              ║
//! ║  DHT-persistable via serde (BLAKE3 content-addressed)       ║
//! ║                                                              ║
//! ╚══════════════════════════════════════════════════════════════╝
//! ```
//!
//! ## Privacy Model
//!
//! Tag IDs are BLAKE3 hashes of semantic vectors — they reveal topic
//! similarity structure but NOT content. Shard IDs are opaque 32-byte
//! identifiers. The index maps topics→locations without leaking data.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

// ─── Core Types ──────────────────────────────────────────────────────

/// Opaque 32-byte tag identifier (matches lib-neural-mesh TagId format)
pub type TagId = [u8; 32];

/// Opaque 32-byte shard identifier (BLAKE3 hash of shard content)
pub type ShardId = [u8; 32];

/// A sorted, deduplicated tuple of tag IDs used as a compound index key.
///
/// Using BTreeSet ensures canonical ordering regardless of insertion order,
/// so `(tag_a, tag_b)` and `(tag_b, tag_a)` map to the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TagKey(pub BTreeSet<TagId>);

impl TagKey {
    /// Create a TagKey from a slice of tag IDs (auto-sorted, deduped)
    pub fn new(tags: &[TagId]) -> Self {
        Self(tags.iter().copied().collect())
    }

    /// Create a single-tag key
    pub fn single(tag: TagId) -> Self {
        let mut set = BTreeSet::new();
        set.insert(tag);
        Self(set)
    }

    /// Number of tags in this key
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is this an empty key?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if this key contains a specific tag
    pub fn contains(&self, tag: &TagId) -> bool {
        self.0.contains(tag)
    }

    /// Merge two keys (union)
    pub fn merge(&self, other: &TagKey) -> TagKey {
        let mut merged = self.0.clone();
        for tag in &other.0 {
            merged.insert(*tag);
        }
        TagKey(merged)
    }

    /// Compute a deterministic hash of this key for storage addressing
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for tag in &self.0 {
            hasher.update(tag);
        }
        *hasher.finalize().as_bytes()
    }

    /// Short hex representation for logging
    pub fn short_hex(&self) -> String {
        if self.0.is_empty() {
            return "empty".to_string();
        }
        let first = self.0.iter().next().unwrap();
        let hex: String = first[..4].iter().map(|b| format!("{:02x}", b)).collect();
        if self.0.len() == 1 {
            format!("tag:{}", hex)
        } else {
            format!("tags:{}+{}", hex, self.0.len() - 1)
        }
    }
}

impl std::fmt::Display for TagKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short_hex())
    }
}

/// A set of shard IDs associated with a tag combination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardSet {
    /// Shard IDs that contain content matching the tag key
    pub shards: HashSet<ShardId>,
    /// When this mapping was last updated (ms since epoch)
    pub updated_at: u64,
    /// How many content items contributed to this mapping
    pub content_count: u32,
}

impl ShardSet {
    /// Create a new shard set
    pub fn new() -> Self {
        Self {
            shards: HashSet::new(),
            updated_at: now_ms(),
            content_count: 0,
        }
    }

    /// Add a shard to this set
    pub fn insert(&mut self, shard: ShardId) {
        self.shards.insert(shard);
        self.updated_at = now_ms();
    }

    /// Remove a shard from this set
    pub fn remove(&mut self, shard: &ShardId) -> bool {
        let removed = self.shards.remove(shard);
        if removed {
            self.updated_at = now_ms();
        }
        removed
    }

    /// Number of shards in this set
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    /// Is this set empty?
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }
}

impl Default for ShardSet {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Semantic Tag Index ──────────────────────────────────────────────

/// The Semantic Tag Index — maps tag combinations to shard locations.
///
/// Maintains both a compound index (multi-tag keys) and a single-tag
/// reverse index for fast lookups. Designed to be serializable for
/// DHT persistence.
///
/// ## Usage
///
/// ```rust
/// use lib_storage::semantic_tag_index::{SemanticTagIndex, TagKey};
///
/// let mut index = SemanticTagIndex::new();
///
/// let tag_a = [0xAA; 32];
/// let tag_b = [0xBB; 32];
/// let shard = [0x01; 32];
///
/// // Index a content item with tags [A, B] stored in shard
/// index.index_content(&[tag_a, tag_b], &[shard]);
///
/// // Query: which shards have content tagged with A?
/// let shards = index.query_single(&tag_a);
/// assert!(shards.contains(&shard));
///
/// // Query: which shards have content tagged with BOTH A and B?
/// let shards = index.query_intersection(&[tag_a, tag_b]);
/// assert!(shards.contains(&shard));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTagIndex {
    /// Compound index: sorted tag tuple → shard set
    compound_index: HashMap<TagKey, ShardSet>,

    /// Single-tag reverse index: one tag → shard set
    /// (fast path for single-tag queries)
    single_tag_index: HashMap<TagId, ShardSet>,

    /// Total content items indexed
    total_indexed: u64,

    /// Total unique tag keys
    total_keys: u64,
}

impl SemanticTagIndex {
    /// Create a new empty index
    pub fn new() -> Self {
        Self {
            compound_index: HashMap::new(),
            single_tag_index: HashMap::new(),
            total_indexed: 0,
            total_keys: 0,
        }
    }

    /// Index a content item: associate its tag set with its shard locations.
    ///
    /// This creates/updates entries in both the compound index (the full tag
    /// tuple) and the single-tag index (each individual tag).
    pub fn index_content(&mut self, tag_ids: &[TagId], shard_ids: &[ShardId]) {
        if tag_ids.is_empty() || shard_ids.is_empty() {
            return;
        }

        // 1. Compound index: full tag set → shards
        let key = TagKey::new(tag_ids);
        let entry = self.compound_index.entry(key).or_insert_with(|| {
            self.total_keys += 1;
            ShardSet::new()
        });
        for &shard in shard_ids {
            entry.insert(shard);
        }
        entry.content_count += 1;

        // 2. Single-tag index: each individual tag → shards
        for &tag in tag_ids {
            let single_entry = self.single_tag_index.entry(tag).or_insert_with(ShardSet::new);
            for &shard in shard_ids {
                single_entry.insert(shard);
            }
            single_entry.content_count += 1;
        }

        // 3. Pairwise sub-keys for 2-tag combinations (enables AND queries)
        if tag_ids.len() >= 2 {
            for i in 0..tag_ids.len() {
                for j in (i + 1)..tag_ids.len() {
                    let pair_key = TagKey::new(&[tag_ids[i], tag_ids[j]]);
                    let pair_entry = self.compound_index.entry(pair_key).or_insert_with(|| {
                        self.total_keys += 1;
                        ShardSet::new()
                    });
                    for &shard in shard_ids {
                        pair_entry.insert(shard);
                    }
                    pair_entry.content_count += 1;
                }
            }
        }

        self.total_indexed += 1;
    }

    /// Remove content from the index (when content is deleted or shards are moved)
    pub fn remove_content(&mut self, tag_ids: &[TagId], shard_ids: &[ShardId]) {
        // Remove from compound index
        let key = TagKey::new(tag_ids);
        if let Some(entry) = self.compound_index.get_mut(&key) {
            for shard in shard_ids {
                entry.remove(shard);
            }
            if entry.is_empty() {
                self.compound_index.remove(&key);
                self.total_keys = self.total_keys.saturating_sub(1);
            }
        }

        // Remove from single-tag index
        for tag in tag_ids {
            if let Some(entry) = self.single_tag_index.get_mut(tag) {
                for shard in shard_ids {
                    entry.remove(shard);
                }
                if entry.is_empty() {
                    self.single_tag_index.remove(tag);
                }
            }
        }
    }

    /// Query: which shards have content with this single tag?
    pub fn query_single(&self, tag: &TagId) -> HashSet<ShardId> {
        self.single_tag_index
            .get(tag)
            .map(|s| s.shards.clone())
            .unwrap_or_default()
    }

    /// Query: which shards have content with ALL of these tags (intersection)?
    ///
    /// If a compound key exists, uses it directly. Otherwise, intersects
    /// the single-tag results.
    pub fn query_intersection(&self, tags: &[TagId]) -> HashSet<ShardId> {
        if tags.is_empty() {
            return HashSet::new();
        }

        if tags.len() == 1 {
            return self.query_single(&tags[0]);
        }

        // Try compound index first (exact match)
        let key = TagKey::new(tags);
        if let Some(entry) = self.compound_index.get(&key) {
            return entry.shards.clone();
        }

        // Fallback: intersect single-tag results
        let mut result: Option<HashSet<ShardId>> = None;
        for tag in tags {
            let shards = self.query_single(tag);
            result = Some(match result {
                Some(existing) => existing.intersection(&shards).copied().collect(),
                None => shards,
            });
        }
        result.unwrap_or_default()
    }

    /// Query: which shards have content with ANY of these tags (union)?
    pub fn query_union(&self, tags: &[TagId]) -> HashSet<ShardId> {
        let mut result = HashSet::new();
        for tag in tags {
            result.extend(self.query_single(tag));
        }
        result
    }

    /// Get the number of shards associated with a tag
    pub fn tag_shard_count(&self, tag: &TagId) -> usize {
        self.single_tag_index
            .get(tag)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Get all known tags in the index
    pub fn all_tags(&self) -> Vec<TagId> {
        self.single_tag_index.keys().copied().collect()
    }

    /// Get all known compound keys in the index
    pub fn all_keys(&self) -> Vec<&TagKey> {
        self.compound_index.keys().collect()
    }

    /// Number of unique tags indexed
    pub fn unique_tag_count(&self) -> usize {
        self.single_tag_index.len()
    }

    /// Number of compound keys
    pub fn compound_key_count(&self) -> usize {
        self.compound_index.len()
    }

    /// Total content items indexed
    pub fn total_indexed(&self) -> u64 {
        self.total_indexed
    }

    /// Serialize the index for DHT persistence
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("Serialize tag index: {}", e))
    }

    /// Deserialize from DHT persistence
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("Deserialize tag index: {}", e))
    }

    /// Merge another index into this one (for distributed index sync)
    pub fn merge(&mut self, other: &SemanticTagIndex) {
        for (key, shard_set) in &other.compound_index {
            let entry = self.compound_index.entry(key.clone()).or_insert_with(|| {
                self.total_keys += 1;
                ShardSet::new()
            });
            for &shard in &shard_set.shards {
                entry.insert(shard);
            }
            entry.content_count += shard_set.content_count;
        }

        for (tag, shard_set) in &other.single_tag_index {
            let entry = self.single_tag_index.entry(*tag).or_insert_with(ShardSet::new);
            for &shard in &shard_set.shards {
                entry.insert(shard);
            }
            entry.content_count += shard_set.content_count;
        }

        self.total_indexed += other.total_indexed;
    }

    /// Summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "SemanticTagIndex: {} tags, {} compound keys, {} total indexed",
            self.unique_tag_count(),
            self.compound_key_count(),
            self.total_indexed,
        )
    }
}

impl Default for SemanticTagIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_key_canonical_ordering() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];

        let key1 = TagKey::new(&[a, b]);
        let key2 = TagKey::new(&[b, a]);

        assert_eq!(key1, key2, "TagKey should be order-independent");
        assert_eq!(key1.content_hash(), key2.content_hash());
    }

    #[test]
    fn test_tag_key_single() {
        let tag = [0x42; 32];
        let key = TagKey::single(tag);
        assert_eq!(key.len(), 1);
        assert!(key.contains(&tag));
    }

    #[test]
    fn test_tag_key_merge() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        let c = [0xCC; 32];

        let k1 = TagKey::new(&[a, b]);
        let k2 = TagKey::new(&[b, c]);
        let merged = k1.merge(&k2);

        assert_eq!(merged.len(), 3);
        assert!(merged.contains(&a));
        assert!(merged.contains(&b));
        assert!(merged.contains(&c));
    }

    #[test]
    fn test_index_and_query_single() {
        let mut index = SemanticTagIndex::new();

        let tag_a = [0xAA; 32];
        let shard_1 = [0x01; 32];
        let shard_2 = [0x02; 32];

        index.index_content(&[tag_a], &[shard_1, shard_2]);

        let result = index.query_single(&tag_a);
        assert!(result.contains(&shard_1));
        assert!(result.contains(&shard_2));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_index_and_query_compound() {
        let mut index = SemanticTagIndex::new();

        let tag_a = [0xAA; 32];
        let tag_b = [0xBB; 32];
        let tag_c = [0xCC; 32];
        let shard_1 = [0x01; 32];
        let shard_2 = [0x02; 32];

        // Content 1 has tags A + B, in shard 1
        index.index_content(&[tag_a, tag_b], &[shard_1]);
        // Content 2 has tags B + C, in shard 2
        index.index_content(&[tag_b, tag_c], &[shard_2]);

        // Query: which shards have A AND B?
        let result = index.query_intersection(&[tag_a, tag_b]);
        assert!(result.contains(&shard_1));
        assert!(!result.contains(&shard_2));

        // Query: which shards have B? (both)
        let result = index.query_single(&tag_b);
        assert!(result.contains(&shard_1));
        assert!(result.contains(&shard_2));

        // Query: which shards have A OR C?
        let result = index.query_union(&[tag_a, tag_c]);
        assert!(result.contains(&shard_1));
        assert!(result.contains(&shard_2));
    }

    #[test]
    fn test_remove_content() {
        let mut index = SemanticTagIndex::new();

        let tag = [0xAA; 32];
        let shard = [0x01; 32];

        index.index_content(&[tag], &[shard]);
        assert_eq!(index.query_single(&tag).len(), 1);

        index.remove_content(&[tag], &[shard]);
        assert_eq!(index.query_single(&tag).len(), 0);
    }

    #[test]
    fn test_index_serialization_roundtrip() {
        let mut index = SemanticTagIndex::new();

        let tag_a = [0xAA; 32];
        let tag_b = [0xBB; 32];
        let shard = [0x01; 32];

        index.index_content(&[tag_a, tag_b], &[shard]);

        let bytes = index.to_bytes().unwrap();
        let restored = SemanticTagIndex::from_bytes(&bytes).unwrap();

        assert_eq!(restored.unique_tag_count(), index.unique_tag_count());
        assert_eq!(restored.total_indexed(), index.total_indexed());

        let result = restored.query_intersection(&[tag_a, tag_b]);
        assert!(result.contains(&shard));
    }

    #[test]
    fn test_index_merge() {
        let mut index_a = SemanticTagIndex::new();
        let mut index_b = SemanticTagIndex::new();

        let tag = [0xAA; 32];
        let shard_1 = [0x01; 32];
        let shard_2 = [0x02; 32];

        index_a.index_content(&[tag], &[shard_1]);
        index_b.index_content(&[tag], &[shard_2]);

        index_a.merge(&index_b);

        let result = index_a.query_single(&tag);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&shard_1));
        assert!(result.contains(&shard_2));
    }

    #[test]
    fn test_empty_queries() {
        let index = SemanticTagIndex::new();

        assert!(index.query_single(&[0xFF; 32]).is_empty());
        assert!(index.query_intersection(&[]).is_empty());
        assert!(index.query_union(&[]).is_empty());
    }

    #[test]
    fn test_stats() {
        let mut index = SemanticTagIndex::new();

        let tag_a = [0xAA; 32];
        let tag_b = [0xBB; 32];

        index.index_content(&[tag_a, tag_b], &[[0x01; 32]]);
        index.index_content(&[tag_a], &[[0x02; 32]]);

        assert_eq!(index.unique_tag_count(), 2);
        assert_eq!(index.total_indexed(), 2);
        assert!(index.compound_key_count() >= 1);
        assert_eq!(index.tag_shard_count(&tag_a), 2); // in both shards
        assert_eq!(index.tag_shard_count(&tag_b), 1); // in one shard
    }

    #[test]
    fn test_tag_key_display() {
        let key = TagKey::new(&[[0xDE, 0xAD, 0xBE, 0xEF].iter().copied()
            .chain(std::iter::repeat(0u8).take(28)).collect::<Vec<_>>().try_into().unwrap()]);
        let display = format!("{}", key);
        assert!(display.starts_with("tag:"));
    }
}
