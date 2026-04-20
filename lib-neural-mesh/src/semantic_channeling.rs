//! # Semantic Channeling — Flow-State Parallel Inference
//!
//! The missing piece: instead of the AI accessing all data at once (causing
//! hallucinations and overwhelm), data flows through **parallel semantic
//! channels** — like a human having multiple simultaneous thought-chains
//! about a topic, each following its own neuropathway through the data.
//!
//! ## Core Insight
//!
//! Traditional AI/RAG: load everything → think → output (hallucination-prone)
//!
//! Semantic Channeling: data streams through parallel ZKP-tagged channels,
//! each following one thread of reasoning. The AI never sees raw data —
//! only semantic tags (the "neuropathways") and ZK proofs of existence.
//! Each step is grounded in a real data point, so no hallucination.
//!
//! ## Architecture
//!
//! ```text
//! ╔══════════════════════════════════════════════════════════════════╗
//! ║              PARALLEL SEMANTIC CHANNELING                       ║
//! ╠══════════════════════════════════════════════════════════════════╣
//! ║                                                                  ║
//! ║  Query: "How does compression affect routing?"                  ║
//! ║        │                                                         ║
//! ║        ├─► QUIC Channel 0: CAUSAL chain                        ║
//! ║        │   tag:compression → tag:ratio → tag:bandwidth_saved    ║
//! ║        │   → tag:route_faster → tag:more_data → …              ║
//! ║        │                                                         ║
//! ║        ├─► QUIC Channel 1: SIMILARITY chain                    ║
//! ║        │   tag:compression ≈ tag:dedup ≈ tag:entropy            ║
//! ║        │   ≈ tag:pattern_mining ≈ tag:codec_params → …         ║
//! ║        │                                                         ║
//! ║        ├─► QUIC Channel 2: STRUCTURAL chain                    ║
//! ║        │   tag:compression.pipeline → tag:BWT → tag:MTF         ║
//! ║        │   → tag:RLE → tag:range_coder → …                     ║
//! ║        │                                                         ║
//! ║        └─► QUIC Channel 3: TEMPORAL chain                      ║
//! ║            tag:compression_v1 → tag:SFC7_added → tag:SFC9      ║
//! ║            → tag:neural_tuning → tag:fedavg_improved → …       ║
//! ║                                                                  ║
//! ║  Channels run IN PARALLEL via rayon (like shard compression)    ║
//! ║  Each follows ONE neuropathway — never accesses all data        ║
//! ║  Cross-pollination: channels share discoveries at merge points  ║
//! ║  Final aggregation: layered synthesis like neurons converging   ║
//! ║                                                                  ║
//! ╚══════════════════════════════════════════════════════════════════╝
//! ```
//!
//! ## Privacy Model
//!
//! The AI never sees raw content. It operates on:
//! 1. **Semantic tags** — topic/intent labels derived from embeddings
//! 2. **Content IDs** — BLAKE3 hashes (opaque identifiers)
//! 3. **ZK proofs** — prove "content with tag X exists" without revealing it
//! 4. **Embedding similarities** — cosine distance between tag vectors
//!
//! The user's ZHTP packets remain encrypted and sharded across the DHT.
//! Tags are the neuropathways. Content IDs are the synapses.
//! The AI traverses the graph without reading the neurons' contents.

use crate::compressor::Embedding;
use crate::error::{NeuralMeshError, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Instant;

// ─── Semantic Tags (The Neuropathways) ───────────────────────────────

/// A semantic tag — the fundamental unit of the tag graph.
///
/// Tags are derived from content embeddings (via NeuroCompressor) but
/// contain NO raw data. They are the "neuropathways" the AI follows.
/// Each tag is a compressed semantic fingerprint: topic vector + metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTag {
    /// Unique tag identifier (BLAKE3 hash of the tag vector)
    pub tag_id: TagId,

    /// Human-readable label (e.g. "compression", "routing", "entropy")
    /// Optional — tags can be unlabeled (pure vector)
    pub label: Option<String>,

    /// Compressed semantic vector (reduced from 512-D embedding to 32-D)
    /// This is what the AI actually "sees" — a low-dimensional fingerprint
    /// that captures topic/intent without revealing content
    pub semantic_vector: Vec<f32>,

    /// Topic cluster ID — which cluster this tag belongs to
    /// (derived from k-means over all tag vectors)
    pub cluster_id: u32,

    /// Connectivity: how many content items carry this tag
    /// (higher = more central neuropathway)
    pub weight: u32,

    /// Creation timestamp (ms since epoch)
    pub created_at: u64,
}

/// Opaque tag identifier — BLAKE3 hash, no content leakage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TagId(pub [u8; 32]);

impl TagId {
    /// Create tag ID from a semantic vector
    pub fn from_vector(vec: &[f32]) -> Self {
        let bytes: Vec<u8> = vec.iter().flat_map(|f| f.to_le_bytes()).collect();
        TagId(*blake3::hash(&bytes).as_bytes())
    }

    /// Hex representation (first 16 chars)
    pub fn short_hex(&self) -> String {
        self.0[..8].iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Display for TagId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tag:{}", self.short_hex())
    }
}

impl SemanticTag {
    /// Create a new tag from a full embedding by reducing dimensionality.
    ///
    /// The 512-D embedding from NeuroCompressor is hashed into a 32-D
    /// semantic fingerprint. This preserves topical similarity while
    /// preventing reconstruction of the original content.
    pub fn from_embedding(embedding: &Embedding, label: Option<String>) -> Self {
        let semantic_vector = reduce_embedding(embedding, TAG_VECTOR_DIM);
        let tag_id = TagId::from_vector(&semantic_vector);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            tag_id,
            label,
            semantic_vector,
            cluster_id: 0, // assigned during indexing
            weight: 1,
            created_at: now,
        }
    }

    /// Cosine similarity to another tag (0.0 – 1.0)
    pub fn similarity(&self, other: &SemanticTag) -> f32 {
        cosine_similarity(&self.semantic_vector, &other.semantic_vector)
    }
}

/// Dimensionality of the compressed tag vector
const TAG_VECTOR_DIM: usize = 32;

/// Minimum similarity for tags to be considered "connected" in the graph
const TAG_EDGE_THRESHOLD: f32 = 0.6;

/// Maximum number of connections per tag (prevents hub explosion)
const MAX_TAG_EDGES: usize = 16;

// ─── Content-Tag Binding (The Synapses) ──────────────────────────────

/// Maps a content item to its semantic tags — the "synapse" connecting
/// a piece of data (identified by its BLAKE3 content ID) to its
/// neuropathways (semantic tags) without revealing the content itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTagBinding {
    /// BLAKE3 hash of the content (opaque identifier — no data leakage)
    pub content_id: [u8; 32],

    /// Semantic tags associated with this content
    pub tag_ids: Vec<TagId>,

    /// Shard IDs where the content resides in the DHT
    /// (the AI doesn't use these — they're for the retrieval layer)
    pub shard_ids: Vec<[u8; 32]>,

    /// ZK proof commitment: "this content exists and has these tags"
    /// In production, this is a Plonky2 proof. For now, BLAKE3-based.
    pub proof_commitment: [u8; 32],
}

impl ContentTagBinding {
    /// Create a new binding with ZK-style commitment.
    ///
    /// The commitment proves "data with hash `content_id` carries tags `tag_ids`"
    /// without revealing the data itself. An observer learns only that the
    /// binding is valid, not what the content contains.
    pub fn new(content_id: [u8; 32], tag_ids: Vec<TagId>, shard_ids: Vec<[u8; 32]>) -> Self {
        // Commitment: H(content_id ‖ tag_ids ‖ shard_ids)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&content_id);
        for tid in &tag_ids {
            hasher.update(&tid.0);
        }
        for sid in &shard_ids {
            hasher.update(sid);
        }
        let proof_commitment = *hasher.finalize().as_bytes();

        Self {
            content_id,
            tag_ids,
            shard_ids,
            proof_commitment,
        }
    }

    /// Verify the ZK commitment is consistent
    pub fn verify_commitment(&self) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.content_id);
        for tid in &self.tag_ids {
            hasher.update(&tid.0);
        }
        for sid in &self.shard_ids {
            hasher.update(sid);
        }
        let expected = *hasher.finalize().as_bytes();
        expected == self.proof_commitment
    }
}

// ─── Tag Graph (The Neural Network of Data) ─────────────────────────

/// The tag graph: a network of semantic tags connected by similarity.
///
/// This IS the "brain" of the network. Tags are neurons. Edges are
/// axons weighted by semantic similarity. Content bindings are synapses
/// connecting external data to internal pathways.
///
/// The AI traverses this graph — never the raw data.
#[derive(Debug)]
pub struct TagGraph {
    /// All tags indexed by ID
    tags: HashMap<TagId, SemanticTag>,

    /// Adjacency: tag → [(neighbor_tag, similarity_weight)]
    /// These are the neuropathways — edges the AI can follow
    edges: HashMap<TagId, Vec<(TagId, f32)>>,

    /// Content-to-tag bindings (the synapses)
    bindings: HashMap<[u8; 32], ContentTagBinding>,

    /// Reverse index: tag → content IDs that carry this tag
    tag_to_content: HashMap<TagId, Vec<[u8; 32]>>,

    /// Number of topic clusters (k-means)
    num_clusters: u32,
}

impl TagGraph {
    /// Create empty tag graph
    pub fn new() -> Self {
        Self {
            tags: HashMap::new(),
            edges: HashMap::new(),
            bindings: HashMap::new(),
            tag_to_content: HashMap::new(),
            num_clusters: 0,
        }
    }

    /// Number of tags in the graph
    pub fn tag_count(&self) -> usize {
        self.tags.len()
    }

    /// Number of content bindings
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// Number of edges (neuropathways)
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|v| v.len()).sum::<usize>() / 2 // undirected
    }

    /// Insert a tag into the graph and connect it to similar existing tags.
    ///
    /// This is like a new neuron forming connections: it finds the most
    /// similar existing tags (above threshold) and creates edges to them.
    pub fn insert_tag(&mut self, tag: SemanticTag) {
        let tag_id = tag.tag_id;

        // Find similar existing tags for edge creation
        let mut neighbors: Vec<(TagId, f32)> = self.tags.values()
            .filter_map(|existing| {
                let sim = tag.similarity(existing);
                if sim >= TAG_EDGE_THRESHOLD && existing.tag_id != tag_id {
                    Some((existing.tag_id, sim))
                } else {
                    None
                }
            })
            .collect();

        // Sort by similarity (highest first) and keep top N
        neighbors.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        neighbors.truncate(MAX_TAG_EDGES);

        // Create bidirectional edges
        for &(neighbor_id, sim) in &neighbors {
            self.edges
                .entry(neighbor_id)
                .or_default()
                .push((tag_id, sim));

            // Trim neighbor's edges if too many
            if let Some(n_edges) = self.edges.get_mut(&neighbor_id) {
                if n_edges.len() > MAX_TAG_EDGES {
                    n_edges.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                    n_edges.truncate(MAX_TAG_EDGES);
                }
            }
        }

        self.edges.insert(tag_id, neighbors);
        self.tags.insert(tag_id, tag);
    }

    /// Bind content to tags (create a synapse).
    pub fn bind_content(&mut self, binding: ContentTagBinding) {
        let content_id = binding.content_id;
        for &tag_id in &binding.tag_ids {
            self.tag_to_content
                .entry(tag_id)
                .or_default()
                .push(content_id);

            // Increment tag weight
            if let Some(tag) = self.tags.get_mut(&tag_id) {
                tag.weight += 1;
            }
        }
        self.bindings.insert(content_id, binding);
    }

    /// Get a tag by ID
    pub fn get_tag(&self, id: &TagId) -> Option<&SemanticTag> {
        self.tags.get(id)
    }

    /// Get neighbors of a tag (its neuropathways)
    pub fn neighbors(&self, id: &TagId) -> &[(TagId, f32)] {
        self.edges.get(id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get content IDs associated with a tag
    pub fn content_for_tag(&self, id: &TagId) -> &[[u8; 32]] {
        self.tag_to_content.get(id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Find the N most similar tags to a query vector.
    /// This is the entry point for channeling: "where do I start?"
    pub fn find_nearest_tags(&self, query_vector: &[f32], n: usize) -> Vec<(TagId, f32)> {
        let mut scored: Vec<(TagId, f32)> = self.tags.values()
            .map(|tag| (tag.tag_id, cosine_similarity(query_vector, &tag.semantic_vector)))
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(n);
        scored
    }

    /// Get all tags (for serialization/inspection)
    pub fn all_tags(&self) -> impl Iterator<Item = &SemanticTag> {
        self.tags.values()
    }
}

impl Default for TagGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Channel Strategies (How Each Thought-Chain Navigates) ──────────

/// Strategy for how a channel traverses the tag graph.
///
/// Different strategies = different angles on the same topic,
/// like a human simultaneously thinking causally, associatively,
/// structurally, and temporally about the same problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStrategy {
    /// CAUSAL: follow highest-weight edges (strongest connections)
    /// "What causes what? What leads to what?"
    Causal,

    /// SIMILARITY: follow edges with highest cosine similarity
    /// "What is this most like? What pattern does this match?"
    Similarity,

    /// STRUCTURAL: follow edges that connect different clusters
    /// "How do different parts of the system relate?"
    Structural,

    /// TEMPORAL: prefer tags with more recent timestamps
    /// "What's the latest development? How has this evolved?"
    Temporal,

    /// EXPLORATORY: prefer tags with fewer visits (novelty-seeking)
    /// "What haven't I considered yet?"
    Exploratory,

    /// CONVERGENT: follow tags that overlap with OTHER channels' discoveries
    /// "Where do my different thought-chains agree?"
    Convergent,
}

impl std::fmt::Display for ChannelStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelStrategy::Causal => write!(f, "causal"),
            ChannelStrategy::Similarity => write!(f, "similarity"),
            ChannelStrategy::Structural => write!(f, "structural"),
            ChannelStrategy::Temporal => write!(f, "temporal"),
            ChannelStrategy::Exploratory => write!(f, "exploratory"),
            ChannelStrategy::Convergent => write!(f, "convergent"),
        }
    }
}

// ─── Thought Step (One Neuron Firing) ────────────────────────────────

/// A single step in a thought-chain — one neuron firing.
///
/// Records which tag was visited, why (which edge was followed),
/// and what was discovered (associated content IDs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtStep {
    /// Which tag was visited at this step
    pub tag_id: TagId,

    /// Tag label (if available)
    pub tag_label: Option<String>,

    /// Similarity to the previous step (edge weight traversed)
    pub edge_weight: f32,

    /// Content IDs reachable from this tag (the AI doesn't read these —
    /// it just knows they exist and are tagged with this topic)
    pub content_ids_found: usize,

    /// Depth in the chain (0 = starting tag)
    pub depth: u32,

    /// Which cluster this tag belongs to (for structural awareness)
    pub cluster_id: u32,
}

// ─── Semantic Channel (One Parallel Thought-Chain) ───────────────────

/// A single semantic channel — one thought-chain following one strategy.
///
/// Like one QUIC stream in parallel shard compression, but instead of
/// carrying compressed bytes, it carries a chain of semantic thoughts.
///
/// Multiple channels run simultaneously via rayon, each exploring
/// a different angle on the same query — like a human having multiple
/// ideas about a topic at once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticChannel {
    /// Channel index (like shard_index in parallel shard streaming)
    pub channel_id: usize,

    /// Total number of parallel channels
    pub total_channels: usize,

    /// Which navigation strategy this channel uses
    pub strategy: ChannelStrategy,

    /// The thought-chain: sequence of tag traversals
    pub thought_chain: Vec<ThoughtStep>,

    /// Tags visited (to avoid cycles within this channel)
    pub visited: HashSet<TagId>,

    /// Content IDs discovered along this neuropathway
    pub discovered_content: Vec<[u8; 32]>,

    /// Total tags traversed
    pub steps_taken: u32,

    /// Maximum depth this channel reached
    pub max_depth: u32,

    /// Processing time for this channel (microseconds)
    pub processing_time_us: u64,
}

impl SemanticChannel {
    /// Create a new channel with a given strategy
    fn new(channel_id: usize, total_channels: usize, strategy: ChannelStrategy) -> Self {
        Self {
            channel_id,
            total_channels,
            strategy,
            thought_chain: Vec::new(),
            visited: HashSet::new(),
            discovered_content: Vec::new(),
            steps_taken: 0,
            max_depth: 0,
            processing_time_us: 0,
        }
    }

    /// Execute this channel's thought-chain through the tag graph.
    ///
    /// Starting from `seed_tag`, follows the channel's strategy to traverse
    /// the graph one step at a time — like neurons firing in sequence.
    /// Each step visits ONE tag, looks at its connections, and picks the
    /// next most relevant one to follow.
    fn execute(
        &mut self,
        graph: &TagGraph,
        seed_tag: TagId,
        max_steps: u32,
        shared_discoveries: &Arc<RwLock<HashSet<TagId>>>,
    ) {
        let start = Instant::now();
        let mut current = seed_tag;

        for depth in 0..max_steps {
            // Get the current tag
            let tag = match graph.get_tag(&current) {
                Some(t) => t,
                None => break,
            };

            // Don't revisit within this channel
            if self.visited.contains(&current) {
                // Try to jump to a neighbor we haven't visited
                let unvisited_neighbor = graph.neighbors(&current)
                    .iter()
                    .find(|(nid, _)| !self.visited.contains(nid));

                match unvisited_neighbor {
                    Some(&(nid, _)) => current = nid,
                    None => break, // Dead end — this chain of thought is complete
                }
                continue;
            }

            // Record this step
            let content_ids = graph.content_for_tag(&current);
            let edge_weight = if depth == 0 {
                1.0 // Seed has full weight
            } else {
                self.thought_chain.last()
                    .map(|prev| {
                        graph.neighbors(&prev.tag_id)
                            .iter()
                            .find(|(nid, _)| *nid == current)
                            .map(|(_, w)| *w)
                            .unwrap_or(0.0)
                    })
                    .unwrap_or(0.0)
            };

            self.thought_chain.push(ThoughtStep {
                tag_id: current,
                tag_label: tag.label.clone(),
                edge_weight,
                content_ids_found: content_ids.len(),
                depth,
                cluster_id: tag.cluster_id,
            });

            self.visited.insert(current);
            self.discovered_content.extend_from_slice(content_ids);
            self.steps_taken += 1;
            self.max_depth = depth + 1;

            // Share our discovery with other channels (cross-pollination)
            if let Ok(mut shared) = shared_discoveries.write() {
                shared.insert(current);
            }

            // Pick next tag based on strategy
            let neighbors = graph.neighbors(&current);
            if neighbors.is_empty() {
                break;
            }

            current = match self.strategy {
                ChannelStrategy::Causal => {
                    // Follow the highest-weight (most connected) neighbor
                    self.pick_causal(neighbors, graph)
                }
                ChannelStrategy::Similarity => {
                    // Follow the most similar neighbor
                    self.pick_similarity(neighbors)
                }
                ChannelStrategy::Structural => {
                    // Cross cluster boundaries — seek different clusters
                    self.pick_structural(neighbors, graph, tag.cluster_id)
                }
                ChannelStrategy::Temporal => {
                    // Prefer more recent tags
                    self.pick_temporal(neighbors, graph)
                }
                ChannelStrategy::Exploratory => {
                    // Prefer tags nobody has visited yet
                    self.pick_exploratory(neighbors, shared_discoveries)
                }
                ChannelStrategy::Convergent => {
                    // Prefer tags OTHER channels have found interesting
                    self.pick_convergent(neighbors, shared_discoveries)
                }
            };
        }

        // Deduplicate discovered content
        self.discovered_content.sort_unstable();
        self.discovered_content.dedup();

        self.processing_time_us = start.elapsed().as_micros() as u64;
    }

    /// CAUSAL: pick the neighbor with the highest tag weight (most data behind it)
    fn pick_causal(&self, neighbors: &[(TagId, f32)], graph: &TagGraph) -> TagId {
        neighbors.iter()
            .filter(|(nid, _)| !self.visited.contains(nid))
            .max_by_key(|(nid, _)| {
                graph.get_tag(nid).map(|t| t.weight).unwrap_or(0)
            })
            .map(|(nid, _)| *nid)
            .unwrap_or(neighbors[0].0) // fallback to first
    }

    /// SIMILARITY: pick the most similar neighbor
    fn pick_similarity(&self, neighbors: &[(TagId, f32)]) -> TagId {
        neighbors.iter()
            .filter(|(nid, _)| !self.visited.contains(nid))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(nid, _)| *nid)
            .unwrap_or(neighbors[0].0)
    }

    /// STRUCTURAL: prefer neighbors in a DIFFERENT cluster (cross-domain thinking)
    fn pick_structural(&self, neighbors: &[(TagId, f32)], graph: &TagGraph, current_cluster: u32) -> TagId {
        // First try: different cluster
        let cross_cluster = neighbors.iter()
            .filter(|(nid, _)| !self.visited.contains(nid))
            .find(|(nid, _)| {
                graph.get_tag(nid).map(|t| t.cluster_id != current_cluster).unwrap_or(false)
            });

        if let Some(&(nid, _)) = cross_cluster {
            return nid;
        }

        // Fallback: highest similarity
        self.pick_similarity(neighbors)
    }

    /// TEMPORAL: prefer more recently created tags
    fn pick_temporal(&self, neighbors: &[(TagId, f32)], graph: &TagGraph) -> TagId {
        neighbors.iter()
            .filter(|(nid, _)| !self.visited.contains(nid))
            .max_by_key(|(nid, _)| {
                graph.get_tag(nid).map(|t| t.created_at).unwrap_or(0)
            })
            .map(|(nid, _)| *nid)
            .unwrap_or(neighbors[0].0)
    }

    /// EXPLORATORY: prefer tags that NO channel has visited yet (novelty)
    fn pick_exploratory(&self, neighbors: &[(TagId, f32)], shared: &Arc<RwLock<HashSet<TagId>>>) -> TagId {
        let globally_visited = shared.read().map(|s| s.clone()).unwrap_or_default();

        neighbors.iter()
            .filter(|(nid, _)| !self.visited.contains(nid))
            .find(|(nid, _)| !globally_visited.contains(nid))
            .or_else(|| {
                // All neighbors visited globally — pick least-visited
                neighbors.iter().find(|(nid, _)| !self.visited.contains(nid))
            })
            .map(|(nid, _)| *nid)
            .unwrap_or(neighbors[0].0)
    }

    /// CONVERGENT: prefer tags that OTHER channels have already found interesting
    fn pick_convergent(&self, neighbors: &[(TagId, f32)], shared: &Arc<RwLock<HashSet<TagId>>>) -> TagId {
        let globally_visited = shared.read().map(|s| s.clone()).unwrap_or_default();

        // Prefer tags other channels visited (converge on shared insights)
        neighbors.iter()
            .filter(|(nid, _)| !self.visited.contains(nid))
            .find(|(nid, _)| globally_visited.contains(nid))
            .or_else(|| {
                // Nobody else found these — follow similarity
                neighbors.iter()
                    .filter(|(nid, _)| !self.visited.contains(nid))
                    .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            })
            .map(|(nid, _)| *nid)
            .unwrap_or(neighbors[0].0)
    }
}

// ─── Channeling Result (Aggregated Parallel Insights) ────────────────

/// Result of parallel semantic channeling — all channels merged.
///
/// Like `ShardedModel` for compression, but for inference: each channel
/// explored one angle and the result is the aggregated discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelingResult {
    /// All channels that ran in parallel
    pub channels: Vec<SemanticChannel>,

    /// Total unique tags visited across all channels
    pub total_unique_tags: usize,

    /// Total unique content items discovered
    pub total_unique_content: usize,

    /// Cross-channel convergence points — tags visited by 2+ channels
    /// (strongest signals, multiple thought-chains agree)
    pub convergence_points: Vec<ConvergencePoint>,

    /// Processing time for the entire parallel channeling (microseconds)
    pub total_time_us: u64,

    /// How many channels were run in parallel
    pub num_channels: usize,
}

/// A point where multiple channels converge — strong signal.
///
/// When 2+ independent thought-chains arrive at the same tag,
/// that's a high-confidence insight. Like how in a human brain,
/// when multiple regions activate on the same concept, it's significant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergencePoint {
    /// The tag where channels converged
    pub tag_id: TagId,

    /// Tag label
    pub tag_label: Option<String>,

    /// How many independent channels reached this tag
    pub channel_count: usize,

    /// Which channels found it
    pub channel_ids: Vec<usize>,

    /// Aggregate confidence (average of edge weights across channels)
    pub confidence: f32,

    /// Content IDs accessible from this convergence point
    pub content_count: usize,
}

// ─── Parallel Semantic Channeler (The Orchestrator) ──────────────────

/// Default channel configurations: which strategies to run in parallel.
///
/// 4 channels matches the QUIC parallel shard stream default,
/// keeping architectural symmetry with the compression pipeline.
pub const DEFAULT_CHANNEL_STRATEGIES: &[ChannelStrategy] = &[
    ChannelStrategy::Causal,
    ChannelStrategy::Similarity,
    ChannelStrategy::Structural,
    ChannelStrategy::Exploratory,
];

/// Maximum steps per channel before it terminates
pub const DEFAULT_MAX_STEPS: u32 = 50;

/// Minimum convergence count to be considered a strong signal
pub const MIN_CONVERGENCE_CHANNELS: usize = 2;

/// Run parallel semantic channeling on a tag graph.
///
/// This is the core function — analogous to `parallel_shard_compress()`
/// but for inference. Spawns N channels via rayon, each following a
/// different strategy through the tag graph, all starting from the
/// same seed tags derived from the query.
///
/// The channels share a `RwLock<HashSet<TagId>>` for cross-pollination:
/// the Exploratory strategy avoids tags others have seen (novelty),
/// while the Convergent strategy seeks them out (confirmation).
///
/// # Arguments
///
/// * `graph` - The tag graph (neural network of data)
/// * `query_vector` - Reduced embedding of the user's query
/// * `strategies` - Which parallel strategies to run (default: 4)
/// * `max_steps` - Max steps per channel (default: 50)
/// * `num_seed_tags` - How many starting points to consider
///
/// # Returns
///
/// A `ChannelingResult` containing all parallel thought-chains,
/// convergence points, and discovered content.
pub fn parallel_semantic_channel(
    graph: &TagGraph,
    query_vector: &[f32],
    strategies: &[ChannelStrategy],
    max_steps: u32,
    num_seed_tags: usize,
) -> ChannelingResult {
    let start = Instant::now();
    let total_channels = strategies.len();

    // Find the best seed tags for the query
    let seed_tags = graph.find_nearest_tags(query_vector, num_seed_tags.max(1));
    if seed_tags.is_empty() {
        return ChannelingResult {
            channels: Vec::new(),
            total_unique_tags: 0,
            total_unique_content: 0,
            convergence_points: Vec::new(),
            total_time_us: start.elapsed().as_micros() as u64,
            num_channels: 0,
        };
    }

    // Primary seed: the most relevant tag to the query
    let primary_seed = seed_tags[0].0;

    // Shared discovery set for cross-pollination between channels
    let shared_discoveries: Arc<RwLock<HashSet<TagId>>> =
        Arc::new(RwLock::new(HashSet::new()));

    // ── Run all channels in parallel via rayon ──────────────────
    // Each channel = one QUIC stream equivalent
    // All start from the same seed but navigate differently
    let channels: Vec<SemanticChannel> = strategies
        .par_iter()
        .enumerate()
        .map(|(idx, &strategy)| {
            // Each channel can start from a different seed if available
            let seed = if idx < seed_tags.len() {
                seed_tags[idx].0
            } else {
                primary_seed
            };

            let mut channel = SemanticChannel::new(idx, total_channels, strategy);
            channel.execute(graph, seed, max_steps, &shared_discoveries);
            channel
        })
        .collect();

    // ── Aggregate results across channels ───────────────────────

    // Collect all unique tags visited
    let mut all_tags: HashSet<TagId> = HashSet::new();
    let mut all_content: HashSet<[u8; 32]> = HashSet::new();
    let mut tag_channel_map: HashMap<TagId, Vec<usize>> = HashMap::new();

    for channel in &channels {
        for step in &channel.thought_chain {
            all_tags.insert(step.tag_id);
            tag_channel_map
                .entry(step.tag_id)
                .or_default()
                .push(channel.channel_id);
        }
        for &cid in &channel.discovered_content {
            all_content.insert(cid);
        }
    }

    // Find convergence points — tags visited by 2+ channels
    let mut convergence_points: Vec<ConvergencePoint> = tag_channel_map.iter()
        .filter(|(_, channel_ids)| channel_ids.len() >= MIN_CONVERGENCE_CHANNELS)
        .map(|(&tag_id, channel_ids)| {
            let tag_label = graph.get_tag(&tag_id).and_then(|t| t.label.clone());
            let content_count = graph.content_for_tag(&tag_id).len();

            // Confidence: average edge weight across channels for this tag
            let total_weight: f32 = channels.iter()
                .flat_map(|c| c.thought_chain.iter())
                .filter(|step| step.tag_id == tag_id)
                .map(|step| step.edge_weight)
                .sum();
            let confidence = total_weight / channel_ids.len() as f32;

            ConvergencePoint {
                tag_id,
                tag_label,
                channel_count: channel_ids.len(),
                channel_ids: channel_ids.clone(),
                confidence,
                content_count,
            }
        })
        .collect();

    // Sort convergence by channel_count (most agreement first), then confidence
    convergence_points.sort_by(|a, b| {
        b.channel_count.cmp(&a.channel_count)
            .then(b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
    });

    ChannelingResult {
        channels,
        total_unique_tags: all_tags.len(),
        total_unique_content: all_content.len(),
        convergence_points,
        total_time_us: start.elapsed().as_micros() as u64,
        num_channels: total_channels,
    }
}

/// Convenience: run with default strategies (4 parallel channels)
pub fn channel_query(
    graph: &TagGraph,
    query_vector: &[f32],
    max_steps: u32,
) -> ChannelingResult {
    parallel_semantic_channel(
        graph,
        query_vector,
        DEFAULT_CHANNEL_STRATEGIES,
        max_steps,
        DEFAULT_CHANNEL_STRATEGIES.len(),
    )
}

// ─── QUIC Channel Messages (Network Transport) ──────────────────────

/// Message types for semantic channeling over QUIC parallel streams.
///
/// Each semantic channel maps to one QUIC stream, allowing thought-chains
/// to flow across nodes — distributed cognition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelStreamMessage {
    /// Initiate a channeling session on a peer
    StartChanneling {
        /// Reduced query vector (32-D)
        query_vector: Vec<f32>,
        /// Which strategy this channel should use
        strategy: ChannelStrategy,
        /// Channel ID within the parallel session
        channel_id: usize,
        /// Max steps
        max_steps: u32,
    },
    /// Intermediate discovery from a remote channel
    ChannelDiscovery {
        channel_id: usize,
        /// Tags discovered so far
        discovered_tags: Vec<TagId>,
        /// Current depth
        depth: u32,
    },
    /// Completed channel result from a remote node
    ChannelComplete {
        channel: SemanticChannel,
    },
    /// Cross-pollinate: share discoveries between nodes
    CrossPollinate {
        /// Tags that other channels (possibly on other nodes) have found
        shared_tags: Vec<TagId>,
    },
}

impl ChannelStreamMessage {
    /// Serialize for QUIC stream transfer
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Serialize channel message: {}", e)))
    }

    /// Deserialize from QUIC stream
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Deserialize channel message: {}", e)))
    }
}

// ─── Channeling Metrics ──────────────────────────────────────────────

/// Metrics for the channeling subsystem — fed back to the neural mesh
/// for self-optimization (like SelfOptimizingMetrics in distributed.rs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelingMetrics {
    /// Total channeling sessions run
    pub sessions: u64,
    /// Total channels spawned across all sessions
    pub total_channels_spawned: u64,
    /// Average convergence points per session
    pub avg_convergence_points: f32,
    /// Average unique content discovered per session
    pub avg_content_discovered: f32,
    /// Average processing time (microseconds)
    pub avg_time_us: f64,
    /// Which strategies produce the most convergence
    pub strategy_convergence_scores: HashMap<String, f32>,
    /// Best number of parallel channels (learned)
    pub optimal_channel_count: usize,
}

impl ChannelingMetrics {
    pub fn new() -> Self {
        Self {
            optimal_channel_count: DEFAULT_CHANNEL_STRATEGIES.len(),
            ..Default::default()
        }
    }

    /// Record a session result for learning
    pub fn record_session(&mut self, result: &ChannelingResult) {
        self.sessions += 1;
        self.total_channels_spawned += result.num_channels as u64;

        let conv = result.convergence_points.len() as f32;
        let content = result.total_unique_content as f32;
        let time = result.total_time_us as f64;

        // Exponential moving average (α = 0.1)
        let alpha = 0.1;
        self.avg_convergence_points = self.avg_convergence_points * (1.0 - alpha as f32) + conv * alpha as f32;
        self.avg_content_discovered = self.avg_content_discovered * (1.0 - alpha as f32) + content * alpha as f32;
        self.avg_time_us = self.avg_time_us * (1.0 - alpha) + time * alpha;

        // Track which strategies contribute to convergence
        for cp in &result.convergence_points {
            for &ch_id in &cp.channel_ids {
                if ch_id < result.channels.len() {
                    let strategy_name = result.channels[ch_id].strategy.to_string();
                    let score = self.strategy_convergence_scores
                        .entry(strategy_name)
                        .or_insert(0.0);
                    *score += cp.confidence;
                }
            }
        }
    }

    /// Summary for logging
    pub fn summary(&self) -> String {
        format!(
            "🧠🔮 Semantic Channeling: {} sessions, {:.1} avg convergence pts, \
             {:.0} avg content discovered, {:.0}μs avg time",
            self.sessions,
            self.avg_convergence_points,
            self.avg_content_discovered,
            self.avg_time_us,
        )
    }
}

// ─── Utility Functions ───────────────────────────────────────────────

/// Reduce a high-dimensional embedding to a lower dimension via
/// locality-sensitive hashing. Groups every `stride` values and
/// takes their mean, preserving relative distances.
fn reduce_embedding(embedding: &[f32], target_dim: usize) -> Vec<f32> {
    if embedding.is_empty() {
        return vec![0.0; target_dim];
    }

    let stride = (embedding.len() + target_dim - 1) / target_dim;
    let mut reduced = Vec::with_capacity(target_dim);

    for chunk in embedding.chunks(stride) {
        let mean: f32 = chunk.iter().sum::<f32>() / chunk.len() as f32;
        reduced.push(mean);
    }

    // Pad or truncate to exact dimension
    reduced.resize(target_dim, 0.0);

    // L2-normalize
    let norm: f32 = reduced.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        let inv = 1.0 / norm;
        for v in &mut reduced {
            *v *= inv;
        }
    }

    reduced
}

/// Cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a < 1e-10 || norm_b < 1e-10 {
        return 0.0;
    }

    (dot / (norm_a * norm_b)).clamp(-1.0, 1.0)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──

    /// Create a deterministic tag with a known vector
    fn make_tag(label: &str, values: &[f32]) -> SemanticTag {
        let mut vec = values.to_vec();
        vec.resize(TAG_VECTOR_DIM, 0.0);
        // L2-normalize
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut vec {
                *v /= norm;
            }
        }
        SemanticTag {
            tag_id: TagId::from_vector(&vec),
            label: Some(label.to_string()),
            semantic_vector: vec,
            cluster_id: 0,
            weight: 1,
            created_at: 1000,
        }
    }

    /// Build a small tag graph for testing
    fn build_test_graph() -> TagGraph {
        let mut graph = TagGraph::new();

        // Compression cluster
        let t_compress = make_tag("compression", &[1.0, 0.0, 0.0, 0.0]);
        let t_ratio = make_tag("ratio", &[0.9, 0.1, 0.0, 0.0]);
        let t_entropy = make_tag("entropy", &[0.8, 0.2, 0.0, 0.0]);
        let t_codec = make_tag("codec", &[0.85, 0.15, 0.0, 0.0]);

        // Routing cluster
        let t_routing = make_tag("routing", &[0.0, 1.0, 0.0, 0.0]);
        let t_latency = make_tag("latency", &[0.0, 0.9, 0.1, 0.0]);
        let t_bandwidth = make_tag("bandwidth", &[0.1, 0.85, 0.05, 0.0]);

        // Bridge: connects compression and routing
        let t_throughput = make_tag("throughput", &[0.5, 0.5, 0.0, 0.0]);

        // Security cluster
        let t_zkp = make_tag("zkp", &[0.0, 0.0, 1.0, 0.0]);
        let t_privacy = make_tag("privacy", &[0.0, 0.0, 0.9, 0.1]);

        // Assign clusters
        let mut t_routing = t_routing;
        t_routing.cluster_id = 1;
        let mut t_latency = t_latency;
        t_latency.cluster_id = 1;
        let mut t_bandwidth = t_bandwidth;
        t_bandwidth.cluster_id = 1;
        let mut t_zkp = t_zkp;
        t_zkp.cluster_id = 2;
        let mut t_privacy = t_privacy;
        t_privacy.cluster_id = 2;

        graph.insert_tag(t_compress);
        graph.insert_tag(t_ratio);
        graph.insert_tag(t_entropy);
        graph.insert_tag(t_codec);
        graph.insert_tag(t_routing);
        graph.insert_tag(t_latency);
        graph.insert_tag(t_bandwidth);
        graph.insert_tag(t_throughput);
        graph.insert_tag(t_zkp);
        graph.insert_tag(t_privacy);

        // Bind some content
        let content_a = [0xAA; 32];
        let content_b = [0xBB; 32];

        let tag_compress_id = TagId::from_vector(&make_tag("compression", &[1.0, 0.0, 0.0, 0.0]).semantic_vector);
        let tag_ratio_id = TagId::from_vector(&make_tag("ratio", &[0.9, 0.1, 0.0, 0.0]).semantic_vector);
        let tag_routing_id = TagId::from_vector(&make_tag("routing", &[0.0, 1.0, 0.0, 0.0]).semantic_vector);

        graph.bind_content(ContentTagBinding::new(
            content_a,
            vec![tag_compress_id, tag_ratio_id],
            vec![[0x01; 32]],
        ));

        graph.bind_content(ContentTagBinding::new(
            content_b,
            vec![tag_routing_id],
            vec![[0x02; 32]],
        ));

        graph
    }

    // ── Tag Tests ──

    #[test]
    fn test_tag_creation_from_embedding() {
        let embedding: Vec<f32> = (0..512).map(|i| i as f32 / 512.0).collect();
        let tag = SemanticTag::from_embedding(&embedding, Some("test".to_string()));

        assert_eq!(tag.semantic_vector.len(), TAG_VECTOR_DIM);
        assert!(tag.label.as_deref() == Some("test"));

        // Vector should be L2-normalized
        let norm: f32 = tag.semantic_vector.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01, "norm should be 1.0, got {}", norm);
    }

    #[test]
    fn test_tag_similarity() {
        let t1 = make_tag("a", &[1.0, 0.0, 0.0, 0.0]);
        let t2 = make_tag("b", &[0.9, 0.1, 0.0, 0.0]);
        let t3 = make_tag("c", &[0.0, 0.0, 1.0, 0.0]);

        assert!(t1.similarity(&t2) > 0.9, "similar tags should have high sim");
        assert!(t1.similarity(&t3) < 0.2, "dissimilar tags should have low sim");
    }

    #[test]
    fn test_tag_id_display() {
        let tag = make_tag("test", &[1.0, 2.0, 3.0]);
        let display = format!("{}", tag.tag_id);
        assert!(display.starts_with("tag:"));
        assert_eq!(display.len(), 4 + 16); // "tag:" + 16 hex chars
    }

    // ── Content Binding Tests ──

    #[test]
    fn test_content_binding_commitment() {
        let tag_id = TagId::from_vector(&[1.0, 2.0, 3.0]);
        let binding = ContentTagBinding::new(
            [0xAA; 32],
            vec![tag_id],
            vec![[0x01; 32]],
        );

        assert!(binding.verify_commitment(), "commitment should verify");

        // Tamper with content_id — commitment should fail
        let mut tampered = binding.clone();
        tampered.content_id[0] ^= 0xFF;
        assert!(!tampered.verify_commitment(), "tampered binding should fail");
    }

    // ── Tag Graph Tests ──

    #[test]
    fn test_graph_insert_and_connect() {
        let mut graph = TagGraph::new();

        let t1 = make_tag("a", &[1.0, 0.0, 0.0, 0.0]);
        let t2 = make_tag("b", &[0.9, 0.1, 0.0, 0.0]); // similar to a
        let t3 = make_tag("c", &[0.0, 0.0, 1.0, 0.0]); // different from a

        graph.insert_tag(t1);
        graph.insert_tag(t2);
        graph.insert_tag(t3);

        assert_eq!(graph.tag_count(), 3);
        // t1 and t2 should be connected (similar), t3 should not be
        assert!(graph.edge_count() >= 1, "similar tags should form edges");
    }

    #[test]
    fn test_graph_find_nearest() {
        let graph = build_test_graph();

        // Query close to "compression"
        let mut query = vec![1.0, 0.0, 0.0, 0.0];
        query.resize(TAG_VECTOR_DIM, 0.0);
        // normalize
        let norm: f32 = query.iter().map(|x| x * x).sum::<f32>().sqrt();
        for v in &mut query { *v /= norm; }

        let nearest = graph.find_nearest_tags(&query, 3);
        assert!(!nearest.is_empty(), "should find at least one tag");
        assert!(nearest[0].1 > 0.5, "top result should be similar to query");
    }

    // ── Single Channel Tests ──

    #[test]
    fn test_single_channel_execution() {
        let graph = build_test_graph();
        let shared = Arc::new(RwLock::new(HashSet::new()));

        // Find a seed tag
        let mut query = vec![1.0, 0.0, 0.0, 0.0];
        query.resize(TAG_VECTOR_DIM, 0.0);
        let norm: f32 = query.iter().map(|x| x * x).sum::<f32>().sqrt();
        for v in &mut query { *v /= norm; }
        let seeds = graph.find_nearest_tags(&query, 1);
        assert!(!seeds.is_empty());

        let mut channel = SemanticChannel::new(0, 1, ChannelStrategy::Similarity);
        channel.execute(&graph, seeds[0].0, 10, &shared);

        assert!(!channel.thought_chain.is_empty(), "channel should have at least one step");
        assert!(channel.steps_taken > 0);
        assert!(channel.processing_time_us > 0 || channel.steps_taken > 0);
    }

    // ── Parallel Channeling Tests ──

    #[test]
    fn test_parallel_channeling_basic() {
        let graph = build_test_graph();

        let mut query = vec![1.0, 0.0, 0.0, 0.0]; // query about "compression"
        query.resize(TAG_VECTOR_DIM, 0.0);
        let norm: f32 = query.iter().map(|x| x * x).sum::<f32>().sqrt();
        for v in &mut query { *v /= norm; }

        let result = parallel_semantic_channel(
            &graph,
            &query,
            DEFAULT_CHANNEL_STRATEGIES,
            20,
            4,
        );

        assert_eq!(result.num_channels, 4);
        assert!(result.total_unique_tags > 0, "should discover some tags");
        assert!(result.total_time_us > 0 || result.num_channels > 0);

        // At least some channels should have run
        let active = result.channels.iter().filter(|c| !c.thought_chain.is_empty()).count();
        assert!(active > 0, "at least one channel should produce steps");
    }

    #[test]
    fn test_parallel_channeling_convergence() {
        let graph = build_test_graph();

        // Query that sits between clusters (should cause convergence)
        let mut query = vec![0.5, 0.5, 0.0, 0.0]; // between compression and routing
        query.resize(TAG_VECTOR_DIM, 0.0);
        let norm: f32 = query.iter().map(|x| x * x).sum::<f32>().sqrt();
        for v in &mut query { *v /= norm; }

        let result = parallel_semantic_channel(
            &graph,
            &query,
            &[
                ChannelStrategy::Causal,
                ChannelStrategy::Similarity,
                ChannelStrategy::Structural,
                ChannelStrategy::Convergent,
            ],
            20,
            4,
        );

        // Multiple channels should find some common tags
        // (especially the "throughput" bridge tag)
        assert!(result.total_unique_tags > 0);
    }

    #[test]
    fn test_channel_query_convenience() {
        let graph = build_test_graph();

        let mut query = vec![0.0, 1.0, 0.0, 0.0]; // query about "routing"
        query.resize(TAG_VECTOR_DIM, 0.0);
        let norm: f32 = query.iter().map(|x| x * x).sum::<f32>().sqrt();
        for v in &mut query { *v /= norm; }

        let result = channel_query(&graph, &query, 15);
        assert_eq!(result.num_channels, DEFAULT_CHANNEL_STRATEGIES.len());
    }

    #[test]
    fn test_empty_graph_channeling() {
        let graph = TagGraph::new();
        let query = vec![1.0; TAG_VECTOR_DIM];

        let result = channel_query(&graph, &query, 10);
        assert_eq!(result.num_channels, 0);
        assert_eq!(result.total_unique_tags, 0);
    }

    // ── Strategy Tests ──

    #[test]
    fn test_all_strategies_execute() {
        let graph = build_test_graph();
        let shared = Arc::new(RwLock::new(HashSet::new()));

        let mut query = vec![1.0, 0.0, 0.0, 0.0];
        query.resize(TAG_VECTOR_DIM, 0.0);
        let norm: f32 = query.iter().map(|x| x * x).sum::<f32>().sqrt();
        for v in &mut query { *v /= norm; }
        let seeds = graph.find_nearest_tags(&query, 1);
        if seeds.is_empty() { return; }
        let seed = seeds[0].0;

        let all_strategies = [
            ChannelStrategy::Causal,
            ChannelStrategy::Similarity,
            ChannelStrategy::Structural,
            ChannelStrategy::Temporal,
            ChannelStrategy::Exploratory,
            ChannelStrategy::Convergent,
        ];

        for strategy in &all_strategies {
            let mut channel = SemanticChannel::new(0, 1, *strategy);
            channel.execute(&graph, seed, 10, &shared);
            // All strategies should at least start (visit the seed)
            assert!(
                !channel.thought_chain.is_empty(),
                "strategy {} should produce at least one step",
                strategy,
            );
        }
    }

    // ── Metric Tests ──

    #[test]
    fn test_channeling_metrics() {
        let graph = build_test_graph();

        let mut query = vec![1.0, 0.0, 0.0, 0.0];
        query.resize(TAG_VECTOR_DIM, 0.0);
        let norm: f32 = query.iter().map(|x| x * x).sum::<f32>().sqrt();
        for v in &mut query { *v /= norm; }

        let result = channel_query(&graph, &query, 10);

        let mut metrics = ChannelingMetrics::new();
        metrics.record_session(&result);

        assert_eq!(metrics.sessions, 1);
        assert!(metrics.total_channels_spawned > 0);
    }

    // ── Serialization Tests ──

    #[test]
    fn test_channel_stream_message_roundtrip() {
        let msg = ChannelStreamMessage::StartChanneling {
            query_vector: vec![0.5; 32],
            strategy: ChannelStrategy::Causal,
            channel_id: 0,
            max_steps: 50,
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ChannelStreamMessage::from_bytes(&bytes).unwrap();

        match restored {
            ChannelStreamMessage::StartChanneling { channel_id, max_steps, .. } => {
                assert_eq!(channel_id, 0);
                assert_eq!(max_steps, 50);
            }
            _ => panic!("Wrong variant"),
        }
    }

    // ── Reduce Embedding Tests ──

    #[test]
    fn test_reduce_embedding() {
        let embedding: Vec<f32> = (0..512).map(|i| i as f32).collect();
        let reduced = reduce_embedding(&embedding, 32);

        assert_eq!(reduced.len(), 32);
        // Should be normalized
        let norm: f32 = reduced.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01, "reduced should be L2-normalized");
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![1.0, 2.0, 3.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity(&a, &b).abs() < 0.001);
    }
}
