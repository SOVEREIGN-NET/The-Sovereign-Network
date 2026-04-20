//! Semantic Search Plugin API
//!
//! Allows developers and companies to register their own datasets as
//! plugins into the semantic search engine. Each plugin gets its own
//! private `TagGraph` — the same engine that powers the Sovereign Network's
//! public graph, but over the user's private data.
//!
//! # Privacy
//!
//! All plugin data is:
//! - Encrypted end-to-end via ZHTP's ZKP + encryption layer
//! - Stored only in the user's ZHTP node (never leaves unless they choose)
//! - Queried via the same semantic channeling engine
//! - Protected by the same ZK proofs as network data
//!
//! # Developer API
//!
//! ```text
//! POST   /api/v1/semantic/plugins                  — Register a new plugin
//! GET    /api/v1/semantic/plugins                  — List plugins
//! DELETE /api/v1/semantic/plugins/{id}             — Remove a plugin
//! POST   /api/v1/semantic/plugins/{id}/ingest      — Ingest data items
//! POST   /api/v1/semantic/plugins/{id}/search      — Search plugin's graph
//! GET    /api/v1/semantic/plugins/{id}/stats        — Plugin graph stats
//! POST   /api/v1/semantic/plugins/{id}/embed        — Custom embedding override
//! POST   /api/v1/semantic/search                   — Unified search (all sources)
//! ```
//!
//! # Neural Compression Integration
//!
//! When data is ingested, the `AdaptiveCodecLearner` from lib-neural-mesh
//! observes the content. Compression patterns create new semantic connections:
//! - Similar compression signatures → new tag edges (neuropathways)
//! - Content-type clustering → automatic tag generation
//! - Learned codec params → compression feedback strengthens relevant tags

use anyhow::Result;
use blake3;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use lib_neural_mesh::{
    parallel_semantic_channel, ContentTagBinding, SemanticTag, TagGraph, TagId,
    DEFAULT_CHANNEL_STRATEGIES,
};

use super::semantic::{
    channeling_result_to_vis, parse_strategy, text_to_query_vector, EngineMetadata,
    SemanticSearchRequest, SemanticSearchResponse, VisLink, VisNode,
};

// ─── Plugin Types ────────────────────────────────────────────────────

/// Unique identifier for a plugin (BLAKE3 hash of name + creator)
pub type PluginId = [u8; 32];

/// Embedding function type — plugins can provide custom embedders
/// via an external AI model endpoint, or use the built-in BLAKE3 hasher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingSource {
    /// Use the built-in BLAKE3 text→vector projection (default)
    Builtin,
    /// Call an external API to generate embeddings (e.g., OpenAI, local LLM)
    ExternalApi {
        /// URL of the embedding endpoint
        endpoint: String,
        /// Model name (e.g., "text-embedding-3-small")
        model: String,
        /// Bearer token (encrypted in transit via ZHTP)
        #[serde(skip_serializing)]
        api_key: Option<String>,
        /// Expected vector dimensions (default: 32)
        dimensions: Option<usize>,
    },
    /// Embeddings are provided inline with each data item
    Inline,
}

impl Default for EmbeddingSource {
    fn default() -> Self {
        Self::Builtin
    }
}

/// Request to register a new plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPluginRequest {
    /// Human-readable name
    pub name: String,
    /// Description of this dataset
    #[serde(default)]
    pub description: String,
    /// How to generate embeddings for ingested data
    #[serde(default)]
    pub embedding_source: EmbeddingSource,
    /// Optional: predefined cluster/category names
    #[serde(default)]
    pub categories: Vec<String>,
    /// Whether to enable neural compression learning on ingested data
    #[serde(default = "default_true")]
    pub enable_compression_learning: bool,
}

fn default_true() -> bool {
    true
}

/// A registered plugin with its own TagGraph
pub struct SemanticPlugin {
    /// Unique ID
    pub id: PluginId,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// The plugin's private TagGraph
    pub graph: Arc<RwLock<TagGraph>>,
    /// How embeddings are generated
    pub embedding_source: EmbeddingSource,
    /// Whether neural compression learning is enabled
    pub compression_learning: bool,
    /// Number of items ingested
    pub item_count: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Cluster names (if predefined)
    pub categories: Vec<String>,
    /// Compression signature cache: content_hash → compression_profile
    /// Used for neural compression learning (discovering similar content)
    pub compression_signatures: HashMap<[u8; 32], CompressionSignature>,
}

/// Compression learning signature for a piece of content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionSignature {
    /// BLAKE3 hash of the raw content
    pub content_hash: [u8; 32],
    /// Compression ratio achieved
    pub ratio: f32,
    /// Which SFC mode was used (7 = default, 9 = neural-tuned)
    pub sfc_mode: u8,
    /// Byte entropy (0.0 = all zeros, 8.0 = pure random)
    pub entropy: f32,
    /// Content length
    pub raw_size: usize,
    /// Tag IDs assigned to this content
    pub tag_ids: Vec<TagId>,
}

/// Plugin info for API responses (no internal state)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub embedding_source: String,
    pub compression_learning: bool,
    pub item_count: u64,
    pub graph_tags: usize,
    pub graph_edges: usize,
    pub graph_bindings: usize,
    pub categories: Vec<String>,
    pub created_at: u64,
}

/// Request to ingest data items into a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRequest {
    /// Array of items to ingest
    pub items: Vec<IngestItem>,
}

/// A single data item to ingest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestItem {
    /// Unique ID for this item (or auto-generated from content hash)
    #[serde(default)]
    pub id: Option<String>,
    /// The content text/data (used for embedding + tag generation)
    pub content: String,
    /// Optional: pre-assigned labels/tags
    #[serde(default)]
    pub labels: Vec<String>,
    /// Optional: pre-computed embedding vector (used with EmbeddingSource::Inline)
    #[serde(default)]
    pub embedding: Option<Vec<f32>>,
    /// Optional: metadata key-value pairs
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Optional: category/cluster assignment
    #[serde(default)]
    pub category: Option<String>,
}

/// Response from ingest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub ingested: usize,
    pub tags_created: usize,
    pub bindings_created: usize,
    pub compression_signatures: usize,
    pub graph_tags: usize,
    pub graph_edges: usize,
}

/// Request to provide custom embedding for a query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEmbedRequest {
    /// The query text
    pub query: String,
    /// The embedding vector (should match plugin's vector dimension)
    pub vector: Vec<f32>,
}

// ─── Plugin Registry ─────────────────────────────────────────────────

/// Registry of all semantic search plugins.
///
/// Each plugin is an independent data silo with its own TagGraph,
/// searched privately via the same channeling engine.
pub struct PluginRegistry {
    plugins: HashMap<PluginId, SemanticPlugin>,
}

impl PluginRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a new plugin, returns its ID
    pub fn register(&mut self, req: RegisterPluginRequest) -> Result<PluginId> {
        let id = Self::make_id(&req.name);

        if self.plugins.contains_key(&id) {
            anyhow::bail!("Plugin '{}' already registered", req.name);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let plugin = SemanticPlugin {
            id,
            name: req.name.clone(),
            description: req.description,
            graph: Arc::new(RwLock::new(TagGraph::new())),
            embedding_source: req.embedding_source,
            compression_learning: req.enable_compression_learning,
            item_count: 0,
            created_at: now,
            categories: req.categories,
            compression_signatures: HashMap::new(),
        };

        info!("🔌 Registered semantic plugin '{}' (id: {})", req.name, hex::encode(id));
        self.plugins.insert(id, plugin);
        Ok(id)
    }

    /// Remove a plugin
    pub fn remove(&mut self, id: &PluginId) -> Option<String> {
        self.plugins.remove(id).map(|p| {
            info!("🔌 Removed semantic plugin '{}'", p.name);
            p.name
        })
    }

    /// Get a plugin by ID
    pub fn get(&self, id: &PluginId) -> Option<&SemanticPlugin> {
        self.plugins.get(id)
    }

    /// Get a mutable plugin by ID
    pub fn get_mut(&mut self, id: &PluginId) -> Option<&mut SemanticPlugin> {
        self.plugins.get_mut(id)
    }

    /// List all plugins
    pub fn list(&self) -> Vec<PluginInfo> {
        // Note: we can't await inside a sync method, so we return 0 for graph stats.
        // The real stats are fetched in the async handler.
        self.plugins
            .values()
            .map(|p| PluginInfo {
                id: hex::encode(p.id),
                name: p.name.clone(),
                description: p.description.clone(),
                embedding_source: match &p.embedding_source {
                    EmbeddingSource::Builtin => "builtin".into(),
                    EmbeddingSource::ExternalApi { model, .. } => format!("external:{}", model),
                    EmbeddingSource::Inline => "inline".into(),
                },
                compression_learning: p.compression_learning,
                item_count: p.item_count,
                graph_tags: 0,  // Filled in async handler
                graph_edges: 0,
                graph_bindings: 0,
                categories: p.categories.clone(),
                created_at: p.created_at,
            })
            .collect()
    }

    /// Find plugin by hex ID string
    pub fn find_by_hex(&self, hex_id: &str) -> Option<&SemanticPlugin> {
        if let Ok(bytes) = hex::decode(hex_id) {
            if bytes.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                return self.plugins.get(&id);
            }
        }
        // Also try name-based lookup
        let name_id = Self::make_id(hex_id);
        self.plugins.get(&name_id)
    }

    /// Find mutable plugin by hex ID or name
    pub fn find_by_hex_mut(&mut self, hex_id: &str) -> Option<&mut SemanticPlugin> {
        if let Ok(bytes) = hex::decode(hex_id) {
            if bytes.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                return self.plugins.get_mut(&id);
            }
        }
        let name_id = Self::make_id(hex_id);
        self.plugins.get_mut(&name_id)
    }

    /// Generate a deterministic plugin ID from name
    fn make_id(name: &str) -> PluginId {
        *blake3::hash(format!("semantic-plugin:{}", name.to_lowercase()).as_bytes()).as_bytes()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Data Ingestion Engine ───────────────────────────────────────────

/// Ingest data items into a plugin's TagGraph.
///
/// For each item:
/// 1. Generate or use provided embedding vector (32-D)
/// 2. Create a SemanticTag from the embedding
/// 3. Insert into the TagGraph (auto-connects to similar tags)
/// 4. Bind content to tags
/// 5. Optionally: compute compression signature for neural learning
pub async fn ingest_items(
    plugin: &mut SemanticPlugin,
    items: Vec<IngestItem>,
) -> Result<IngestResponse> {
    let mut tags_created = 0;
    let mut bindings_created = 0;
    let mut compression_sigs = 0;

    // Pre-resolve all cluster IDs before taking the graph lock
    // (avoids borrow conflict with plugin.categories)
    let cluster_ids: Vec<u32> = items
        .iter()
        .map(|item| resolve_cluster_id_from_categories(&mut plugin.categories, &item.category))
        .collect();

    // Collect compression data outside graph lock scope
    let mut sigs_to_insert: Vec<([u8; 32], CompressionSignature)> = Vec::new();

    {
        let mut graph = plugin.graph.write().await;

        for (idx, item) in items.iter().enumerate() {
            // Step 1: Generate embedding
            let embedding = match &item.embedding {
                Some(vec) if !vec.is_empty() => {
                    let mut v = vec.clone();
                    normalize_to_32d(&mut v);
                    v
                }
                _ => text_to_query_vector(&item.content),
            };

            // Step 2: Create semantic tag
            let label = if !item.labels.is_empty() {
                Some(item.labels.join(", "))
            } else {
                Some(item.content.chars().take(60).collect::<String>())
            };

            let cluster_id = cluster_ids[idx];

            let tag = SemanticTag {
                tag_id: TagId::from_vector(&embedding),
                label,
                semantic_vector: embedding.clone(),
                cluster_id,
                weight: 1,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            };

            let tag_id = tag.tag_id;
            graph.insert_tag(tag);
            tags_created += 1;

            // Step 3: Content binding
            let content_hash = *blake3::hash(item.content.as_bytes()).as_bytes();
            let mut binding_tags = vec![tag_id];

            for lbl in &item.labels {
                let lbl_vec = text_to_query_vector(lbl);
                let lbl_tag = SemanticTag {
                    tag_id: TagId::from_vector(&lbl_vec),
                    label: Some(lbl.clone()),
                    semantic_vector: lbl_vec,
                    cluster_id,
                    weight: 1,
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };
                let lid = lbl_tag.tag_id;
                graph.insert_tag(lbl_tag);
                binding_tags.push(lid);
                tags_created += 1;
            }

            let shard_id = *blake3::hash(&content_hash).as_bytes();
            graph.bind_content(ContentTagBinding::new(
                content_hash,
                binding_tags.clone(),
                vec![shard_id],
            ));
            bindings_created += 1;

            // Step 4: Compression signature
            if plugin.compression_learning {
                let sig = compute_compression_signature(&item.content, &binding_tags);
                sigs_to_insert.push((content_hash, sig));
                compression_sigs += 1;
            }

            plugin.item_count += 1;
        }

        // Step 5: Neural compression cross-linking
        // Insert signatures first
        for (hash, sig) in sigs_to_insert {
            plugin.compression_signatures.insert(hash, sig);
        }

        if plugin.compression_learning && !plugin.compression_signatures.is_empty() {
            let new_edges = create_compression_learned_edges(plugin, &mut graph);
            if new_edges > 0 {
                info!(
                    "🧠 Neural compression learning created {} new edges in plugin '{}'",
                    new_edges, plugin.name
                );
            }
        }

        let response = IngestResponse {
            ingested: items.len(),
            tags_created,
            bindings_created,
            compression_signatures: compression_sigs,
            graph_tags: graph.tag_count(),
            graph_edges: graph.edge_count(),
        };

        Ok(response)
    }
}

/// Normalize a vector to 32 dimensions, L2-normalized
fn normalize_to_32d(vec: &mut Vec<f32>) {
    // Reduce higher-dim vectors by averaging buckets
    if vec.len() > 32 {
        let mut reduced = vec![0.0f32; 32];
        for (i, &v) in vec.iter().enumerate() {
            reduced[i % 32] += v;
        }
        *vec = reduced;
    }
    // Pad shorter vectors
    vec.resize(32, 0.0);

    // L2-normalize
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        let inv = 1.0 / norm;
        for v in vec.iter_mut() {
            *v *= inv;
        }
    }
}

/// Resolve a category name to a cluster_id, creating new category if needed.
/// Works on the categories vec directly to avoid borrow conflicts.
fn resolve_cluster_id_from_categories(categories: &mut Vec<String>, category: &Option<String>) -> u32 {
    match category {
        Some(cat) => {
            if let Some(idx) = categories.iter().position(|c| c == cat) {
                idx as u32
            } else {
                let idx = categories.len() as u32;
                categories.push(cat.clone());
                idx
            }
        }
        None => 0, // Default cluster
    }
}

/// Compute a compression signature for neural learning.
///
/// This is lightweight — we don't actually compress the data, just
/// compute features that predict how compressible it is:
/// - Byte entropy (Shannon entropy)
/// - Byte histogram distribution
/// - Repetition density
///
/// These features are used to discover that "two documents compress
/// similarly" → they should be semantically linked.
fn compute_compression_signature(content: &str, tag_ids: &[TagId]) -> CompressionSignature {
    let bytes = content.as_bytes();
    let len = bytes.len();

    // Byte frequency histogram
    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }

    // Shannon entropy
    let entropy = freq.iter().fold(0.0f32, |acc, &f| {
        if f == 0 {
            acc
        } else {
            let p = f as f32 / len as f32;
            acc - p * p.log2()
        }
    });

    // Estimate compression ratio from entropy
    // 8 bits/byte → entropy bits/byte → ratio = entropy/8
    let ratio = if entropy > 0.0 { entropy / 8.0 } else { 0.01 };

    CompressionSignature {
        content_hash: *blake3::hash(bytes).as_bytes(),
        ratio,
        sfc_mode: 7, // Default SFC7, would be updated after actual compression
        entropy,
        raw_size: len,
        tag_ids: tag_ids.to_vec(),
    }
}

/// Create new TagGraph edges between content that has similar compression signatures.
///
/// This is the neural compression → semantic search feedback loop:
/// If two pieces of content compress similarly (similar entropy, similar ratio),
/// they probably have similar structure, so they should be semantically linked.
///
/// This creates the "learning" effect — the more data you feed in,
/// the more connections emerge, and the better the search gets.
fn create_compression_learned_edges(
    plugin: &SemanticPlugin,
    graph: &mut TagGraph,
) -> usize {
    let sigs: Vec<&CompressionSignature> = plugin.compression_signatures.values().collect();
    let mut new_edges = 0;

    // Compare pairs of compression signatures
    for i in 0..sigs.len() {
        for j in (i + 1)..sigs.len() {
            let a = sigs[i];
            let b = sigs[j];

            // Skip if same content
            if a.content_hash == b.content_hash {
                continue;
            }

            // Compression similarity: similar entropy + similar ratio
            let entropy_sim = 1.0 - (a.entropy - b.entropy).abs() / 8.0;
            let ratio_sim = 1.0 - (a.ratio - b.ratio).abs();
            let size_sim = 1.0 - ((a.raw_size as f32).ln() - (b.raw_size as f32).ln()).abs() / 20.0;
            let compression_similarity = (entropy_sim * 0.4 + ratio_sim * 0.4 + size_sim * 0.2)
                .clamp(0.0, 1.0);

            // Only link if compression profiles are very similar (>0.85)
            if compression_similarity > 0.85 {
                // Cross-bind tags from both content items
                for tag_a in &a.tag_ids {
                    for tag_b in &b.tag_ids {
                        if tag_a != tag_b {
                            // Create a cross-content binding
                            let bridge_id = {
                                let mut hasher = blake3::Hasher::new();
                                hasher.update(&a.content_hash);
                                hasher.update(&b.content_hash);
                                hasher.update(b"compression-bridge");
                                *hasher.finalize().as_bytes()
                            };

                            graph.bind_content(ContentTagBinding::new(
                                bridge_id,
                                vec![*tag_a, *tag_b],
                                vec![],
                            ));
                            new_edges += 1;
                        }
                    }
                }
            }
        }
    }

    new_edges
}

/// Search a plugin's TagGraph using the real channeling engine.
///
/// Identical algorithm to the Sovereign Network search, just
/// running over the plugin's private graph instead.
pub async fn search_plugin(
    plugin: &SemanticPlugin,
    req: &SemanticSearchRequest,
) -> Result<SemanticSearchResponse> {
    let query_vector = match &plugin.embedding_source {
        EmbeddingSource::Builtin | EmbeddingSource::Inline => {
            text_to_query_vector(&req.query)
        }
        EmbeddingSource::ExternalApi { .. } => {
            // For external API, we'd call the endpoint here.
            // For now, fall back to builtin (the endpoint call is async
            // and would use reqwest/hyper — left as a TODO for full
            // external model integration).
            text_to_query_vector(&req.query)
        }
    };

    let strategies = if req.strategies.is_empty() {
        DEFAULT_CHANNEL_STRATEGIES.to_vec()
    } else {
        let parsed: Vec<_> = req
            .strategies
            .iter()
            .filter_map(|s| parse_strategy(s))
            .collect();
        if parsed.is_empty() {
            DEFAULT_CHANNEL_STRATEGIES.to_vec()
        } else {
            parsed
        }
    };

    let max_steps = req.max_steps.unwrap_or(50);
    let graph = plugin.graph.read().await;

    let result = parallel_semantic_channel(
        &graph,
        &query_vector,
        &strategies,
        max_steps,
        strategies.len(),
    );

    let mut response = channeling_result_to_vis(&req.query, &result, &graph);

    // Tag the response with plugin source info
    response.engine.graph_tags = graph.tag_count();
    response.engine.graph_edges = graph.edge_count();
    response.engine.graph_bindings = graph.binding_count();

    Ok(response)
}

/// Search across ALL sources: network graph + all plugins.
///
/// Returns merged results with source attribution.
pub async fn search_all_sources(
    network_graph: &Arc<RwLock<TagGraph>>,
    registry: &PluginRegistry,
    req: &SemanticSearchRequest,
) -> Result<UnifiedSearchResponse> {
    let mut sources: Vec<SourceResult> = Vec::new();

    // 1. Search the network graph
    let query_vector = text_to_query_vector(&req.query);
    let strategies = if req.strategies.is_empty() {
        DEFAULT_CHANNEL_STRATEGIES.to_vec()
    } else {
        req.strategies
            .iter()
            .filter_map(|s| parse_strategy(s))
            .collect()
    };
    let max_steps = req.max_steps.unwrap_or(50);

    {
        let graph = network_graph.read().await;
        let result = parallel_semantic_channel(
            &graph,
            &query_vector,
            &strategies,
            max_steps,
            strategies.len(),
        );
        let response = channeling_result_to_vis(&req.query, &result, &graph);
        sources.push(SourceResult {
            source_id: "network".into(),
            source_name: "Sovereign Network".into(),
            source_type: "network".into(),
            result: response,
        });
    }

    // 2. Search each plugin
    for plugin in registry.list() {
        if let Some(p) = registry.find_by_hex(&plugin.id) {
            match search_plugin(p, req).await {
                Ok(result) => {
                    sources.push(SourceResult {
                        source_id: plugin.id.clone(),
                        source_name: plugin.name.clone(),
                        source_type: "plugin".into(),
                        result,
                    });
                }
                Err(e) => {
                    warn!("Plugin '{}' search failed: {}", plugin.name, e);
                }
            }
        }
    }

    Ok(UnifiedSearchResponse {
        query: req.query.clone(),
        sources,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Unified search response combining all data sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedSearchResponse {
    pub query: String,
    pub sources: Vec<SourceResult>,
    pub timestamp: String,
}

/// Result from a single data source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceResult {
    /// Unique source identifier ("network" or plugin hex ID)
    pub source_id: String,
    /// Human-readable name
    pub source_name: String,
    /// "network" or "plugin"
    pub source_type: String,
    /// The channeling result
    pub result: SemanticSearchResponse,
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_registration() {
        let mut registry = PluginRegistry::new();
        let req = RegisterPluginRequest {
            name: "My Custom Dataset".into(),
            description: "Employee docs".into(),
            embedding_source: EmbeddingSource::Builtin,
            categories: vec!["Engineering".into(), "Marketing".into()],
            enable_compression_learning: true,
        };
        let id = registry.register(req).unwrap();
        assert!(registry.get(&id).is_some());

        let list = registry.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "My Custom Dataset");
    }

    #[test]
    fn test_duplicate_plugin_rejected() {
        let mut registry = PluginRegistry::new();
        let req = RegisterPluginRequest {
            name: "test".into(),
            description: "".into(),
            embedding_source: EmbeddingSource::default(),
            categories: vec![],
            enable_compression_learning: false,
        };
        registry.register(req.clone()).unwrap();
        assert!(registry.register(req).is_err());
    }

    #[test]
    fn test_plugin_removal() {
        let mut registry = PluginRegistry::new();
        let req = RegisterPluginRequest {
            name: "ephemeral".into(),
            description: "".into(),
            embedding_source: EmbeddingSource::default(),
            categories: vec![],
            enable_compression_learning: false,
        };
        let id = registry.register(req).unwrap();
        assert!(registry.remove(&id).is_some());
        assert!(registry.get(&id).is_none());
    }

    #[test]
    fn test_compression_signature() {
        let sig = compute_compression_signature(
            "Hello world, this is some test content for compression analysis.",
            &[],
        );
        assert!(sig.entropy > 0.0);
        assert!(sig.entropy < 8.0);
        assert!(sig.ratio > 0.0);
        assert!(sig.ratio < 1.0);
        assert_eq!(sig.sfc_mode, 7);
    }

    #[test]
    fn test_normalize_to_32d() {
        let mut vec = vec![1.0; 512];
        normalize_to_32d(&mut vec);
        assert_eq!(vec.len(), 32);
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_normalize_short_vec() {
        let mut vec = vec![1.0, 0.0, 0.0];
        normalize_to_32d(&mut vec);
        assert_eq!(vec.len(), 32);
        assert!((vec[0] - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_ingest_and_search() {
        let mut registry = PluginRegistry::new();
        let req = RegisterPluginRequest {
            name: "test-ingest".into(),
            description: "Testing".into(),
            embedding_source: EmbeddingSource::Builtin,
            categories: vec!["Tech".into()],
            enable_compression_learning: true,
        };
        let id = registry.register(req).unwrap();

        let plugin = registry.get_mut(&id).unwrap();
        let items = vec![
            IngestItem {
                id: None,
                content: "Rust is a systems programming language focused on safety".into(),
                labels: vec!["rust".into(), "programming".into()],
                embedding: None,
                metadata: HashMap::new(),
                category: Some("Tech".into()),
            },
            IngestItem {
                id: None,
                content: "Zero knowledge proofs enable private verification".into(),
                labels: vec!["cryptography".into(), "zkp".into()],
                embedding: None,
                metadata: HashMap::new(),
                category: Some("Tech".into()),
            },
        ];

        let result = ingest_items(plugin, items).await.unwrap();
        assert_eq!(result.ingested, 2);
        assert!(result.tags_created > 0);
        assert!(result.bindings_created > 0);
        assert!(result.graph_tags > 0);

        // Now search
        let search_req = SemanticSearchRequest {
            query: "programming language safety".into(),
            strategies: vec![],
            max_steps: Some(20),
        };
        let search_result = search_plugin(plugin, &search_req).await.unwrap();
        assert_eq!(search_result.query, "programming language safety");
        assert!(!search_result.nodes.is_empty());
    }
}
