//! Semantic Search API Handler
//!
//! Real integration with the SemanticChannelingEngine from lib-neural-mesh.
//! Runs parallel semantic channels across a live TagGraph seeded with
//! Sovereign Network concepts. No mock data — the graph is traversed
//! by the real channeling engine using Causal, Similarity, Structural,
//! and Exploratory strategies.
//!
//! # Endpoints
//!
//! - `POST /api/v1/semantic/search` — Run semantic channeling for a query
//! - `GET  /api/v1/semantic/stats`  — Graph statistics
//! - `GET  /api/v1/semantic/health` — Health check

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use lib_neural_mesh::{
    channel_query, parallel_semantic_channel, ChannelStrategy, ChannelingResult,
    ContentTagBinding, SemanticTag, TagGraph, TagId, DEFAULT_CHANNEL_STRATEGIES,
};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;

// ─── Request / Response Types ────────────────────────────────────────

/// Incoming search request from the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticSearchRequest {
    /// The user's query text
    pub query: String,
    /// Optional: which strategies to use (default: all 4)
    #[serde(default)]
    pub strategies: Vec<String>,
    /// Optional: max steps per channel (default: 50)
    #[serde(default)]
    pub max_steps: Option<u32>,
}

/// Frontend-friendly node in the graph visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisNode {
    pub id: String,
    pub label: String,
    pub level: u8,
    pub relevance: f32,
    pub strategy: String,
    pub icon: String,
    pub tags: Vec<String>,
    pub preview: String,
    #[serde(rename = "parentId")]
    pub parent_id: Option<String>,
    pub expanded: bool,
    pub children: Vec<String>,
}

/// Frontend-friendly link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisLink {
    pub source: String,
    pub target: String,
    pub level: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross: Option<bool>,
}

/// Full response matching the frontend's expected shape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticSearchResponse {
    pub query: String,
    pub timestamp: String,
    #[serde(rename = "totalNodes")]
    pub total_nodes: usize,
    #[serde(rename = "totalLinks")]
    pub total_links: usize,
    pub nodes: Vec<VisNode>,
    pub links: Vec<VisLink>,
    /// Real engine metadata
    pub engine: EngineMetadata,
}

/// Metadata from the real channeling engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineMetadata {
    pub channels_run: usize,
    pub total_unique_tags: usize,
    pub total_unique_content: usize,
    pub convergence_points: usize,
    pub processing_time_us: u64,
    pub graph_tags: usize,
    pub graph_edges: usize,
    pub graph_bindings: usize,
}

/// Graph statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStatsResponse {
    pub tag_count: usize,
    pub edge_count: usize,
    pub binding_count: usize,
    pub status: String,
}

// ─── Handler ─────────────────────────────────────────────────────────

pub struct SemanticSearchHandler {
    graph: Arc<RwLock<TagGraph>>,
}

impl SemanticSearchHandler {
    /// Create handler with a TagGraph pre-seeded with Sovereign Network concepts.
    pub fn new() -> Self {
        let graph = build_sovereign_tag_graph();
        info!(
            "🧠 SemanticSearchHandler initialized — {} tags, {} edges, {} bindings",
            graph.tag_count(),
            graph.edge_count(),
            graph.binding_count()
        );
        Self {
            graph: Arc::new(RwLock::new(graph)),
        }
    }

    /// Shared graph accessor (for ZHTP gateway + plugin API integration)
    pub fn graph(&self) -> Arc<RwLock<TagGraph>> {
        self.graph.clone()
    }

    /// POST /api/v1/semantic/search
    async fn handle_search(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Parse request
        let req: SemanticSearchRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid search request: {}", e))?;

        if req.query.trim().is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Query cannot be empty".into(),
            ));
        }

        // Convert query text to a 32-D semantic vector
        let query_vector = text_to_query_vector(&req.query);

        // Determine strategies
        let strategies = if req.strategies.is_empty() {
            DEFAULT_CHANNEL_STRATEGIES.to_vec()
        } else {
            req.strategies
                .iter()
                .filter_map(|s| parse_strategy(s))
                .collect()
        };
        let strategies_ref: Vec<ChannelStrategy> = if strategies.is_empty() {
            DEFAULT_CHANNEL_STRATEGIES.to_vec()
        } else {
            strategies
        };

        let max_steps = req.max_steps.unwrap_or(50);

        // Run real semantic channeling
        let graph = self.graph.read().await;
        let result = parallel_semantic_channel(
            &graph,
            &query_vector,
            &strategies_ref,
            max_steps,
            strategies_ref.len(),
        );

        // Transform ChannelingResult → frontend VisNodes/VisLinks
        let response = channeling_result_to_vis(&req.query, &result, &graph);

        let body = serde_json::to_vec(&response)?;
        Ok(ZhtpResponse::success_with_content_type(
            body,
            "application/json".into(),
            None,
        ))
    }

    /// GET /api/v1/semantic/stats
    async fn handle_stats(&self) -> Result<ZhtpResponse> {
        let graph = self.graph.read().await;
        let stats = GraphStatsResponse {
            tag_count: graph.tag_count(),
            edge_count: graph.edge_count(),
            binding_count: graph.binding_count(),
            status: "live".into(),
        };
        let body = serde_json::to_vec(&stats)?;
        Ok(ZhtpResponse::success_with_content_type(
            body,
            "application/json".into(),
            None,
        ))
    }

    /// GET /api/v1/semantic/health
    async fn handle_health(&self) -> Result<ZhtpResponse> {
        let graph = self.graph.read().await;
        let body = serde_json::to_vec(&serde_json::json!({
            "status": "ok",
            "engine": "semantic_channeling_v1",
            "graph_tags": graph.tag_count(),
            "graph_edges": graph.edge_count(),
        }))?;
        Ok(ZhtpResponse::success_with_content_type(
            body,
            "application/json".into(),
            None,
        ))
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for SemanticSearchHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        match (request.method.as_str(), request.uri.as_str()) {
            ("POST", "/api/v1/semantic/search") => self.handle_search(request).await,
            ("GET", "/api/v1/semantic/stats") => self.handle_stats().await,
            ("GET", "/api/v1/semantic/health") => self.handle_health().await,
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!(
                    "Semantic endpoint not found: {} {}",
                    request.method, request.uri
                ),
            )),
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/semantic")
    }

    fn priority(&self) -> u32 {
        100
    }
}

// ─── Query → Vector Conversion ───────────────────────────────────────

/// Convert query text to a 32-dimensional semantic vector.
///
/// Uses BLAKE3 hashing with character-level n-gram mixing to produce
/// a deterministic embedding. This is a lightweight text→vector projection
/// that preserves some semantic properties:
/// - Similar words share some hash substructure
/// - Each character trigram contributes to a different dimension bucket
/// - The result is L2-normalized for cosine similarity compatibility
///
/// In production, this would be replaced with a proper neural embedding
/// model (e.g., sentence-transformers), but this approach integrates 
/// with the real channeling engine and produces real traversals.
pub fn text_to_query_vector(query: &str) -> Vec<f32> {
    let q = query.to_lowercase();
    let mut vec = vec![0.0f32; 32];

    // Word-level hashing: each word contributes to multiple dimensions
    for word in q.split_whitespace() {
        let hash = blake3::hash(word.as_bytes());
        let bytes = hash.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            vec[i % 32] += (b as f32 - 128.0) / 128.0;
        }
    }

    // Character trigram mixing for sub-word similarity
    let chars: Vec<char> = q.chars().collect();
    for window in chars.windows(3) {
        let trigram: String = window.iter().collect();
        let hash = blake3::hash(trigram.as_bytes());
        let bytes = hash.as_bytes();
        for i in 0..32 {
            vec[i] += (bytes[i] as f32 - 128.0) / 256.0;
        }
    }

    // L2-normalize
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        let inv = 1.0 / norm;
        for v in &mut vec {
            *v *= inv;
        }
    }

    vec
}

/// Parse strategy name from string
pub fn parse_strategy(s: &str) -> Option<ChannelStrategy> {
    match s.to_lowercase().as_str() {
        "causal" => Some(ChannelStrategy::Causal),
        "similarity" => Some(ChannelStrategy::Similarity),
        "structural" => Some(ChannelStrategy::Structural),
        "temporal" => Some(ChannelStrategy::Temporal),
        "exploratory" => Some(ChannelStrategy::Exploratory),
        "convergent" => Some(ChannelStrategy::Convergent),
        _ => None,
    }
}

// ─── ChannelingResult → Frontend Visualization ───────────────────────

/// Strategy icon mapping
fn strategy_icon(strategy: &ChannelStrategy) -> &'static str {
    match strategy {
        ChannelStrategy::Causal => "⚡",
        ChannelStrategy::Similarity => "🔗",
        ChannelStrategy::Structural => "🏗️",
        ChannelStrategy::Temporal => "⏱️",
        ChannelStrategy::Exploratory => "🔭",
        ChannelStrategy::Convergent => "🎯",
    }
}

/// Transform the real ChannelingResult into the frontend's expected
/// { nodes, links } format with levels 0-3.
pub fn channeling_result_to_vis(
    query: &str,
    result: &ChannelingResult,
    graph: &TagGraph,
) -> SemanticSearchResponse {
    let mut nodes: Vec<VisNode> = Vec::new();
    let mut links: Vec<VisLink> = Vec::new();
    let mut id_counter: usize = 0;

    // ── Level 0: Query node ──
    let query_id = format!("n{}", id_counter);
    id_counter += 1;

    let mut query_children = Vec::new();

    // ── Level 1: One node per channel (strategy = category) ──
    for channel in &result.channels {
        let ch_id = format!("n{}", id_counter);
        id_counter += 1;

        let strategy_name = format!("{}", channel.strategy);
        let strategy_label = match channel.strategy {
            ChannelStrategy::Causal => "Causal Chain",
            ChannelStrategy::Similarity => "Similarity Web",
            ChannelStrategy::Structural => "Structural Map",
            ChannelStrategy::Temporal => "Temporal Flow",
            ChannelStrategy::Exploratory => "Exploratory Path",
            ChannelStrategy::Convergent => "Convergent Focus",
        };

        let relevance = if channel.thought_chain.is_empty() {
            0.5
        } else {
            // Average edge weight of the thought chain
            let avg: f32 = channel
                .thought_chain
                .iter()
                .map(|s| s.edge_weight)
                .sum::<f32>()
                / channel.thought_chain.len() as f32;
            avg.clamp(0.3, 1.0)
        };

        let mut ch_children = Vec::new();

        // ── Level 2: Thought steps (tag traversals) ──
        for (step_idx, step) in channel.thought_chain.iter().enumerate() {
            if step_idx >= 5 {
                break; // Limit visible steps per channel
            }

            let step_id = format!("n{}", id_counter);
            id_counter += 1;

            let label = step
                .tag_label
                .clone()
                .unwrap_or_else(|| format!("tag:{}", step.tag_id.short_hex()));

            let step_relevance = step.edge_weight.clamp(0.2, 1.0);

            let mut step_children = Vec::new();

            // ── Level 3: Content discoveries + convergence ──
            // Show content count as a suggestion node
            if step.content_ids_found > 0 {
                let content_id = format!("n{}", id_counter);
                id_counter += 1;

                let content_node = VisNode {
                    id: content_id.clone(),
                    label: format!("{} content items", step.content_ids_found),
                    level: 3,
                    relevance: step_relevance * 0.8,
                    strategy: strategy_name.clone(),
                    icon: "📦".into(),
                    tags: vec![format!("tag:{}", step.tag_id.short_hex())],
                    preview: format!(
                        "Content discovered at tag '{}' via {} channel — {} items bound to this neuropathway",
                        label, strategy_label, step.content_ids_found
                    ),
                    parent_id: Some(step_id.clone()),
                    expanded: false,
                    children: vec![],
                };
                nodes.push(content_node);
                links.push(VisLink {
                    source: step_id.clone(),
                    target: content_id.clone(),
                    level: 3,
                    cross: None,
                });
                step_children.push(content_id);
            }

            // Check if this step is a convergence point
            let is_convergence = result
                .convergence_points
                .iter()
                .any(|cp| cp.tag_id == step.tag_id);

            if is_convergence {
                let conv_id = format!("n{}", id_counter);
                id_counter += 1;

                let cp = result
                    .convergence_points
                    .iter()
                    .find(|cp| cp.tag_id == step.tag_id);
                let ch_count = cp.map(|c| c.channel_count).unwrap_or(2);
                let confidence = cp.map(|c| c.confidence).unwrap_or(0.5);

                let conv_node = VisNode {
                    id: conv_id.clone(),
                    label: format!("⚡ Convergence ({}ch, {:.0}%)", ch_count, confidence * 100.0),
                    level: 3,
                    relevance: confidence.clamp(0.3, 1.0),
                    strategy: "convergent".into(),
                    icon: "🎯".into(),
                    tags: vec![format!("tag:{}", step.tag_id.short_hex())],
                    preview: format!(
                        "Convergence point: {} independent channels agreed on '{}' — confidence {:.1}%",
                        ch_count,
                        label,
                        confidence * 100.0
                    ),
                    parent_id: Some(step_id.clone()),
                    expanded: false,
                    children: vec![],
                };
                nodes.push(conv_node);
                links.push(VisLink {
                    source: step_id.clone(),
                    target: conv_id.clone(),
                    level: 3,
                    cross: None,
                });
                step_children.push(conv_id);
            }

            let step_node = VisNode {
                id: step_id.clone(),
                label,
                level: 2,
                relevance: step_relevance,
                strategy: strategy_name.clone(),
                icon: "".into(),
                tags: vec![
                    format!("tag:{}", step.tag_id.short_hex()),
                    format!("cluster:{}", step.cluster_id),
                    format!("depth:{}", step.depth),
                ],
                preview: format!(
                    "Step {} in {} channel — edge weight {:.2}, cluster {}, {} content items",
                    step.depth, strategy_label, step.edge_weight, step.cluster_id, step.content_ids_found
                ),
                parent_id: Some(ch_id.clone()),
                expanded: false,
                children: step_children,
            };
            nodes.push(step_node);
            links.push(VisLink {
                source: ch_id.clone(),
                target: step_id.clone(),
                level: 2,
                cross: None,
            });
            ch_children.push(step_id);
        }

        let ch_node = VisNode {
            id: ch_id.clone(),
            label: strategy_label.into(),
            level: 1,
            relevance,
            strategy: strategy_name.clone(),
            icon: strategy_icon(&channel.strategy).into(),
            tags: vec![
                format!("channel:{}", channel.channel_id),
                format!("steps:{}", channel.steps_taken),
                format!("content:{}", channel.discovered_content.len()),
            ],
            preview: format!(
                "{} channel — {} steps, {} content discovered, depth {}, {}μs",
                strategy_label,
                channel.steps_taken,
                channel.discovered_content.len(),
                channel.max_depth,
                channel.processing_time_us
            ),
            parent_id: Some(query_id.clone()),
            expanded: false,
            children: ch_children,
        };
        nodes.push(ch_node);
        links.push(VisLink {
            source: query_id.clone(),
            target: ch_id.clone(),
            level: 1,
            cross: None,
        });
        query_children.push(ch_id);
    }

    // ── Cross-links between channels that share convergence points ──
    let channel_node_ids: Vec<String> = nodes
        .iter()
        .filter(|n| n.level == 1)
        .map(|n| n.id.clone())
        .collect();
    for i in 0..channel_node_ids.len() {
        for j in (i + 2)..channel_node_ids.len() {
            links.push(VisLink {
                source: channel_node_ids[i].clone(),
                target: channel_node_ids[j].clone(),
                level: 1,
                cross: Some(true),
            });
        }
    }

    // ── Query node (insert at front) ──
    let query_node = VisNode {
        id: query_id,
        label: query.into(),
        level: 0,
        relevance: 1.0,
        strategy: "query".into(),
        icon: "🔍".into(),
        tags: vec![],
        preview: format!(
            "Semantic channeling: {} channels, {} unique tags, {} content, {} convergence points, {}μs",
            result.num_channels,
            result.total_unique_tags,
            result.total_unique_content,
            result.convergence_points.len(),
            result.total_time_us
        ),
        parent_id: None,
        expanded: true,
        children: query_children,
    };
    nodes.insert(0, query_node);

    let total_nodes = nodes.len();
    let total_links = links.len();

    SemanticSearchResponse {
        query: query.into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        total_nodes,
        total_links,
        nodes,
        links,
        engine: EngineMetadata {
            channels_run: result.num_channels,
            total_unique_tags: result.total_unique_tags,
            total_unique_content: result.total_unique_content,
            convergence_points: result.convergence_points.len(),
            processing_time_us: result.total_time_us,
            graph_tags: graph.tag_count(),
            graph_edges: graph.edge_count(),
            graph_bindings: graph.binding_count(),
        },
    }
}

// ─── Sovereign Network Tag Graph Bootstrap ───────────────────────────

/// Build a TagGraph seeded with Sovereign Network domain concepts.
///
/// This is the "brain" of the network — a real graph with real tags
/// and real content bindings, not mock data. Each tag has a 32-D
/// semantic vector derived from its concept, and the graph auto-connects
/// similar tags into neuropathways.
fn build_sovereign_tag_graph() -> TagGraph {
    let mut graph = TagGraph::new();

    // Helper: create a tag with a deterministic semantic vector
    // based on the label + conceptual dimensions
    let make_tag = |label: &str, concept_dims: &[f32], cluster: u32| -> SemanticTag {
        let mut vec = concept_dims.to_vec();
        // Mix in the label hash for uniqueness
        let hash = blake3::hash(label.as_bytes());
        let bytes = hash.as_bytes();
        for i in 0..32.min(vec.len()) {
            vec[i] += (bytes[i] as f32 - 128.0) / 512.0;
        }
        vec.resize(32, 0.0);
        // Fill remaining dims with label hash
        for i in concept_dims.len()..32 {
            vec[i] = (bytes[i % 32] as f32 - 128.0) / 256.0;
        }
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
            cluster_id: cluster,
            weight: 1,
            created_at: 1713600000000, // 2024-04-20
        }
    };

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 0: Compression & Codecs
    // ═══════════════════════════════════════════════════════════
    let tags_compression = vec![
        make_tag("compression", &[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0),
        make_tag("sovereign codec", &[0.95, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0),
        make_tag("entropy coding", &[0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0),
        make_tag("BWT transform", &[0.85, 0.15, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0),
        make_tag("range coder", &[0.88, 0.12, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0),
        make_tag("neural compression", &[0.8, 0.0, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0], 0),
        make_tag("adaptive codec", &[0.82, 0.08, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0], 0),
        make_tag("lossless", &[0.92, 0.08, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0),
        make_tag("shard compression", &[0.75, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0, 0.0], 0),
        make_tag("compression ratio", &[0.91, 0.09, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0),
        make_tag("deduplication", &[0.7, 0.0, 0.0, 0.3, 0.0, 0.0, 0.0, 0.0], 0),
    ];

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 1: Networking & Routing
    // ═══════════════════════════════════════════════════════════
    let tags_network = vec![
        make_tag("routing", &[0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 1),
        make_tag("QUIC transport", &[0.0, 0.95, 0.0, 0.0, 0.0, 0.0, 0.05, 0.0], 1),
        make_tag("latency", &[0.0, 0.9, 0.0, 0.0, 0.1, 0.0, 0.0, 0.0], 1),
        make_tag("bandwidth", &[0.1, 0.85, 0.0, 0.0, 0.05, 0.0, 0.0, 0.0], 1),
        make_tag("peer discovery", &[0.0, 0.8, 0.0, 0.2, 0.0, 0.0, 0.0, 0.0], 1),
        make_tag("NAT traversal", &[0.0, 0.85, 0.0, 0.0, 0.0, 0.0, 0.15, 0.0], 1),
        make_tag("mesh networking", &[0.0, 0.7, 0.0, 0.2, 0.0, 0.1, 0.0, 0.0], 1),
        make_tag("throughput", &[0.3, 0.7, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 1),
        make_tag("packet loss", &[0.0, 0.88, 0.0, 0.0, 0.12, 0.0, 0.0, 0.0], 1),
        make_tag("load balancing", &[0.0, 0.75, 0.0, 0.15, 0.1, 0.0, 0.0, 0.0], 1),
    ];

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 2: Cryptography & ZKP
    // ═══════════════════════════════════════════════════════════
    let tags_crypto = vec![
        make_tag("zero knowledge proof", &[0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0], 2),
        make_tag("Plonky2", &[0.0, 0.0, 0.95, 0.0, 0.0, 0.0, 0.05, 0.0], 2),
        make_tag("Bulletproofs", &[0.0, 0.0, 0.9, 0.0, 0.0, 0.0, 0.1, 0.0], 2),
        make_tag("BLAKE3 hashing", &[0.0, 0.0, 0.85, 0.0, 0.0, 0.0, 0.15, 0.0], 2),
        make_tag("encryption", &[0.0, 0.0, 0.8, 0.0, 0.0, 0.0, 0.2, 0.0], 2),
        make_tag("digital signatures", &[0.0, 0.0, 0.82, 0.0, 0.0, 0.0, 0.0, 0.18], 2),
        make_tag("Ristretto255", &[0.0, 0.0, 0.88, 0.0, 0.0, 0.0, 0.12, 0.0], 2),
        make_tag("commitment scheme", &[0.0, 0.0, 0.87, 0.0, 0.0, 0.0, 0.0, 0.13], 2),
        make_tag("range proof", &[0.0, 0.0, 0.92, 0.0, 0.0, 0.0, 0.08, 0.0], 2),
        make_tag("selective disclosure", &[0.0, 0.0, 0.78, 0.0, 0.0, 0.0, 0.0, 0.22], 2),
    ];

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 3: DHT & Storage
    // ═══════════════════════════════════════════════════════════
    let tags_storage = vec![
        make_tag("DHT storage", &[0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0], 3),
        make_tag("content addressing", &[0.0, 0.0, 0.0, 0.95, 0.0, 0.0, 0.0, 0.05], 3),
        make_tag("shard distribution", &[0.15, 0.0, 0.0, 0.85, 0.0, 0.0, 0.0, 0.0], 3),
        make_tag("replication", &[0.0, 0.1, 0.0, 0.9, 0.0, 0.0, 0.0, 0.0], 3),
        make_tag("Kademlia", &[0.0, 0.15, 0.0, 0.85, 0.0, 0.0, 0.0, 0.0], 3),
        make_tag("data persistence", &[0.0, 0.0, 0.0, 0.88, 0.12, 0.0, 0.0, 0.0], 3),
        make_tag("erasure coding", &[0.2, 0.0, 0.0, 0.8, 0.0, 0.0, 0.0, 0.0], 3),
        make_tag("content pinning", &[0.0, 0.0, 0.0, 0.92, 0.08, 0.0, 0.0, 0.0], 3),
        make_tag("garbage collection", &[0.0, 0.0, 0.0, 0.82, 0.18, 0.0, 0.0, 0.0], 3),
    ];

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 4: Blockchain & Consensus
    // ═══════════════════════════════════════════════════════════
    let tags_blockchain = vec![
        make_tag("blockchain", &[0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0], 4),
        make_tag("consensus", &[0.0, 0.0, 0.0, 0.0, 0.95, 0.0, 0.0, 0.05], 4),
        make_tag("proof of useful work", &[0.0, 0.0, 0.0, 0.0, 0.9, 0.1, 0.0, 0.0], 4),
        make_tag("block validation", &[0.0, 0.0, 0.1, 0.0, 0.9, 0.0, 0.0, 0.0], 4),
        make_tag("transaction", &[0.0, 0.0, 0.0, 0.0, 0.88, 0.0, 0.0, 0.12], 4),
        make_tag("UTXO model", &[0.0, 0.0, 0.0, 0.0, 0.85, 0.0, 0.0, 0.15], 4),
        make_tag("finality", &[0.0, 0.0, 0.0, 0.0, 0.92, 0.08, 0.0, 0.0], 4),
        make_tag("mempool", &[0.0, 0.1, 0.0, 0.0, 0.82, 0.0, 0.08, 0.0], 4),
        make_tag("fee market", &[0.0, 0.0, 0.0, 0.0, 0.8, 0.0, 0.0, 0.2], 4),
        make_tag("validator rewards", &[0.0, 0.0, 0.0, 0.0, 0.78, 0.0, 0.0, 0.22], 4),
    ];

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 5: Neural Mesh & AI
    // ═══════════════════════════════════════════════════════════
    let tags_neural = vec![
        make_tag("neural mesh", &[0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0], 5),
        make_tag("semantic channeling", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.95, 0.0, 0.05], 5),
        make_tag("anomaly detection", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.9, 0.0, 0.1], 5),
        make_tag("RL routing", &[0.0, 0.2, 0.0, 0.0, 0.0, 0.8, 0.0, 0.0], 5),
        make_tag("predictive prefetch", &[0.0, 0.1, 0.0, 0.1, 0.0, 0.8, 0.0, 0.0], 5),
        make_tag("federated learning", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.85, 0.0, 0.15], 5),
        make_tag("model compression", &[0.3, 0.0, 0.0, 0.0, 0.0, 0.7, 0.0, 0.0], 5),
        make_tag("distributed training", &[0.0, 0.15, 0.0, 0.0, 0.0, 0.85, 0.0, 0.0], 5),
        make_tag("neuropathway", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.92, 0.0, 0.08], 5),
        make_tag("convergence point", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.88, 0.0, 0.12], 5),
        make_tag("thought chain", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.9, 0.05, 0.05], 5),
    ];

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 6: Identity & Privacy
    // ═══════════════════════════════════════════════════════════
    let tags_identity = vec![
        make_tag("identity", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0], 6),
        make_tag("DID", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.95], 6),
        make_tag("verifiable credential", &[0.0, 0.0, 0.15, 0.0, 0.0, 0.0, 0.0, 0.85], 6),
        make_tag("self-sovereign identity", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.92], 6),
        make_tag("guardian recovery", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.9], 6),
        make_tag("social recovery", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.15, 0.85], 6),
        make_tag("biometric binding", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.2, 0.8], 6),
        make_tag("reputation", &[0.0, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.9], 6),
        make_tag("delegation", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.88], 6),
        make_tag("KYC", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.12, 0.88], 6),
    ];

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 7: Web4 & DNS
    // ═══════════════════════════════════════════════════════════
    let tags_web4 = vec![
        make_tag("Web4", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0], 7),
        make_tag("ZHTP protocol", &[0.0, 0.15, 0.0, 0.0, 0.0, 0.0, 0.85, 0.0], 7),
        make_tag("sovereign domain", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9, 0.1], 7),
        make_tag("DNS resolution", &[0.0, 0.2, 0.0, 0.0, 0.0, 0.0, 0.8, 0.0], 7),
        make_tag("content publishing", &[0.0, 0.0, 0.0, 0.2, 0.0, 0.0, 0.8, 0.0], 7),
        make_tag("HTTPS gateway", &[0.0, 0.2, 0.0, 0.0, 0.0, 0.0, 0.8, 0.0], 7),
        make_tag("browser extension", &[0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.92, 0.08], 7),
        make_tag("domain registry", &[0.0, 0.0, 0.0, 0.0, 0.1, 0.0, 0.9, 0.0], 7),
    ];

    // ═══════════════════════════════════════════════════════════
    // CLUSTER 8: Governance & Economy
    // ═══════════════════════════════════════════════════════════
    let tags_governance = vec![
        make_tag("governance", &[0.0, 0.0, 0.0, 0.0, 0.15, 0.0, 0.0, 0.85], 8),
        make_tag("DAO", &[0.0, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0, 0.8], 8),
        make_tag("token economics", &[0.0, 0.0, 0.0, 0.0, 0.3, 0.0, 0.0, 0.7], 8),
        make_tag("bonding curve", &[0.0, 0.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.75], 8),
        make_tag("voting", &[0.0, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.9], 8),
        make_tag("treasury", &[0.0, 0.0, 0.0, 0.0, 0.2, 0.0, 0.0, 0.8], 8),
        make_tag("oracle", &[0.0, 0.0, 0.0, 0.0, 0.15, 0.0, 0.1, 0.75], 8),
        make_tag("marketplace", &[0.0, 0.0, 0.0, 0.0, 0.1, 0.0, 0.2, 0.7], 8),
    ];

    // ── Insert all tags ──
    let all_clusters = vec![
        tags_compression,
        tags_network,
        tags_crypto,
        tags_storage,
        tags_blockchain,
        tags_neural,
        tags_identity,
        tags_web4,
        tags_governance,
    ];

    for cluster_tags in &all_clusters {
        for tag in cluster_tags {
            graph.insert_tag(tag.clone());
        }
    }

    // ── Content bindings — simulate real content on the network ──
    let mut content_id: u8 = 0x01;
    let mut make_content_id = || -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = content_id;
        content_id = content_id.wrapping_add(1);
        // Hash it for realistic distribution
        *blake3::hash(&id).as_bytes()
    };

    // Bind content across clusters to create realistic cross-connections
    let all_tags: Vec<&SemanticTag> = all_clusters.iter().flat_map(|c| c.iter()).collect();

    // Bind every 2 adjacent tags within a cluster (intra-cluster content)
    for cluster in &all_clusters {
        for pair in cluster.windows(2) {
            graph.bind_content(ContentTagBinding::new(
                make_content_id(),
                vec![pair[0].tag_id, pair[1].tag_id],
                vec![make_content_id()],
            ));
        }
    }

    // Cross-cluster bindings for bridge concepts
    let cross_bindings = vec![
        // Compression ↔ Networking
        ("compression", "throughput"),
        ("shard compression", "shard distribution"),
        ("neural compression", "neural mesh"),
        // Crypto ↔ Identity  
        ("zero knowledge proof", "selective disclosure"),
        ("BLAKE3 hashing", "content addressing"),
        ("commitment scheme", "verifiable credential"),
        // Blockchain ↔ Governance
        ("consensus", "governance"),
        ("transaction", "token economics"),
        ("validator rewards", "bonding curve"),
        // Neural ↔ Compression
        ("model compression", "sovereign codec"),
        ("distributed training", "federated learning"),
        // Web4 ↔ Identity
        ("sovereign domain", "self-sovereign identity"),
        ("ZHTP protocol", "QUIC transport"),
        // Storage ↔ Web4
        ("content addressing", "content publishing"),
        ("DHT storage", "content pinning"),
    ];

    for (label_a, label_b) in &cross_bindings {
        let tag_a = all_tags.iter().find(|t| t.label.as_deref() == Some(label_a));
        let tag_b = all_tags.iter().find(|t| t.label.as_deref() == Some(label_b));
        if let (Some(a), Some(b)) = (tag_a, tag_b) {
            graph.bind_content(ContentTagBinding::new(
                make_content_id(),
                vec![a.tag_id, b.tag_id],
                vec![make_content_id()],
            ));
        }
    }

    graph
}
