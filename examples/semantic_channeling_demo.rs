//! # Semantic Channeling Integration Demo (with SovereignCodec Compression)
//!
//! End-to-end demonstration of all 6 integration layers, using the real
//! SovereignCodec (BWT->MTF->RLE->Range) for model weight compression.
//!
//! 1. **ContentProfile -> Semantic Tags**: Analyze content, generate tags
//! 2. **SemanticTagIndex**: Index tags -> shards for fast lookup
//! 3. **ZK Tag Membership Proofs**: Prove tag ownership without revealing content
//! 4. **SemanticPrefetcher**: Predict future tag-chain traversals with LSTM
//! 5. **SovereignCodec Compression**: Lossless model compression (THE REAL THING)
//! 6. **Full Pipeline**: Parallel semantic channeling through a tag graph
//!
//! Run: `cargo run --example semantic_channeling_demo -p lib-compression`

use lib_neural_mesh::{
    // Core semantic channeling
    TagGraph, SemanticTag, TagId, ContentTagBinding,
    parallel_semantic_channel, ChannelStrategy,
    // Content profiling + tag generation
    ContentProfile, TagGenerationConfig, NeuroCompressor,
    // Semantic prefetcher
    SemanticPrefetcher, TagAccessEvent,
    // Distributed training
    CompressedModel, ModelId,
};
use lib_compression::{SovereignCodecCompressor, SovereignCodec};
use lib_neural_mesh::distributed::ModelCompressor;

fn main() {
    println!("===================================================================");
    println!("  Sovereign Network -- Semantic Channeling Integration Demo");
    println!("  (with real SovereignCodec lossless compression)");
    println!("===================================================================\n");

    // -- Step 1: Content -> Semantic Tags
    let all_tags = step1_content_to_tags();

    // -- Step 2: Tag Index (storage layer)
    step2_tag_index();

    // -- Step 3: ZK Tag Membership Proofs
    step3_zk_proofs();

    // -- Step 4: Semantic Prefetcher (tag-chain prediction)
    step4_semantic_prefetcher();

    // -- Step 5: Lossless Compression with SovereignCodec
    step5_sovereign_compression();

    // -- Step 6: Full Pipeline -- channel through the tag graph
    step6_full_pipeline(&all_tags);

    println!("\n===================================================================");
    println!("  All 6 stages complete. Semantic Channeling is operational.");
    println!("  Compression: SovereignCodec SFC7 (BWT->MTF->RLE->Range)");
    println!("  Status: LOSSLESS VERIFIED");
    println!("===================================================================");
}

// -----------------------------------------------------------------------
// Step 1: Content Profiling -> Semantic Tags
// -----------------------------------------------------------------------

fn step1_content_to_tags() -> Vec<SemanticTag> {
    println!("[ 1 / 6 ] Content Profiling -> Semantic Tags");
    println!("---------------------------------------------\n");

    let content_samples: &[(&str, &[u8])] = &[
        ("Rust source code", b"fn main() { let x: Vec<u8> = vec![1,2,3]; println!(\"{:?}\", x); }"),
        ("JSON config",      b"{\"nodes\": 128, \"replication\": 3, \"latency_target_ms\": 50}"),
        ("Binary blob",      &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42, 0x42, 0x01, 0x02, 0x03, 0x04,
                               0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    ];

    let mut compressor = NeuroCompressor::new();
    compressor.enable();
    let config = TagGenerationConfig {
        num_sub_tags: 3,
        dedup_threshold: 0.85,
    };

    let mut all_tags = Vec::new();

    for (label, data) in content_samples {
        let profile = ContentProfile::analyze(data);
        let tags = profile.generate_semantic_tags(&compressor, data, &config).unwrap();

        println!("  Content:  \"{}\" ({} bytes)", label, data.len());
        println!("  Type:     {:?}", profile.content_type);
        println!("  Entropy:  {:.3}", profile.entropy);
        println!("  Tags:     {} generated", tags.len());
        for (i, tag) in tags.iter().enumerate() {
            let kind = if i == 0 { "primary" } else { "sub-tag" };
            println!("    [{}] {}", kind, tag.tag_id);
        }
        println!();

        all_tags.extend(tags);
    }

    println!("  OK -- content analysis and tag generation working.\n");
    all_tags
}

// -----------------------------------------------------------------------
// Step 2: SemanticTagIndex (storage layer)
// -----------------------------------------------------------------------

fn step2_tag_index() {
    println!("[ 2 / 6 ] SemanticTagIndex -- tag -> shard mapping");
    println!("---------------------------------------------\n");

    let tag_compression = *blake3::hash(b"topic:compression").as_bytes();
    let tag_routing     = *blake3::hash(b"topic:routing").as_bytes();
    let tag_crypto      = *blake3::hash(b"topic:crypto").as_bytes();

    let shard_a = *blake3::hash(b"shard:alpha").as_bytes();
    let shard_b = *blake3::hash(b"shard:beta").as_bytes();
    let shard_c = *blake3::hash(b"shard:gamma").as_bytes();

    let mut index: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>> =
        std::collections::HashMap::new();

    index.entry(tag_compression).or_default().push(shard_a);
    index.entry(tag_routing).or_default().push(shard_a);
    index.entry(tag_routing).or_default().push(shard_b);
    index.entry(tag_crypto).or_default().push(shard_b);
    index.entry(tag_compression).or_default().push(shard_c);
    index.entry(tag_crypto).or_default().push(shard_c);

    println!("  Indexed 3 tag types across 3 shards:");
    println!("    compression : {} shards", index[&tag_compression].len());
    println!("    routing     : {} shards", index[&tag_routing].len());
    println!("    crypto      : {} shards", index[&tag_crypto].len());

    let compression_shards = &index[&tag_compression];
    println!("\n  Query(compression) -> {} shard(s) found", compression_shards.len());

    let comp_set: std::collections::HashSet<_> = index[&tag_compression].iter().collect();
    let route_set: std::collections::HashSet<_> = index[&tag_routing].iter().collect();
    let intersection: Vec<_> = comp_set.intersection(&route_set).collect();
    println!("  Query(compression AND routing) -> {} shard(s) found", intersection.len());

    let serialized = bincode::serialize(&index).unwrap();
    let restored: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>> =
        bincode::deserialize(&serialized).unwrap();
    assert_eq!(index.len(), restored.len());
    println!("\n  Serialization roundtrip: {} bytes, OK", serialized.len());

    println!("\n  OK -- tag index queries working.\n");
}

// -----------------------------------------------------------------------
// Step 3: ZK Tag Membership Proofs
// -----------------------------------------------------------------------

fn step3_zk_proofs() {
    println!("[ 3 / 6 ] ZK Tag Membership Proofs");
    println!("---------------------------------------------\n");

    let content = b"Sovereign Network: decentralized intelligence";
    let content_id = *blake3::hash(content).as_bytes();

    let tag_a = *blake3::hash(b"topic:ai").as_bytes();
    let tag_b = *blake3::hash(b"topic:mesh").as_bytes();
    let shard  = *blake3::hash(b"shard:001").as_bytes();

    let binding = ContentTagBinding::new(
        content_id,
        vec![TagId(tag_a), TagId(tag_b)],
        vec![shard],
    );

    println!("  Content ID:   {}...", hex(&content_id[..8]));
    println!("  Tags bound:   {} tags", binding.tag_ids.len());
    println!("  Shards:       {} shard(s)", binding.shard_ids.len());
    println!("  Commitment:   {}...", hex(&binding.proof_commitment[..8]));

    let valid = binding.verify_commitment();
    println!("  Verified:     {}", if valid { "PASS" } else { "FAIL" });
    assert!(valid, "Commitment should verify");

    let mut tampered = binding.clone();
    tampered.tag_ids.push(TagId([0xFF; 32]));
    let tampered_valid = tampered.verify_commitment();
    println!("  Tamper test:  {}",
        if !tampered_valid { "DETECTED (good!)" } else { "MISSED (bad!)" });
    assert!(!tampered_valid, "Tampered binding should NOT verify");

    println!("\n  OK -- ZK tag membership proofs working.\n");
}

// -----------------------------------------------------------------------
// Step 4: SemanticPrefetcher -- tag-chain prediction
// -----------------------------------------------------------------------

fn step4_semantic_prefetcher() {
    println!("[ 4 / 6 ] SemanticPrefetcher -- tag-chain LSTM prediction");
    println!("---------------------------------------------\n");

    let mut prefetcher = SemanticPrefetcher::new();
    prefetcher.enable_default();

    let tags: Vec<TagId> = (0..8u8)
        .map(|i| TagId(*blake3::hash(&[i]).as_bytes()))
        .collect();

    for i in 0..30u64 {
        let chain_len = (i % 3 + 1) as usize;
        let start = (i % 5) as usize;
        let chain: Vec<TagId> = (0..chain_len)
            .map(|j| tags[(start + j) % tags.len()])
            .collect();

        prefetcher.record_tag_access(TagAccessEvent {
            tag_chain: chain,
            timestamp: 1000 + i * 200,
            strategy_id: (i % 3) as u8,
        });
    }

    println!("  Recorded 30 tag access events");
    println!("  Tag vocabulary: {} unique tags", prefetcher.tag_vocab_size());

    let (loss, num_seq) = prefetcher.train_from_tag_history().unwrap();
    println!("\n  Training:");
    println!("    Sequences: {}", num_seq);
    println!("    Loss:      {:.6}", loss);

    let predictions = prefetcher.predict_next_tags(3).unwrap();
    println!("\n  Predictions: ({} results)", predictions.len());
    for (i, pred) in predictions.iter().enumerate() {
        println!("    {}. {} (confidence: {:.1}%, lookahead: {})",
            i + 1,
            pred.predicted_tags[0],
            pred.confidence * 100.0,
            pred.lookahead,
        );
    }

    let model_bytes = prefetcher.save_tag_model().unwrap();
    println!("\n  Tag LSTM model: {} bytes", model_bytes.len());
    println!("  Total model size: {} bytes", prefetcher.total_model_size_bytes());

    let mut restored = SemanticPrefetcher::new();
    restored.load_tag_model(&model_bytes).unwrap();
    println!("  Model reload:  OK");

    println!("\n  OK -- semantic prefetching working.\n");
}

// -----------------------------------------------------------------------
// Step 5: SovereignCodec Lossless Compression (THE REAL THING)
// -----------------------------------------------------------------------

fn step5_sovereign_compression() {
    println!("[ 5 / 6 ] SovereignCodec Lossless Compression");
    println!("---------------------------------------------\n");

    let compressor = SovereignCodecCompressor;
    println!("  Compressor:   {} (BWT->MTF->RLE->Range)", compressor.name());

    // ── 5a: Raw SovereignCodec on various data types ──────────────────

    println!("\n  --- Raw SovereignCodec Codec Tests ---\n");

    let model_weight_data: Vec<u8> = (0..64u32)
        .flat_map(|i| (i as f32 * 0.015625).to_le_bytes())
        .collect();

    let repeated_pattern: Vec<u8> = [0xAA, 0xBB, 0xCC, 0xDD].repeat(64);

    let test_data: Vec<(&str, &[u8])> = vec![
        ("Rust source code",
         b"fn compress(data: &[u8]) -> Vec<u8> { sovereign_codec::encode(data) }"),
        ("JSON config",
         b"{\"peers\":[\"10.0.1.1:8443\",\"10.0.1.2:8443\"],\"ttl\":64,\"replicas\":3}"),
        ("Model weights (f32)", &model_weight_data),
        ("Repeated pattern", &repeated_pattern),
    ];

    for (label, data) in &test_data {
        let encoded = SovereignCodec::encode(data);
        let decoded = SovereignCodec::decode(&encoded).unwrap();
        let ratio = data.len() as f64 / encoded.len() as f64;
        let lossless = decoded == *data;

        println!("  {:24} {:>5} -> {:>5} bytes ({:.2}x)  lossless: {}",
            label, data.len(), encoded.len(), ratio,
            if lossless { "YES" } else { "FAIL" });
        assert!(lossless, "SovereignCodec MUST be lossless for {}", label);
    }

    // ── 5b: CompressedModel with SovereignCodec (lossless path) ───────

    println!("\n  --- CompressedModel + SovereignCodec (lossless) ---\n");

    let model_id = ModelId::SemanticChanneler;
    println!("  ModelId:     {}", model_id);
    println!("  Debug:       {:?}", model_id);

    // Create realistic model weights (256 f32 values)
    let fake_weights: Vec<u8> = (0..256u32)
        .flat_map(|i| (i as f32 * 0.00390625).to_le_bytes()) // 0.0 .. 1.0
        .collect();

    println!("  Raw weights: {} bytes ({} f32 params)", fake_weights.len(), fake_weights.len() / 4);

    // Compress losslessly (no int8 quantization)
    let compressed = CompressedModel::compress_lossless(
        ModelId::SemanticChanneler,
        &fake_weights,
        "demo-node-1",
        0,
        &compressor,
    );

    println!("\n  CompressedModel:");
    println!("    model_id:     {}", compressed.model_id);
    println!("    raw_size:     {} bytes", compressed.raw_size);
    println!("    compressed:   {} bytes", compressed.compressed_weights.len());
    println!("    source_node:  {}", compressed.source_node);
    println!("    ratio:        {:.2}x", compressed.compression_ratio);

    // Decompress and verify bit-perfect lossless
    let restored = compressed.decompress(&compressor).unwrap();
    assert_eq!(
        restored, fake_weights,
        "LOSSLESS VIOLATION: decompressed weights must be bit-perfect identical"
    );
    println!("    decompress:   OK ({} bytes, BIT-PERFECT LOSSLESS)", restored.len());

    // ── 5c: Compare with quantized path ───────────────────────────────

    println!("\n  --- Comparison: Lossless vs Quantized ---\n");

    let compressed_quant = CompressedModel::compress(
        ModelId::SemanticChanneler,
        &fake_weights,
        "demo-node-1",
        0,
        &compressor,
    );

    let restored_quant = compressed_quant.decompress(&compressor).unwrap();
    let max_error: f32 = fake_weights.chunks(4).zip(restored_quant.chunks(4))
        .map(|(orig, rest)| {
            let o = f32::from_le_bytes([orig[0], orig[1], orig[2], orig[3]]);
            let r = f32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
            (o - r).abs()
        })
        .fold(0.0f32, f32::max);

    println!("  Lossless path:");
    println!("    Size:       {} -> {} bytes ({:.2}x)",
        fake_weights.len(), compressed.compressed_weights.len(), compressed.compression_ratio);
    println!("    Fidelity:   EXACT (0 error)");

    println!("  Quantized path (int8 + SovereignCodec):");
    println!("    Size:       {} -> {} bytes ({:.2}x)",
        fake_weights.len(), compressed_quant.compressed_weights.len(),
        compressed_quant.compression_ratio);
    println!("    Fidelity:   max error = {:.6} per weight", max_error);

    println!("\n  All ModelIds:");
    for id in &[ModelId::RlRouter, ModelId::Prefetcher, ModelId::AnomalySentry, ModelId::SemanticChanneler] {
        println!("    - {}", id);
    }

    println!("\n  OK -- SovereignCodec lossless compression verified.\n");
}

// -----------------------------------------------------------------------
// Step 6: Full Pipeline -- parallel semantic channeling
// -----------------------------------------------------------------------

fn step6_full_pipeline(all_tags: &[SemanticTag]) {
    println!("[ 6 / 6 ] Full Pipeline -- Parallel Semantic Channeling");
    println!("---------------------------------------------\n");

    let mut graph = TagGraph::new();

    let mut compressor = NeuroCompressor::new();
    compressor.enable();
    let config = TagGenerationConfig { num_sub_tags: 2, dedup_threshold: 0.80 };

    let content_items: &[(&str, &[u8])] = &[
        ("source code",    b"fn compress(data: &[u8]) -> Vec<u8> { zstd::encode(data) }"),
        ("network config", b"{ \"peers\": [\"10.0.1.1:8443\", \"10.0.1.2:8443\"], \"ttl\": 64 }"),
        ("binary data",    &[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x03, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00]),
        ("prose text",     b"The sovereign network enables truly decentralized communication \
                             without relying on centralized infrastructure."),
        ("crypto keys",    b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"),
    ];

    let mut graph_tags = Vec::new();

    for (label, data) in content_items {
        let profile = ContentProfile::analyze(data);
        let tags = profile.generate_semantic_tags(&compressor, data, &config).unwrap();
        let content_id = *blake3::hash(*data).as_bytes();
        let shard_id = *blake3::hash(&content_id).as_bytes();

        for tag in &tags {
            graph.insert_tag(tag.clone());
        }

        let binding = ContentTagBinding::new(
            content_id,
            tags.iter().map(|t| t.tag_id).collect(),
            vec![shard_id],
        );
        assert!(binding.verify_commitment(), "Binding should verify for {}", label);
        graph.bind_content(binding);

        graph_tags.extend(tags);
    }

    for tag in all_tags {
        graph.insert_tag(tag.clone());
    }

    println!("  Tag Graph:");
    println!("    Tags:       {}", graph.tag_count());
    println!("    Edges:      {}", graph.edge_count());
    println!("    Bindings:   {}", graph.binding_count());

    let query_vector: Vec<f32> = if let Some(first_tag) = graph_tags.first() {
        first_tag.semantic_vector.clone()
    } else {
        (0..32).map(|i| (i as f32 * 0.1).sin()).collect()
    };

    let strategies = vec![
        ChannelStrategy::Causal,
        ChannelStrategy::Similarity,
        ChannelStrategy::Exploratory,
    ];

    println!("\n  Running parallel_semantic_channel with {} strategies...",
        strategies.len());

    let result = parallel_semantic_channel(
        &graph,
        &query_vector,
        &strategies,
        50,   // max_steps
        3,    // num_seed_tags
    );

    println!("\n  ChannelingResult:");
    println!("    Channels:           {}", result.num_channels);
    println!("    Unique tags:        {}", result.total_unique_tags);
    println!("    Unique content:     {}", result.total_unique_content);
    println!("    Convergence points: {}", result.convergence_points.len());
    println!("    Total time:         {} us", result.total_time_us);

    for (i, ch) in result.channels.iter().enumerate() {
        println!("\n    Channel #{} ({:?}):", i, ch.strategy);
        println!("      steps:    {}", ch.steps_taken);
        println!("      max_depth: {}", ch.max_depth);
        println!("      thoughts: {}", ch.thought_chain.len());
        println!("      content:  {} items discovered", ch.discovered_content.len());
        println!("      time:     {} us", ch.processing_time_us);
        if let Some(first) = ch.thought_chain.first() {
            println!("      start:    {} (depth {})", first.tag_id, first.depth);
        }
        if let Some(last) = ch.thought_chain.last() {
            println!("      end:      {} (depth {})", last.tag_id, last.depth);
        }
    }

    if !result.convergence_points.is_empty() {
        println!("\n  Convergence Points (multi-strategy agreement):");
        for cp in &result.convergence_points {
            println!("    {} -- found by {} channel(s) {:?} (confidence: {:.2}, content: {})",
                cp.tag_id,
                cp.channel_count,
                cp.channel_ids,
                cp.confidence,
                cp.content_count,
            );
        }
    } else {
        println!("\n  No convergence points (strategies explored disjoint regions)");
    }

    println!("\n  OK -- full semantic channeling pipeline working.");
}

// Utility: hex-encode bytes
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
