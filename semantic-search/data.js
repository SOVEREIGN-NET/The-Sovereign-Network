/* ================================================================
   data.js — Semantic Channeling Data Layer  v4
   ================================================================
   DUAL MODE:
     • LIVE MODE — Calls the real ZHTP Sovereign Network semantic
       channeling API (port 9381). The channeling engine runs real
       parallel thought-chains through a live TagGraph.
     • FALLBACK MODE — If the API is unreachable, falls back to the
       client-side domain classifier (v2 mock generator).

   PLUGIN API:
     Developers/companies can register custom datasets as plugins,
     each with its own private TagGraph. The same channeling engine
     powers both the network graph and private plugins. All data is
     encrypted end-to-end via ZHTP's ZKP + encryption layer.

     SemanticData.plugins.register(name, opts)  — Register a plugin
     SemanticData.plugins.list()                — List all plugins
     SemanticData.plugins.remove(id)            — Remove a plugin
     SemanticData.plugins.ingest(id, items)     — Ingest data items
     SemanticData.plugins.search(id, query)     — Search a plugin
     SemanticData.plugins.stats(id)             — Get plugin stats
     SemanticData.sources.list()                — List all data sources
     SemanticData.sources.setActive(id)         — Set active source
     SemanticData.sources.getActive()           — Get active source
     SemanticData.unified(query)                — Search ALL sources

   NEURAL COMPRESSION LEARNING:
     When data is ingested, compression signatures drive new connections.
     Content with similar compression profiles gets auto-linked.
   ================================================================ */

const SemanticData = (() => {

  // ═══════════════════════════════════════════════════════════════
  // CONFIGURATION
  // ═══════════════════════════════════════════════════════════════

  const API_BASE = "http://localhost:9381";
  const API_ENDPOINT = `${API_BASE}/api/v1/semantic/search`;
  const HEALTH_ENDPOINT = `${API_BASE}/api/v1/semantic/health`;
  const PLUGINS_ENDPOINT = `${API_BASE}/api/v1/semantic/plugins`;
  const UNIFIED_ENDPOINT = `${API_BASE}/api/v1/semantic/unified`;

  let _liveMode = null;  // null = untested, true = live, false = mock
  let _activeSource = "network"; // "network" or a plugin hex ID
  let _healthData = null; // Cached health response

  // ═══════════════════════════════════════════════════════════════
  // LIVE API CLIENT
  // ═══════════════════════════════════════════════════════════════

  /**
   * Check if the real ZHTP semantic API is running.
   * Caches the result after first check.
   */
  async function checkLive() {
    if (_liveMode !== null) return _liveMode;
    try {
      const resp = await fetch(HEALTH_ENDPOINT, {
        signal: AbortSignal.timeout(2000),
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.status === "ok") {
          _liveMode = true;
          _healthData = data;
          const pluginCount = data.plugins || 0;
          const features = data.features || {};
          console.log(
            `%c🧠 LIVE MODE — Connected to Sovereign Network semantic engine (${data.graph_tags} tags, ${data.graph_edges} edges, ${pluginCount} plugins)`,
            "color: #4c9aff; font-weight: bold; font-size: 14px"
          );
          if (features.plugin_api) {
            console.log(
              "%c🔌 Plugin API available — register custom datasets with SemanticData.plugins",
              "color: #a78bfa; font-style: italic"
            );
          }
          return true;
        }
      }
    } catch (_) {
      // API not available
    }
    _liveMode = false;
    _healthData = null;
    console.log(
      "%c⚠️ FALLBACK MODE — ZHTP API not reachable, using client-side domain classifier",
      "color: #ff9f43; font-weight: bold"
    );
    return false;
  }

  /**
   * Call the real semantic channeling API.
   * Returns the same shape as the mock generator.
   */
  async function fetchLive(query) {
    const resp = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, max_steps: 50 }),
      signal: AbortSignal.timeout(10000),
    });
    if (!resp.ok) throw new Error(`API returned ${resp.status}`);
    return await resp.json();
  }

  /**
   * Call a plugin's search endpoint.
   */
  async function fetchPluginSearch(pluginId, query) {
    const resp = await fetch(`${PLUGINS_ENDPOINT}/${pluginId}/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, max_steps: 50 }),
      signal: AbortSignal.timeout(10000),
    });
    if (!resp.ok) throw new Error(`Plugin search returned ${resp.status}`);
    return await resp.json();
  }

  // ═══════════════════════════════════════════════════════════════
  // PUBLIC API — async, tries live first, falls back to mock
  // ═══════════════════════════════════════════════════════════════

  /**
   * Main entry point. Returns { query, timestamp, totalNodes, totalLinks, nodes[], links[] }
   * Routes to the active source (network, plugin, or fallback mock).
   */
  async function generate(query) {
    const isLive = await checkLive();

    if (isLive) {
      try {
        let result;
        if (_activeSource === "network") {
          result = await fetchLive(query);
          result._mode = "live";
          result._source = "Sovereign Network";
        } else {
          result = await fetchPluginSearch(_activeSource, query);
          result._mode = "plugin";
          result._source = _activeSource;
        }
        return result;
      } catch (e) {
        console.warn("Live API call failed, falling back to mock:", e.message);
        _liveMode = false;
      }
    }

    // Fallback to mock generator
    const result = generateMock(query);
    result._mode = "mock";
    result._source = "local-classifier";
    return result;
  }

  /**
   * Search ALL sources at once (network + all plugins).
   * Returns { query, sources: [{ source_id, source_name, source_type, result }], timestamp }
   */
  async function unified(query) {
    const isLive = await checkLive();
    if (!isLive) {
      // Fallback: wrap mock result as a single source
      const result = generateMock(query);
      return {
        query,
        sources: [{ source_id: "mock", source_name: "Local Classifier", source_type: "mock", result }],
        timestamp: new Date().toISOString(),
      };
    }

    const resp = await fetch(UNIFIED_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, max_steps: 50 }),
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) throw new Error(`Unified search returned ${resp.status}`);
    return await resp.json();
  }

  /**
   * Force a re-check of the live API on next call.
   */
  function resetLiveCheck() {
    _liveMode = null;
  }

  /**
   * Get current mode: "live", "mock", or "unknown"
   */
  function getMode() {
    if (_liveMode === null) return "unknown";
    return _liveMode ? "live" : "mock";
  }

  // ═══════════════════════════════════════════════════════════════
  // PLUGIN API CLIENT
  // ═══════════════════════════════════════════════════════════════

  const plugins = {
    /**
     * Register a new plugin (private dataset).
     * @param {string} name - Human-readable name
     * @param {Object} opts - Options: description, embedding_source, categories, enable_compression_learning
     * @returns {Promise<{id: string, status: string}>}
     *
     * Example:
     *   await SemanticData.plugins.register("Company Docs", {
     *     description: "Internal documentation",
     *     categories: ["Engineering", "Design", "Legal"],
     *     enable_compression_learning: true,
     *   });
     */
    async register(name, opts = {}) {
      const resp = await fetch(PLUGINS_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          description: opts.description || "",
          embedding_source: opts.embedding_source || "Builtin",
          categories: opts.categories || [],
          enable_compression_learning: opts.enable_compression_learning !== false,
        }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `Registration failed: ${resp.status}`);
      }
      return await resp.json();
    },

    /**
     * List all registered plugins.
     * @returns {Promise<{plugins: Array, count: number}>}
     */
    async list() {
      const resp = await fetch(PLUGINS_ENDPOINT);
      if (!resp.ok) throw new Error(`Failed to list plugins: ${resp.status}`);
      return await resp.json();
    },

    /**
     * Remove a plugin by ID or name.
     * @param {string} id - Plugin hex ID or name
     * @returns {Promise<{removed: string}>}
     */
    async remove(id) {
      const resp = await fetch(`${PLUGINS_ENDPOINT}/${id}`, { method: "DELETE" });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `Removal failed: ${resp.status}`);
      }
      return await resp.json();
    },

    /**
     * Ingest data items into a plugin.
     * @param {string} id - Plugin hex ID or name
     * @param {Array<Object>} items - Items: { content, labels?, embedding?, metadata?, category? }
     * @returns {Promise<{ingested, tags_created, bindings_created, graph_tags, graph_edges}>}
     *
     * Example:
     *   await SemanticData.plugins.ingest(pluginId, [
     *     { content: "My document text", labels: ["doc", "engineering"], category: "Engineering" },
     *     { content: "Another doc", labels: ["design"], category: "Design" },
     *   ]);
     */
    async ingest(id, items) {
      const resp = await fetch(`${PLUGINS_ENDPOINT}/${id}/ingest`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ items }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `Ingest failed: ${resp.status}`);
      }
      return await resp.json();
    },

    /**
     * Search a plugin's private graph.
     * @param {string} id - Plugin hex ID or name
     * @param {string} query - Search query
     * @returns {Promise<SemanticSearchResponse>}
     */
    async search(id, query) {
      return await fetchPluginSearch(id, query);
    },

    /**
     * Get statistics for a plugin's graph.
     * @param {string} id - Plugin hex ID or name
     * @returns {Promise<{tag_count, edge_count, binding_count, item_count, ...}>}
     */
    async stats(id) {
      const resp = await fetch(`${PLUGINS_ENDPOINT}/${id}/stats`);
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `Stats failed: ${resp.status}`);
      }
      return await resp.json();
    },
  };

  // ═══════════════════════════════════════════════════════════════
  // DATA SOURCE MANAGEMENT
  // ═══════════════════════════════════════════════════════════════

  const sources = {
    /**
     * List all available data sources (network + registered plugins).
     * @returns {Promise<Array<{id, name, type, tags?, edges?}>>}
     */
    async list() {
      const srcs = [{ id: "network", name: "Sovereign Network", type: "network" }];
      try {
        const data = await plugins.list();
        for (const p of (data.plugins || [])) {
          srcs.push({
            id: p.id,
            name: p.name,
            type: "plugin",
            tags: p.graph_tags,
            edges: p.graph_edges,
            items: p.item_count,
          });
        }
      } catch (_) {
        // Plugins not available
      }
      return srcs;
    },

    /**
     * Set the active data source for generate() calls.
     * @param {string} id - "network" or a plugin hex ID
     */
    setActive(id) {
      _activeSource = id;
      console.log(`%c📌 Active source: ${id}`, "color: #a78bfa; font-weight: bold");
    },

    /**
     * Get the active data source ID.
     * @returns {string}
     */
    getActive() {
      return _activeSource;
    },
  };

  // ═══════════════════════════════════════════════════════════════
  // DOMAIN SIGNAL DATABASE
  // Each domain has:
  //   keywords  — words/fragments that signal this domain
  //   weight    — base importance when matched
  //   categories — L1 categories specific to this domain
  //   results   — L2 result generators per category label
  //   suggestions — L3 conceptual-adjacency seeds
  // ═══════════════════════════════════════════════════════════════

  const DOMAINS = {

    food: {
      keywords: [
        "food", "cook", "bake", "recipe", "pie", "cake", "bread",
        "meal", "dish", "ingredient", "cuisine", "restaurant", "chef",
        "dessert", "soup", "salad", "grill", "fry", "roast", "sauce",
        "pasta", "pizza", "sushi", "taco", "burger", "steak", "vegan",
        "vegetarian", "gluten", "spice", "flavor", "nutrition", "diet",
        "kitchen", "oven", "appetizer", "snack", "breakfast", "lunch",
        "dinner", "chocolate", "fruit", "vegetable", "seafood", "wine",
        "coffee", "tea", "cocktail", "smoothie", "ice cream", "candy",
        "apple", "banana", "mango", "chicken", "beef", "pork", "fish",
      ],
      weight: 1.0,
      categories: [
        { label: "Recipes",       icon: "📝", strategy: "Structural" },
        { label: "Cooking Videos", icon: "🎬", strategy: "Similarity" },
        { label: "Ingredients",   icon: "🥘", strategy: "Causal" },
        { label: "Restaurants",   icon: "🍽️", strategy: "Convergent" },
        { label: "Nutrition Info", icon: "🥗", strategy: "Causal" },
        { label: "Food Science",  icon: "🔬", strategy: "Exploratory" },
        { label: "Shopping",      icon: "🛒", strategy: "Convergent" },
      ],
      results: {
        "Recipes":        q => [`Classic ${q}`, `Quick 30-Min ${q}`, `Vegan ${q}`, `Regional Variations`, `Professional Chef ${q}`, `Family-Style ${q}`],
        "Cooking Videos":  q => ["Step-by-Step Tutorial", "Quick Tips", "Chef Masterclass", "Home Cook Version", "Behind the Scenes", "Competition Entry"],
        "Ingredients":    q => ["Core Ingredients", "Substitutions Guide", "Seasonal Picks", "Organic Sources", "Bulk Buying Guide"],
        "Restaurants":    q => ["Top-Rated Near You", "Fine Dining", "Street Food Spots", "Hidden Gems", "Delivery Options"],
        "Nutrition Info":  q => ["Calorie Breakdown", "Allergen Info", "Macro Ratios", "Health Benefits", "Dietary Comparisons"],
        "Food Science":   q => ["Chemistry of Flavor", "Texture Analysis", "Fermentation Science", "Historical Origins", "Molecular Gastronomy"],
        "Shopping":       q => ["Specialty Ingredients", "Kitchen Tools", "Recipe Books", "Gift Sets", "Local Markets"],
      },
      suggestions: [
        "Food Photography", "Seasonal Cooking", "Meal Prep Strategies",
        "Culinary History", "Fermentation", "Farm-to-Table",
        "Comfort Food Culture", "Food Preservation", "Plating Techniques",
        "Regional Cuisine Origins", "Food Science Experiments",
      ],
    },

    programming: {
      keywords: [
        "programming", "code", "coding", "developer", "software",
        "language", "compiler", "library", "framework", "api",
        "algorithm", "function", "class", "module", "package",
        "debug", "test", "deploy", "git", "version", "open source",
        "rust", "python", "javascript", "typescript", "java",
        "go", "golang", "c++", "cpp", "swift", "kotlin", "ruby",
        "php", "sql", "html", "css", "react", "vue", "angular",
        "node", "deno", "wasm", "webassembly", "backend", "frontend",
        "fullstack", "devops", "ci/cd", "docker", "kubernetes",
        "microservice", "serverless", "database", "orm", "graphql",
        "rest", "grpc", "async", "concurrent", "parallel",
      ],
      weight: 1.0,
      categories: [
        { label: "Documentation", icon: "📖", strategy: "Structural" },
        { label: "Libraries",     icon: "📦", strategy: "Causal" },
        { label: "Source Code",   icon: "💻", strategy: "Structural" },
        { label: "Tutorials",     icon: "🎓", strategy: "Similarity" },
        { label: "Discussions",   icon: "💬", strategy: "Exploratory" },
        { label: "Dev Tools",     icon: "🔧", strategy: "Convergent" },
        { label: "Benchmarks",    icon: "📊", strategy: "Causal" },
      ],
      results: {
        "Documentation": q => ["Official Reference", "API Docs", "Getting Started Guide", "Migration Guide", "Changelog", "RFC Docs"],
        "Libraries":     q => ["Most Downloaded", "Recently Updated", "Security Audited", "WASM-Compatible", "Lightweight Alternatives"],
        "Source Code":   q => ["Open Source Projects", "Examples & Snippets", "Templates", "Reference Implementations", "Test Suites"],
        "Tutorials":     q => ["Beginner Guide", "Advanced Techniques", "Interactive Labs", "Video Course", "Project Walkthrough"],
        "Discussions":   q => ["Hot Debates", "Help Requests", "Show & Tell", "RFC Discussions", "Weekly Thread"],
        "Dev Tools":     q => ["IDE Plugins", "CLI Tools", "Linters & Formatters", "Build Systems", "Profilers"],
        "Benchmarks":    q => ["Performance Comparisons", "Memory Profiling", "Latency Tests", "Throughput Analysis", "Real-World Benchmarks"],
      },
      suggestions: [
        "Systems Programming Paradigms", "Memory Safety Research",
        "Formal Verification", "Async Runtime Design",
        "Zero-Copy Parsing", "Compiler Optimizations",
        "Developer Experience", "Language Interop",
        "Build System Evolution", "Type System Theory",
      ],
    },

    crypto: {
      keywords: [
        "blockchain", "crypto", "cryptocurrency", "bitcoin", "ethereum",
        "token", "nft", "defi", "dao", "consensus", "validator",
        "mining", "staking", "wallet", "smart contract", "solidity",
        "web3", "dapp", "protocol", "layer 2", "rollup", "bridge",
        "chain", "ledger", "hash", "merkle", "block", "transaction",
        "decentralized", "sovereign", "governance", "treasury",
        "proof of stake", "proof of work", "finality", "shard",
        "mempool", "gas", "fee", "utxo", "account",
      ],
      weight: 1.0,
      categories: [
        { label: "Protocols",      icon: "🔗", strategy: "Structural" },
        { label: "Whitepapers",    icon: "📄", strategy: "Causal" },
        { label: "Smart Contracts", icon: "📜", strategy: "Structural" },
        { label: "Governance",     icon: "🏛️", strategy: "Exploratory" },
        { label: "Live Network",   icon: "📡", strategy: "Temporal" },
        { label: "Tokens",         icon: "🪙", strategy: "Convergent" },
        { label: "Validators",     icon: "🛡️", strategy: "Temporal" },
      ],
      results: {
        "Protocols":       q => ["Consensus Mechanisms", "Network Architecture", "Peer Discovery", "Data Availability", "Finality Rules", "Fork Handling"],
        "Whitepapers":     q => ["Original Paper", "BFT Variants", "Economic Analysis", "Formal Proofs", "Comparison Studies"],
        "Smart Contracts": q => ["Audited Contracts", "Templates", "Gas Optimizations", "Security Patterns", "Upgrade Proxies"],
        "Governance":      q => ["Active Proposals", "Voting History", "Treasury Stats", "Delegation Dashboard", "Constitution"],
        "Live Network":    q => ["Node Map", "Peer Stats", "Block Explorer", "Mempool View", "Consensus Rounds"],
        "Tokens":          q => ["Utility Tokens", "Governance Tokens", "NFT Collections", "Staking Pools", "Token Metrics"],
        "Validators":      q => ["Active Validators", "Uptime Leaderboard", "Rewards Calculator", "Slashing History", "Hardware Requirements"],
      },
      suggestions: [
        "Game Theory in Distributed Systems", "MEV Resistance",
        "Cross-Chain Bridges", "Layer 2 Rollup Design",
        "Quantum Resistance", "Economic Finality",
        "Data Availability Sampling", "Sybil Resistance Patterns",
        "Social Consensus Mechanisms", "State Rent Economics",
      ],
    },

    science: {
      keywords: [
        "science", "research", "study", "experiment", "physics",
        "chemistry", "biology", "math", "mathematics", "equation",
        "theory", "hypothesis", "quantum", "atom", "molecule",
        "genome", "cell", "evolution", "climate", "energy",
        "particle", "wave", "relativity", "gravity", "cosmos",
        "astronomy", "space", "planet", "star", "galaxy",
        "telescope", "microscope", "lab", "peer review", "journal",
        "nature", "genetic", "dna", "rna", "protein",
        "thermodynamic", "electromagnetic", "nuclear", "entropy",
      ],
      weight: 1.0,
      categories: [
        { label: "Papers",        icon: "📄", strategy: "Causal" },
        { label: "Datasets",      icon: "📊", strategy: "Structural" },
        { label: "Lectures",      icon: "🎓", strategy: "Similarity" },
        { label: "Simulations",   icon: "🧪", strategy: "Exploratory" },
        { label: "Researchers",   icon: "👤", strategy: "Convergent" },
        { label: "Visualizations", icon: "📈", strategy: "Similarity" },
        { label: "Lab Equipment",  icon: "🔬", strategy: "Structural" },
      ],
      results: {
        "Papers":         q => ["Seminal Papers", "Recent Submissions", "Survey Papers", "Meta-Analyses", "Preprints"],
        "Datasets":       q => ["Benchmark Sets", "Open Data", "Synthetic Data", "Longitudinal Studies", "Annotated Collections"],
        "Lectures":       q => ["University Series", "Conference Talks", "Nobel Speeches", "Crash Course", "Graduate Seminars"],
        "Simulations":    q => ["Interactive Models", "Monte Carlo Sims", "Real-Time Visualizations", "Parameter Explorers", "Historical Replications"],
        "Researchers":    q => ["Leading Authors", "Lab Groups", "Collaboration Networks", "Citation Graphs", "Emerging Voices"],
        "Visualizations": q => ["Infographics", "3D Models", "Time-Lapse Data", "Interactive Charts", "Animated Explainers"],
        "Lab Equipment":  q => ["Instruments Guide", "Supplier Comparison", "Calibration Protocols", "DIY Lab Setups", "Safety Guides"],
      },
      suggestions: [
        "Interdisciplinary Connections", "Replication Crisis",
        "Emerging Methodologies", "Historical Experiments",
        "Science Communication", "Citizen Science Projects",
        "Ethical Implications", "Funding Landscapes",
        "Open Access Movement", "Paradigm Shifts",
      ],
    },

    ai: {
      keywords: [
        "ai", "artificial intelligence", "machine learning", "ml",
        "deep learning", "neural network", "neural", "transformer",
        "gpt", "llm", "bert", "model", "training", "inference",
        "dataset", "epoch", "gradient", "backprop", "loss function",
        "attention", "embedding", "tokenizer", "fine-tune", "rlhf",
        "diffusion", "gan", "autoencoder", "reinforcement learning",
        "nlp", "computer vision", "speech recognition", "robotics",
        "autonomous", "classification", "regression", "clustering",
        "feature", "parameter", "weight", "bias", "activation",
      ],
      weight: 1.0,
      categories: [
        { label: "Models",       icon: "🧠", strategy: "Structural" },
        { label: "Papers",       icon: "📄", strategy: "Causal" },
        { label: "Datasets",     icon: "📊", strategy: "Causal" },
        { label: "Tutorials",    icon: "🎓", strategy: "Similarity" },
        { label: "Playgrounds",  icon: "🎮", strategy: "Exploratory" },
        { label: "Hardware",     icon: "🔧", strategy: "Convergent" },
        { label: "Ethics",       icon: "⚖️", strategy: "Exploratory" },
      ],
      results: {
        "Models":      q => ["Pre-Trained Weights", "Fine-Tuned Variants", "ONNX Exports", "Quantized Models", "Distilled Models"],
        "Papers":      q => ["Seminal Papers", "Recent Arxiv", "Survey Papers", "Benchmark Studies", "Architecture Papers"],
        "Datasets":    q => ["Benchmark Sets", "Domain-Specific", "Synthetic Data", "Labeled Collections", "Streaming Datasets"],
        "Tutorials":   q => ["Beginner Guide", "Advanced Techniques", "Interactive Labs", "Video Course", "Certification Path"],
        "Playgrounds": q => ["Browser Demo", "Colab Notebook", "API Sandbox", "Visualization Tool", "Comparison Playground"],
        "Hardware":    q => ["GPU Benchmarks", "TPU Access", "Edge Devices", "FPGA Accelerators", "Cloud Pricing"],
        "Ethics":      q => ["Bias Audits", "Safety Research", "Regulation Tracker", "Impact Assessments", "Alignment Research"],
      },
      suggestions: [
        "Neuromorphic Computing", "Sparse Attention",
        "Knowledge Distillation", "Self-Supervised Learning",
        "Neural Architecture Search", "Federated Learning",
        "Mixture of Experts", "Continual Learning",
        "Mechanistic Interpretability", "AI Governance Frameworks",
      ],
    },

    identity: {
      keywords: [
        "identity", "did", "credential", "authentication", "auth",
        "sso", "oauth", "password", "biometric", "fingerprint",
        "face recognition", "kyc", "verifiable", "self-sovereign",
        "privacy", "anonymity", "pseudonym", "passport", "license",
        "certificate", "trust", "reputation", "attestation",
        "zero knowledge", "zk", "selective disclosure",
        "decentralized id", "w3c", "openid",
      ],
      weight: 1.0,
      categories: [
        { label: "Standards",  icon: "📋", strategy: "Structural" },
        { label: "DIDs",       icon: "🔑", strategy: "Causal" },
        { label: "Wallets",    icon: "👛", strategy: "Convergent" },
        { label: "Privacy",    icon: "🔒", strategy: "Exploratory" },
        { label: "Compliance", icon: "📜", strategy: "Structural" },
        { label: "SDKs",       icon: "🔧", strategy: "Causal" },
      ],
      results: {
        "Standards":  q => ["W3C DIDs", "Verifiable Credentials", "DIDComm", "KERI Protocol", "OpenID Connect"],
        "DIDs":       q => ["did:web", "did:key", "did:ion", "did:sovereign", "DID Resolution"],
        "Wallets":    q => ["Browser Wallets", "Hardware Wallets", "Mobile Wallets", "Multi-Sig Wallets", "Social Recovery"],
        "Privacy":    q => ["ZK Credentials", "Selective Disclosure", "Anonymous Credentials", "Data Minimization", "Consent Frameworks"],
        "Compliance": q => ["GDPR Mapping", "eIDAS Alignment", "KYC Flows", "Audit Trails", "Cross-Border Rules"],
        "SDKs":       q => ["JavaScript SDK", "Rust SDK", "Mobile SDK", "CLI Tools", "Integration Guides"],
      },
      suggestions: [
        "Zero-Knowledge Credentials", "Soulbound Tokens",
        "Decentralized Reputation", "Privacy-Preserving Auth",
        "Cross-Chain Identity", "Human-Readable Names",
        "Biometric Binding", "Identity Recovery",
        "Selective Disclosure", "Decentralized PKI",
      ],
    },

    art: {
      keywords: [
        "art", "music", "design", "creative", "photography", "film",
        "painting", "sculpture", "drawing", "illustration", "animation",
        "graphic", "typography", "color", "composition", "gallery",
        "museum", "exhibition", "artist", "musician", "song", "album",
        "genre", "instrument", "studio", "portfolio", "aesthetic",
        "architecture", "fashion", "textile", "craft", "poetry",
        "literature", "novel", "fiction", "theater", "dance",
      ],
      weight: 1.0,
      categories: [
        { label: "Galleries",    icon: "🖼️", strategy: "Similarity" },
        { label: "Creations",    icon: "🎨", strategy: "Structural" },
        { label: "Artists",      icon: "👤", strategy: "Convergent" },
        { label: "Tutorials",    icon: "🎓", strategy: "Similarity" },
        { label: "Marketplaces", icon: "🏪", strategy: "Convergent" },
        { label: "Movements",    icon: "📚", strategy: "Causal" },
      ],
      results: {
        "Galleries":    q => ["Featured Works", "Community Picks", "New Submissions", "Curated Collections", "Historical Archive"],
        "Creations":    q => ["Digital Art", "Physical Works", "Mixed Media", "Generative", "Collaborative Pieces"],
        "Artists":      q => ["Trending Creators", "Established Masters", "Emerging Voices", "Local Artists", "Collaboration Groups"],
        "Tutorials":    q => ["Technique Guides", "Software Walkthroughs", "Color Theory", "Composition Rules", "Style Studies"],
        "Marketplaces": q => ["Prints & Originals", "Digital Downloads", "Commissions", "NFT Listings", "Auction Houses"],
        "Movements":    q => ["Historical Movements", "Contemporary Trends", "Manifestos", "Critical Essays", "Cultural Context"],
      },
      suggestions: [
        "Cross-Media Expression", "Generative Art Algorithms",
        "Art Conservation Science", "Synesthesia Research",
        "Cultural Appropriation Debates", "Patronage Economics",
        "AI-Assisted Creation", "Found Objects Movement",
        "Performance Art History", "Outsider Art",
      ],
    },

    health: {
      keywords: [
        "health", "medical", "doctor", "therapy", "wellness",
        "exercise", "fitness", "workout", "yoga", "meditation",
        "mental health", "anxiety", "depression", "sleep",
        "disease", "symptom", "diagnosis", "treatment", "drug",
        "medicine", "pharmaceutical", "vaccine", "surgery",
        "physical therapy", "rehabilitation", "chronic",
        "immune", "allergy", "vitamin", "supplement",
        "heart", "brain", "lung", "kidney", "cancer",
      ],
      weight: 1.0,
      categories: [
        { label: "Research",    icon: "🔬", strategy: "Causal" },
        { label: "Guides",      icon: "📋", strategy: "Structural" },
        { label: "Providers",   icon: "🏥", strategy: "Convergent" },
        { label: "Discussions", icon: "💬", strategy: "Exploratory" },
        { label: "Data",        icon: "📊", strategy: "Structural" },
        { label: "Wellness",    icon: "🧘", strategy: "Similarity" },
      ],
      results: {
        "Research":     q => ["Clinical Trials", "Systematic Reviews", "Case Studies", "Drug Interactions", "Emerging Treatments"],
        "Guides":       q => ["Patient Guide", "Prevention Tips", "Recovery Plans", "Family Support", "Lifestyle Adjustments"],
        "Providers":    q => ["Specialists Near You", "Telemedicine", "Rating Comparisons", "Wait Times", "Insurance Coverage"],
        "Discussions":  q => ["Patient Stories", "Doctor Q&As", "Support Groups", "Treatment Debates", "Recovery Journeys"],
        "Data":         q => ["Population Statistics", "Outcome Databases", "Risk Calculators", "Longitudinal Studies", "Demographic Breakdown"],
        "Wellness":     q => ["Exercise Programs", "Mindfulness Practices", "Nutrition Plans", "Sleep Optimization", "Stress Management"],
      },
      suggestions: [
        "Preventive Medicine Trends", "Gut Microbiome Research",
        "Chronobiology", "Epigenetics in Disease",
        "Digital Health Platforms", "Psychedelic Therapy Research",
        "Wearable Health Tech", "Global Health Equity",
        "Longevity Science", "Functional Medicine",
      ],
    },

    business: {
      keywords: [
        "business", "market", "startup", "company", "enterprise",
        "revenue", "profit", "investment", "stock", "fund",
        "entrepreneur", "ceo", "management", "strategy", "growth",
        "marketing", "branding", "advertising", "sales", "customer",
        "supply chain", "logistics", "manufacturing", "retail",
        "ecommerce", "fintech", "saas", "b2b", "b2c",
        "venture capital", "ipo", "merger", "acquisition",
        "pricing", "product", "roadmap", "pitch",
      ],
      weight: 1.0,
      categories: [
        { label: "Analysis",     icon: "📊", strategy: "Causal" },
        { label: "Companies",    icon: "🏢", strategy: "Structural" },
        { label: "News",         icon: "📰", strategy: "Temporal" },
        { label: "Tools",        icon: "🔧", strategy: "Convergent" },
        { label: "Case Studies", icon: "📋", strategy: "Causal" },
        { label: "Funding",      icon: "💰", strategy: "Convergent" },
      ],
      results: {
        "Analysis":      q => ["Market Overview", "Competitive Landscape", "Trend Report", "SWOT Analysis", "Financial Deep-Dive"],
        "Companies":     q => ["Market Leaders", "Emerging Players", "Comparison Matrix", "Org Structures", "Hiring Trends"],
        "News":          q => ["Breaking News", "Weekly Roundup", "Expert Commentary", "Earnings Reports", "Regulatory Updates"],
        "Tools":         q => ["SaaS Platforms", "Analytics Dashboards", "Automation Tools", "CRM Systems", "Financial Models"],
        "Case Studies":  q => ["Success Stories", "Failure Analyses", "Pivot Strategies", "Scaling Playbooks", "International Expansion"],
        "Funding":       q => ["Recent Rounds", "Investor Profiles", "Pitch Deck Examples", "Valuation Methods", "Grant Programs"],
      },
      suggestions: [
        "Blue Ocean Strategy", "Platform Economics",
        "Remote Work Dynamics", "Behavioral Economics",
        "Circular Economy Models", "Creator Economy Trends",
        "Market Timing Research", "Organizational Psychology",
        "Innovation Diffusion", "Regulatory Arbitrage",
      ],
    },

    education: {
      keywords: [
        "learn", "teach", "education", "school", "university",
        "college", "course", "curriculum", "degree", "student",
        "classroom", "lecture", "homework", "exam", "grade",
        "pedagogy", "tutoring", "scholarship", "certificate",
        "online learning", "mooc", "bootcamp", "textbook",
      ],
      weight: 0.8,
      categories: [
        { label: "Courses",     icon: "🎓", strategy: "Structural" },
        { label: "Instructors", icon: "👤", strategy: "Convergent" },
        { label: "Resources",   icon: "📚", strategy: "Causal" },
        { label: "Communities", icon: "💬", strategy: "Exploratory" },
        { label: "Paths",       icon: "🗺️", strategy: "Similarity" },
      ],
      results: {
        "Courses":     q => ["Free Courses", "Paid Certifications", "University MOOCs", "Interactive Labs", "Self-Paced Programs"],
        "Instructors": q => ["Top-Rated Teachers", "Industry Experts", "University Professors", "Peer Tutors", "Mentorship Programs"],
        "Resources":   q => ["Textbooks", "Cheat Sheets", "Reference Cards", "Practice Problems", "Flashcard Decks"],
        "Communities": q => ["Study Groups", "Discord Servers", "Forum Threads", "Local Meetups", "Conference Events"],
        "Paths":       q => ["Beginner Track", "Intermediate Track", "Expert Track", "Career Transition", "Research Path"],
      },
      suggestions: [
        "Spaced Repetition Research", "Active Recall Methods",
        "Bloom's Taxonomy Applications", "Flipped Classroom Model",
        "Competency-Based Education", "Adaptive Learning Systems",
        "Peer Instruction Methods", "Learning Analytics",
      ],
    },

    gaming: {
      keywords: [
        "game", "gaming", "esport", "video game", "console",
        "playstation", "xbox", "nintendo", "steam", "pc gaming",
        "rpg", "fps", "mmo", "moba", "indie game", "strategy",
        "speedrun", "twitch", "streamer", "game dev", "unity",
        "unreal engine", "pixel art", "3d model", "level design",
      ],
      weight: 1.0,
      categories: [
        { label: "Games",      icon: "🎮", strategy: "Structural" },
        { label: "Streams",    icon: "📡", strategy: "Temporal" },
        { label: "Guides",     icon: "📖", strategy: "Causal" },
        { label: "Communities", icon: "💬", strategy: "Exploratory" },
        { label: "Dev Tools",  icon: "🔧", strategy: "Convergent" },
        { label: "Reviews",    icon: "⭐", strategy: "Similarity" },
      ],
      results: {
        "Games":       q => ["Trending Now", "Upcoming Releases", "All-Time Classics", "Indie Gems", "Free-to-Play"],
        "Streams":     q => ["Live Now", "Top Clips", "Tournaments", "Speedruns", "Developer Streams"],
        "Guides":      q => ["Beginner Walkthrough", "Pro Tips", "Build Guides", "Achievement Hunting", "Hidden Secrets"],
        "Communities": q => ["Subreddits", "Discord Servers", "Clan Finders", "Fan Art", "Modding Forums"],
        "Dev Tools":   q => ["Game Engines", "Asset Packs", "Sound Libraries", "Testing Frameworks", "Publishing Guides"],
        "Reviews":     q => ["Critic Reviews", "User Scores", "Video Reviews", "Comparison Roundups", "Retrospectives"],
      },
      suggestions: [
        "Game Design Theory", "Procedural Generation",
        "Accessibility in Gaming", "Speedrunning Culture",
        "Game Preservation", "Narrative Design Patterns",
        "Monetization Ethics", "Cross-Platform Play",
        "VR/AR Evolution", "Esports Economics",
      ],
    },
  };

  // ═══════════════════════════════════════════════════════════════
  // UNIVERSAL CATEGORIES — content-type categories available for
  // ANY query, but weighted lower than domain-specific ones
  // ═══════════════════════════════════════════════════════════════

  const UNIVERSAL_CATEGORIES = [
    { label: "Images",      icon: "🖼️", strategy: "Similarity",   weight: 0.7 },
    { label: "Videos",      icon: "🎬", strategy: "Similarity",   weight: 0.8 },
    { label: "Articles",    icon: "📄", strategy: "Causal",       weight: 0.75 },
    { label: "Discussions", icon: "💬", strategy: "Exploratory",  weight: 0.5 },
    { label: "Livestreams", icon: "📡", strategy: "Temporal",     weight: 0.3 },
  ];

  const UNIVERSAL_RESULTS = {
    "Images":      q => [`${q} Photos`, "Infographics", "Diagrams", "User Uploads", "Stock Images", "Illustrations"],
    "Videos":      q => ["Explainer Videos", "Documentaries", "Interviews", "Quick Tutorials", "Deep Dives", "Community Content"],
    "Articles":    q => ["In-Depth Analysis", "Quick Overview", "Opinion Pieces", "Historical Context", "Case Studies", "Comparisons"],
    "Discussions": q => ["Hot Debates", "Help Requests", "Show & Tell", "Weekly Threads", "Expert AMAs"],
    "Livestreams": q => ["Live Now", "Scheduled Events", "Past Recordings", "Conference Streams", "Community Calls"],
  };

  const UNIVERSAL_SUGGESTIONS = [
    "Related Concepts", "Emerging Perspectives",
    "Cross-Domain Connections", "Historical Roots",
    "Future Directions", "Contrarian Takes",
    "Practical Applications", "Hidden Connections",
    "Community Innovations", "Adjacent Fields",
  ];


  // ═══════════════════════════════════════════════════════════════
  // DOMAIN CLASSIFIER
  // ═══════════════════════════════════════════════════════════════

  /**
   * Analyze a query and return scored domains.
   * Returns: [{ name, score, domain }] sorted by score desc.
   */
  function classifyQuery(query) {
    const q = query.toLowerCase();
    const tokens = q.split(/\s+/);
    const scores = [];

    for (const [name, domain] of Object.entries(DOMAINS)) {
      let score = 0;

      for (const kw of domain.keywords) {
        // Substring match — handles "apple pies" matching "apple" and "pie"
        if (q.includes(kw)) {
          // Exact word-boundary match scores higher
          const re = new RegExp("\\b" + kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + "\\b", "i");
          score += re.test(q) ? 2.0 : 0.8;
        }
        // Also check if any query token is a prefix of the keyword
        for (const tok of tokens) {
          if (tok.length >= 3 && kw.startsWith(tok) && !q.includes(kw)) {
            score += 0.4;
          }
        }
      }

      score *= domain.weight;

      if (score > 0) {
        scores.push({ name, score, domain });
      }
    }

    scores.sort((a, b) => b.score - a.score);
    return scores;
  }


  // ═══════════════════════════════════════════════════════════════
  // CATEGORY ASSEMBLY — builds L1 from classified domains
  // ═══════════════════════════════════════════════════════════════

  /**
   * Assemble categories from domain scores.
   * Primary domain contributes more categories, secondary domains fewer.
   * Universal content-type categories fill remaining slots.
   */
  function assembleCategories(domainScores, rng) {
    const categories = [];
    const usedLabels = new Set();
    const targetCount = 5 + Math.floor(rng() * 3); // 5-7 categories

    // From each matched domain, take categories proportional to score
    if (domainScores.length > 0) {
      const totalScore = domainScores.reduce((s, d) => s + d.score, 0);

      for (const { domain, score } of domainScores) {
        const share = score / totalScore;
        // Primary domain gets 3-5 categories, secondary gets 1-2
        const count = Math.max(1, Math.round(share * targetCount));
        const picked = pickN(domain.categories, count, rng);

        for (const cat of picked) {
          if (!usedLabels.has(cat.label)) {
            usedLabels.add(cat.label);
            categories.push({ ...cat, domainSource: domain });
          }
        }
      }
    }

    // Fill remaining slots with universal categories (skip duplicates)
    const universalPool = UNIVERSAL_CATEGORIES
      .filter(c => !usedLabels.has(c.label))
      .sort(() => rng() - 0.5);

    for (const uc of universalPool) {
      if (categories.length >= targetCount) break;
      // Only add if random passes the weight threshold (low-relevance universals get dropped)
      if (rng() < uc.weight) {
        categories.push({ label: uc.label, icon: uc.icon, strategy: uc.strategy, domainSource: null });
        usedLabels.add(uc.label);
      }
    }

    // If no domains matched at all, use universals + generic
    if (categories.length < 3) {
      for (const uc of UNIVERSAL_CATEGORIES) {
        if (!usedLabels.has(uc.label)) {
          categories.push({ label: uc.label, icon: uc.icon, strategy: uc.strategy, domainSource: null });
          usedLabels.add(uc.label);
        }
        if (categories.length >= targetCount) break;
      }
    }

    return categories.slice(0, targetCount);
  }


  // ═══════════════════════════════════════════════════════════════
  // RESULT GENERATION — contextual L2 results
  // ═══════════════════════════════════════════════════════════════

  function getResults(categoryLabel, query, domainSource, rng) {
    // First try domain-specific results
    if (domainSource && domainSource.results[categoryLabel]) {
      return pickN(domainSource.results[categoryLabel](query), 3 + Math.floor(rng() * 3), rng);
    }
    // Then try universal results
    if (UNIVERSAL_RESULTS[categoryLabel]) {
      return pickN(UNIVERSAL_RESULTS[categoryLabel](query), 3 + Math.floor(rng() * 3), rng);
    }
    // Fallback: generate generic results
    return pickN([
      `Top ${categoryLabel} Results`, `Recent ${categoryLabel}`, `Trending in ${categoryLabel}`,
      `Community ${categoryLabel}`, `Expert ${categoryLabel}`, `Deep ${categoryLabel} Analysis`,
    ], 3 + Math.floor(rng() * 2), rng);
  }


  // ═══════════════════════════════════════════════════════════════
  // SUGGESTION GENERATION — L3 neural mesh conceptual adjacency
  // ═══════════════════════════════════════════════════════════════

  function getSuggestions(query, domainScores, rng) {
    const pool = [];
    // Gather suggestions from all matched domains
    for (const { domain } of domainScores) {
      pool.push(...domain.suggestions);
    }
    // Add universals
    pool.push(...UNIVERSAL_SUGGESTIONS);
    // Deduplicate
    return [...new Set(pool)];
  }


  // ═══════════════════════════════════════════════════════════════
  // UTILITIES
  // ═══════════════════════════════════════════════════════════════

  function hashStr(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++) {
      h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    }
    return Math.abs(h);
  }

  function seededRandom(seed) {
    let s = seed | 0 || 1;
    return () => {
      s ^= s << 13; s ^= s >> 17; s ^= s << 5;
      return (s >>> 0) / 4294967296;
    };
  }

  function fakeTagId(seed) {
    const rng = seededRandom(seed);
    return "tag:" + Array.from({ length: 16 }, () =>
      Math.floor(rng() * 16).toString(16)).join("");
  }

  function pickN(arr, n, rng) {
    const shuffled = [...arr].sort(() => rng() - 0.5);
    return shuffled.slice(0, Math.min(n, arr.length));
  }


  // ═══════════════════════════════════════════════════════════════
  // MOCK GENERATOR (client-side fallback)
  // ═══════════════════════════════════════════════════════════════

  function generateMock(query) {
    const q = query.toLowerCase().trim();
    const rng = seededRandom(hashStr(q));
    const nodes = [];
    const links = [];
    let idCounter = 0;

    // ── Step 1: Classify the query ──
    const domainScores = classifyQuery(q);

    // ── Step 2: Assemble categories from domains ──
    const categories = assembleCategories(domainScores, rng);

    // ── Step 3: Build suggestion pool from matched domains ──
    const suggestionPool = getSuggestions(q, domainScores, rng);

    // ── Query node (center) ──
    const domainNames = domainScores.slice(0, 3).map(d => d.name).join(", ") || "general";
    const queryNode = {
      id: `n${idCounter++}`,
      label: query,
      level: 0,
      relevance: 1.0,
      strategy: "query",
      icon: "🔍",
      tags: [fakeTagId(hashStr(q))],
      preview: `Semantic channeling for "${query}" — detected domains: ${domainNames}`,
      parentId: null,
      expanded: true,
      children: [],
    };
    nodes.push(queryNode);

    // ── L1: Category nodes ──
    categories.forEach((cat, i) => {
      const catId = `n${idCounter++}`;
      const relevance = 0.98 - i * 0.03 + (rng() * 0.02 - 0.01);

      const catNode = {
        id: catId,
        label: cat.label,
        level: 1,
        relevance: Math.max(0.6, Math.min(1.0, relevance)),
        strategy: cat.strategy,
        icon: cat.icon,
        tags: [fakeTagId(hashStr(q + cat.label)), fakeTagId(hashStr(cat.label + i))],
        preview: `${cat.label} results for "${query}" via ${cat.strategy} channel`,
        parentId: queryNode.id,
        expanded: false,
        children: [],
      };
      nodes.push(catNode);
      links.push({ source: queryNode.id, target: catId, level: 1 });
      queryNode.children.push(catId);

      // ── L2: Contextual results ──
      const results = getResults(cat.label, query, cat.domainSource, rng);

      results.forEach((res, j) => {
        const resId = `n${idCounter++}`;
        const resRelevance = catNode.relevance * (0.95 - j * 0.05 + rng() * 0.03);

        const resNode = {
          id: resId,
          label: res,
          level: 2,
          relevance: Math.max(0.4, Math.min(1.0, resRelevance)),
          strategy: cat.strategy,
          icon: "",
          tags: [fakeTagId(hashStr(q + res)), fakeTagId(hashStr(res + j))],
          preview: `${res} — #${j + 1} in ${cat.label} for "${query}"`,
          parentId: catId,
          expanded: false,
          children: [],
        };
        nodes.push(resNode);
        links.push({ source: catId, target: resId, level: 2 });
        catNode.children.push(resId);

        // ── L3: Neural mesh suggestions ──
        const numSugs = 1 + Math.floor(rng() * 2);
        const sugs = pickN(suggestionPool, numSugs, rng);

        sugs.forEach((sug, k) => {
          const sugId = `n${idCounter++}`;
          const sugRelevance = resNode.relevance * (0.8 - k * 0.1 + rng() * 0.05);

          const sugNode = {
            id: sugId,
            label: sug,
            level: 3,
            relevance: Math.max(0.2, Math.min(1.0, sugRelevance)),
            strategy: "Exploratory",
            icon: "💡",
            tags: [fakeTagId(hashStr(sug + q))],
            preview: `Neural mesh suggestion: "${sug}" — discovered via exploratory channeling from ${res}`,
            parentId: resId,
            expanded: false,
            children: [],
          };
          nodes.push(sugNode);
          links.push({ source: resId, target: sugId, level: 3 });
          resNode.children.push(sugId);
        });
      });
    });

    // ── Cross-links between L1 categories ──
    const catNodes = nodes.filter(n => n.level === 1);
    for (let i = 0; i < catNodes.length; i++) {
      for (let j = i + 2; j < catNodes.length; j++) {
        if (rng() > 0.6) {
          links.push({ source: catNodes[i].id, target: catNodes[j].id, level: 1, cross: true });
        }
      }
    }

    return {
      query,
      timestamp: new Date().toISOString(),
      detectedDomains: domainScores.slice(0, 3).map(d => ({ name: d.name, score: d.score.toFixed(1) })),
      totalNodes: nodes.length,
      totalLinks: links.length,
      nodes,
      links,
    };
  }

  // Public API
  return {
    // Core search
    generate,
    generateMock,
    unified,
    classifyQuery,

    // Plugin API
    plugins,

    // Data source management
    sources,

    // Mode / health
    resetLiveCheck,
    getMode,
    getHealth: () => _healthData,
  };
})();
