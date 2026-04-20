/* ================================================================
   graph.js — Sovereign Semantic Search Graph Engine  v2
   ================================================================
   Major improvements over v1:
     - Curved links (quadratic bezier paths instead of straight lines)
     - Radial gradient node fills with relevance-proportional sizing
     - Focus mode: hovering a node spotlights its neighborhood
     - Expanded-node pulsing ring indicator
     - Search history bar with clickable chips
     - Keyboard shortcuts (Ctrl+K focus, Escape close panel)
     - Stats bar with live visible-node counts
     - Double-click to expand all children recursively
     - Bug fixes: O(n) cluster lookup → Map, dead code removed
     - Animated dash flow on cross-links
   ================================================================ */

(() => {
  "use strict";

  // ─── Configuration ──────────────────────────────────────────────
  const CFG = {
    // Base radii per level (scaled by relevance)
    baseRadius:  { 0: 26, 1: 18, 2: 12, 3: 9 },
    // How much relevance affects radius (0 = none, 1 = full)
    relevanceScale: 0.35,
    // Radial target distances from center
    radialDist:  { 1: 190, 2: 340, 3: 470 },
    // Force strengths
    chargeStrength: -280,
    linkDistance: { 1: 150, 2: 95, 3: 65 },
    linkStrength: { 1: 0.45, 2: 0.35, 3: 0.25 },
    clusterStrength: 0.12,
    radialStrength:  0.07,
    centerStrength:  0.015,
    // Animation
    revealDuration: 650,
    burstDuration: 900,
    collapseDuration: 350,
    // Colors
    colors: {
      0: "#f0f2f5",
      1: "#ff4466",
      2: "#4c9aff",
      3: "#ff9f43",
    },
    glowColors: {
      0: "rgba(240,242,245,0.20)",
      1: "rgba(255,68,102,0.22)",
      2: "rgba(76,154,255,0.20)",
      3: "rgba(255,159,67,0.18)",
    },
    brightColors: {
      0: "#ffffff",
      1: "#ff6b88",
      2: "#74b4ff",
      3: "#ffb770",
    },
    linkColors: {
      1: "rgba(255,68,102,0.28)",
      2: "rgba(76,154,255,0.20)",
      3: "rgba(255,159,67,0.16)",
    },
    // Focus mode
    focusFadeDuration: 200,
  };

  // ─── State ──────────────────────────────────────────────────────
  let graphData = null;
  let visibleNodes = [];
  let visibleLinks = [];
  let nodeMap = new Map();
  let simNodeMap = new Map();   // id → sim node (fast lookup for cluster force)
  let simulation = null;
  let svg, container, linkGroup, nodeGroup, labelGroup, glowGroup, ringGroup;
  let tooltip;
  let width, height;
  let currentZoom = d3.zoomIdentity;
  let searchHistory = [];
  let activeQuery = null;

  // ─── DOM refs ───────────────────────────────────────────────────
  const searchForm    = document.getElementById("search-form");
  const searchInput   = document.getElementById("search-input");
  const searchMeta    = document.getElementById("search-meta");
  const graphContainer = document.getElementById("graph-container");
  const emptyState    = document.getElementById("empty-state");
  const loadingOverlay = document.getElementById("loading-overlay");
  const detailPanel   = document.getElementById("detail-panel");
  const panelClose    = document.getElementById("panel-close");
  const historyBar    = document.getElementById("history-bar");
  const historyChips  = document.getElementById("history-chips");
  const statsBar      = document.getElementById("stats-bar");

  // ─── Init ───────────────────────────────────────────────────────
  function init() {
    svg = d3.select("#graph-svg");
    measureSize();

    // SVG layers (paint order)
    container  = svg.append("g").attr("class", "graph-root");
    glowGroup  = container.append("g").attr("class", "glow-layer");
    linkGroup  = container.append("g").attr("class", "link-layer");
    ringGroup  = container.append("g").attr("class", "ring-layer");
    nodeGroup  = container.append("g").attr("class", "node-layer");
    labelGroup = container.append("g").attr("class", "label-layer");

    // Tooltip
    tooltip = d3.select("body").append("div").attr("class", "graph-tooltip");

    // Zoom / Pan
    const zoom = d3.zoom()
      .scaleExtent([0.15, 5])
      .on("zoom", (e) => {
        currentZoom = e.transform;
        container.attr("transform", e.transform);
      });
    svg.call(zoom);

    document.getElementById("zoom-in").addEventListener("click", () =>
      svg.transition().duration(300).call(zoom.scaleBy, 1.4));
    document.getElementById("zoom-out").addEventListener("click", () =>
      svg.transition().duration(300).call(zoom.scaleBy, 0.7));
    document.getElementById("zoom-reset").addEventListener("click", () =>
      svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity));

    // Search
    searchForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const q = searchInput.value.trim();
      if (q) runSearch(q);
    });

    // Example chips
    document.querySelectorAll(".example-chip").forEach(chip => {
      chip.addEventListener("click", () => {
        const q = chip.dataset.query;
        searchInput.value = q;
        runSearch(q);
      });
    });

    // Panel close
    panelClose.addEventListener("click", closePanel);

    // Keyboard shortcuts
    document.addEventListener("keydown", (e) => {
      // Ctrl+K / Cmd+K → focus search
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        searchInput.focus();
        searchInput.select();
      }
      // Escape → close panel
      if (e.key === "Escape") {
        closePanel();
        searchInput.blur();
      }
    });

    // Resize
    window.addEventListener("resize", () => {
      measureSize();
      if (simulation) {
        simulation.force("center", d3.forceCenter(width / 2, height / 2));
        simulation.force("radial", makeRadialForce());
      }
    });

    // Source selector
    const sourceSelect = document.getElementById("source-select");
    if (sourceSelect) {
      sourceSelect.addEventListener("change", (e) => {
        SemanticData.sources.setActive(e.target.value);
        // Re-run current query with new source
        if (activeQuery) runSearch(activeQuery);
      });
      // Populate sources on load (async)
      refreshSourceSelector();
    }

    // SVG defs
    buildDefs();
  }

  /** Refresh the source selector dropdown with all available sources */
  async function refreshSourceSelector() {
    const sourceSelect = document.getElementById("source-select");
    if (!sourceSelect) return;
    try {
      const srcs = await SemanticData.sources.list();
      const current = sourceSelect.value;
      sourceSelect.innerHTML = "";
      for (const src of srcs) {
        const opt = document.createElement("option");
        opt.value = src.id;
        if (src.type === "network") {
          opt.textContent = `◈ ${src.name}`;
        } else {
          const tagInfo = src.tags ? ` (${src.tags} tags)` : "";
          opt.textContent = `🔌 ${src.name}${tagInfo}`;
        }
        if (src.id === current) opt.selected = true;
        sourceSelect.appendChild(opt);
      }
    } catch (_) {
      // Keep default option
    }
  }

  function measureSize() {
    const rect = graphContainer.getBoundingClientRect();
    width = rect.width;
    height = rect.height;
  }

  /** Create radial gradient fills + glow filters in SVG defs */
  function buildDefs() {
    const defs = svg.append("defs");

    // Radial gradients for each level
    [0, 1, 2, 3].forEach(level => {
      const grad = defs.append("radialGradient")
        .attr("id", `node-grad-${level}`)
        .attr("cx", "35%").attr("cy", "35%")
        .attr("r", "65%");
      grad.append("stop")
        .attr("offset", "0%")
        .attr("stop-color", CFG.brightColors[level]);
      grad.append("stop")
        .attr("offset", "100%")
        .attr("stop-color", CFG.colors[level]);
    });

    // Glow filters
    [0, 1, 2, 3].forEach(level => {
      const filter = defs.append("filter")
        .attr("id", `glow-${level}`)
        .attr("x", "-50%").attr("y", "-50%")
        .attr("width", "200%").attr("height", "200%");
      filter.append("feGaussianBlur")
        .attr("stdDeviation", level === 0 ? 7 : 5)
        .attr("result", "blur");
      const merge = filter.append("feMerge");
      merge.append("feMergeNode").attr("in", "blur");
      merge.append("feMergeNode").attr("in", "SourceGraphic");
    });

    // Ring pulse filter (softer)
    const ringFilter = defs.append("filter")
      .attr("id", "ring-glow")
      .attr("x", "-100%").attr("y", "-100%")
      .attr("width", "300%").attr("height", "300%");
    ringFilter.append("feGaussianBlur")
      .attr("stdDeviation", 3)
      .attr("result", "blur");
    const ringMerge = ringFilter.append("feMerge");
    ringMerge.append("feMergeNode").attr("in", "blur");
    ringMerge.append("feMergeNode").attr("in", "SourceGraphic");
  }

  /** Compute node radius based on level + relevance */
  function nodeRadius(d) {
    const base = CFG.baseRadius[d.level] || 10;
    const relBoost = 1 + (d.relevance - 0.5) * CFG.relevanceScale;
    return base * Math.max(0.7, Math.min(1.3, relBoost));
  }

  // ─── Mode Indicator ────────────────────────────────────────────
  function updateModeIndicator(mode, sourceName) {
    let badge = document.getElementById("mode-badge");
    if (!badge) {
      badge = document.createElement("div");
      badge.id = "mode-badge";
      badge.style.cssText = `
        position: fixed; top: 12px; right: 16px; z-index: 9999;
        padding: 6px 14px; border-radius: 20px; font-size: 12px;
        font-weight: 600; font-family: 'Inter', sans-serif;
        letter-spacing: 0.5px; text-transform: uppercase;
        backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
        transition: all 0.3s ease;
      `;
      document.body.appendChild(badge);
    }
    if (mode === "live") {
      badge.textContent = "⚡ LIVE — Sovereign Network";
      badge.style.background = "rgba(76, 154, 255, 0.25)";
      badge.style.border = "1px solid rgba(76, 154, 255, 0.5)";
      badge.style.color = "#4c9aff";
    } else if (mode === "plugin") {
      const label = sourceName || "Private Plugin";
      badge.textContent = `🔌 PLUGIN — ${label}`;
      badge.style.background = "rgba(167, 139, 250, 0.2)";
      badge.style.border = "1px solid rgba(167, 139, 250, 0.5)";
      badge.style.color = "#a78bfa";
    } else {
      badge.textContent = "◈ FALLBACK — Local Classifier";
      badge.style.background = "rgba(255, 159, 67, 0.2)";
      badge.style.border = "1px solid rgba(255, 159, 67, 0.4)";
      badge.style.color = "#ff9f43";
    }
  }

  // ─── Search Entry Point ─────────────────────────────────────────
  function runSearch(query) {
    emptyState.classList.add("hidden");
    loadingOverlay.classList.remove("hidden");
    closePanel();

    setTimeout(async () => {
      try {
        graphData = await SemanticData.generate(query);
      } catch (e) {
        console.error("SemanticData.generate failed:", e);
        loadingOverlay.classList.add("hidden");
        return;
      }

      // Show mode indicator
      const mode = graphData._mode || (SemanticData.getMode ? SemanticData.getMode() : "unknown");
      const sourceName = graphData._source || SemanticData.sources.getActive();
      updateModeIndicator(mode, sourceName);

      // Refresh source selector in case plugins changed
      refreshSourceSelector();

      activeQuery = query;
      nodeMap.clear();
      simNodeMap.clear();
      graphData.nodes.forEach(n => nodeMap.set(n.id, n));

      // Initially show query + L1
      const l1Ids = new Set(graphData.nodes.filter(n => n.level <= 1).map(n => n.id));
      visibleNodes = graphData.nodes.filter(n => l1Ids.has(n.id)).map(cloneNodeForSim);
      visibleLinks = graphData.links
        .filter(l => l1Ids.has(srcId(l)) && l1Ids.has(tgtId(l)))
        .map(cloneLink);

      // Position: query at center
      visibleNodes.forEach(n => {
        if (n.level === 0) {
          n.x = width / 2; n.y = height / 2;
          n.fx = width / 2; n.fy = height / 2;
        } else {
          n.x = width / 2 + (Math.random() - 0.5) * 30;
          n.y = height / 2 + (Math.random() - 0.5) * 30;
        }
      });

      rebuildSimNodeMap();
      loadingOverlay.classList.add("hidden");
      buildSimulation();
      render();
      updateStats();
      addToHistory(query);

      // Release center pin after burst
      setTimeout(() => {
        visibleNodes.forEach(n => {
          if (n.level === 0) { n.fx = null; n.fy = null; }
        });
        simulation.alpha(0.3).restart();
      }, CFG.burstDuration);

    }, 350 + Math.random() * 250);
  }

  // ─── Simulation ─────────────────────────────────────────────────
  function buildSimulation() {
    if (simulation) simulation.stop();

    simulation = d3.forceSimulation(visibleNodes)
      .force("link", d3.forceLink(visibleLinks)
        .id(d => d.id)
        .distance(d => CFG.linkDistance[d.level] || 90)
        .strength(d => CFG.linkStrength[d.level] || 0.25))
      .force("charge", d3.forceManyBody()
        .strength(d => CFG.chargeStrength * (d.level === 0 ? 1.5 : 1)))
      .force("center", d3.forceCenter(width / 2, height / 2)
        .strength(CFG.centerStrength))
      .force("radial", makeRadialForce())
      .force("collision", d3.forceCollide(d => nodeRadius(d) + 6))
      .force("cluster", clusterForce(CFG.clusterStrength))
      .alphaDecay(0.018)
      .on("tick", ticked);
  }

  function makeRadialForce() {
    return d3.forceRadial(
      d => CFG.radialDist[d.level] || 0,
      width / 2, height / 2
    ).strength(d => d.level === 0 ? 0 : CFG.radialStrength);
  }

  /** Custom cluster force: pull children toward parent. Uses Map for O(1) lookup. */
  function clusterForce(strength) {
    let nodes;
    function force(alpha) {
      const k = alpha * strength;
      for (const n of nodes) {
        if (n.level === 0 || !n.parentId) continue;
        const parent = simNodeMap.get(n.parentId);
        if (!parent) continue;
        n.vx += (parent.x - n.x) * k;
        n.vy += (parent.y - n.y) * k;
      }
    }
    force.initialize = (_nodes) => { nodes = _nodes; };
    return force;
  }

  function rebuildSimNodeMap() {
    simNodeMap.clear();
    visibleNodes.forEach(n => simNodeMap.set(n.id, n));
  }

  // ─── Render ─────────────────────────────────────────────────────
  function render() {
    renderLinks();
    renderGlows();
    renderRings();
    renderNodes();
    renderLabels();

    // Rebind simulation
    simulation.nodes(visibleNodes);
    simulation.force("link").links(visibleLinks);
    simulation.alpha(0.55).restart();
  }

  /** Curved links as quadratic bezier paths */
  function renderLinks() {
    const sel = linkGroup.selectAll("path")
      .data(visibleLinks, d => linkKey(d));

    sel.exit().transition().duration(CFG.collapseDuration)
      .attr("stroke-opacity", 0).remove();

    sel.enter().append("path")
      .attr("fill", "none")
      .attr("stroke", d => CFG.linkColors[d.level] || "rgba(255,255,255,0.08)")
      .attr("stroke-width", d => d.cross ? 0.6 : (d.level === 1 ? 2 : 1.2))
      .attr("stroke-dasharray", d => d.cross ? "6 6" : null)
      .style("animation", d => d.cross ? "dash-flow 1.5s linear infinite" : null)
      .attr("stroke-opacity", 0)
      .transition().duration(CFG.revealDuration)
      .attr("stroke-opacity", 1);
  }

  function renderGlows() {
    const sel = glowGroup.selectAll("circle.glow")
      .data(visibleNodes, d => d.id);

    sel.exit().transition().duration(CFG.collapseDuration)
      .attr("r", 0).remove();

    sel.enter().append("circle")
      .attr("class", "glow")
      .attr("r", 0)
      .attr("fill", d => CFG.glowColors[d.level])
      .attr("filter", d => `url(#glow-${d.level})`)
      .transition().duration(CFG.revealDuration)
      .attr("r", d => nodeRadius(d) * 2);
  }

  /** Pulsing rings around expanded nodes */
  function renderRings() {
    const expanded = visibleNodes.filter(d => {
      const data = nodeMap.get(d.id);
      return data && data.expanded && data.children.length > 0;
    });

    const sel = ringGroup.selectAll("circle.expand-ring")
      .data(expanded, d => d.id);

    sel.exit().transition().duration(300).attr("opacity", 0).remove();

    sel.enter().append("circle")
      .attr("class", "expand-ring")
      .attr("r", d => nodeRadius(d) + 4)
      .attr("fill", "none")
      .attr("stroke", d => CFG.colors[d.level])
      .attr("stroke-width", 1.5)
      .attr("stroke-opacity", 0.4)
      .attr("filter", "url(#ring-glow)");
  }

  function renderNodes() {
    const sel = nodeGroup.selectAll("circle.node")
      .data(visibleNodes, d => d.id);

    sel.exit().transition().duration(CFG.collapseDuration)
      .attr("r", 0).remove();

    const enter = sel.enter().append("circle")
      .attr("class", "node")
      .attr("r", 0)
      .attr("fill", d => `url(#node-grad-${d.level})`)
      .attr("stroke", d => d.level === 0 ? "rgba(255,255,255,0.2)" : CFG.colors[d.level] + "40")
      .attr("stroke-width", d => d.level === 0 ? 2.5 : 1.5)
      .attr("cursor", "pointer")
      .on("click", (e, d) => { e.stopPropagation(); onNodeClick(d); })
      .on("dblclick", (e, d) => { e.stopPropagation(); onNodeDblClick(d); })
      .on("mouseenter", (e, d) => { showTooltip(e, d); enterFocus(d); })
      .on("mouseleave", () => { hideTooltip(); leaveFocus(); })
      .call(d3.drag()
        .on("start", dragStart)
        .on("drag", dragging)
        .on("end", dragEnd));

    enter.transition().duration(CFG.revealDuration)
      .attr("r", d => nodeRadius(d));

    // Update stroke for expanded state
    nodeGroup.selectAll("circle.node")
      .attr("stroke-width", d => {
        const data = nodeMap.get(d.id);
        return (data && data.expanded) ? 2.5 : 1.5;
      });
  }

  function renderLabels() {
    const sel = labelGroup.selectAll("text")
      .data(visibleNodes, d => d.id);

    sel.exit().transition().duration(CFG.collapseDuration)
      .attr("opacity", 0).remove();

    sel.enter().append("text")
      .attr("class", d => d.level === 0 ? "node-label node-label-bright" : "node-label")
      .attr("dy", d => nodeRadius(d) + 15)
      .attr("opacity", 0)
      .text(d => truncLabel(d.label, d.level))
      .transition().duration(CFG.revealDuration)
      .attr("opacity", 1);
  }

  /** Generate curved link path (quadratic bezier with curvature based on distance) */
  function linkPath(d) {
    const sx = d.source.x, sy = d.source.y;
    const tx = d.target.x, ty = d.target.y;
    const dx = tx - sx, dy = ty - sy;
    const dist = Math.sqrt(dx * dx + dy * dy);
    // Curvature: larger for cross-links, subtle for regular
    const curv = d.cross ? 0.3 : 0.12;
    const mx = (sx + tx) / 2 - dy * curv;
    const my = (sy + ty) / 2 + dx * curv;
    return `M${sx},${sy} Q${mx},${my} ${tx},${ty}`;
  }

  function ticked() {
    linkGroup.selectAll("path").attr("d", linkPath);

    glowGroup.selectAll("circle.glow")
      .attr("cx", d => d.x).attr("cy", d => d.y);

    ringGroup.selectAll("circle.expand-ring")
      .attr("cx", d => d.x).attr("cy", d => d.y);

    nodeGroup.selectAll("circle.node")
      .attr("cx", d => d.x).attr("cy", d => d.y);

    labelGroup.selectAll("text")
      .attr("x", d => d.x).attr("y", d => d.y);
  }

  // ─── Focus Mode (hover spotlight) ──────────────────────────────
  function enterFocus(d) {
    const neighbors = new Set([d.id]);
    visibleLinks.forEach(l => {
      const s = srcId(l), t = tgtId(l);
      if (s === d.id) neighbors.add(t);
      if (t === d.id) neighbors.add(s);
    });

    container.classed("focus-mode", true);

    nodeGroup.selectAll("circle.node")
      .classed("focused", n => neighbors.has(n.id));
    glowGroup.selectAll("circle.glow")
      .classed("focused", n => neighbors.has(n.id));
    linkGroup.selectAll("path")
      .classed("focused", l => srcId(l) === d.id || tgtId(l) === d.id);
    labelGroup.selectAll("text")
      .classed("focused", n => neighbors.has(n.id));
  }

  function leaveFocus() {
    container.classed("focus-mode", false);
    nodeGroup.selectAll("circle.node").classed("focused", false);
    glowGroup.selectAll("circle.glow").classed("focused", false);
    linkGroup.selectAll("path").classed("focused", false);
    labelGroup.selectAll("text").classed("focused", false);
  }

  // ─── Click to Expand / Collapse ─────────────────────────────────
  function onNodeClick(simNode) {
    const data = nodeMap.get(simNode.id);
    if (!data) return;

    if (data.level === 0 || data.children.length === 0) {
      showPanel(data);
      return;
    }

    if (data.expanded) {
      collapseNode(data);
    } else {
      expandNode(data, simNode);
    }
    showPanel(data);
    updateStats();
  }

  /** Double-click: recursively expand all descendants */
  function onNodeDblClick(simNode) {
    const data = nodeMap.get(simNode.id);
    if (!data || data.children.length === 0) return;

    expandAllRecursive(data, simNode);
    showPanel(data);
    updateStats();
  }

  function expandNode(data, simNode) {
    data.expanded = true;
    const newNodes = [];

    data.children.forEach((cid, i) => {
      if (simNodeMap.has(cid)) return;
      const childData = nodeMap.get(cid);
      if (!childData) return;

      const angle = (i / data.children.length) * Math.PI * 2;
      const dist = CFG.linkDistance[childData.level] || 80;
      const cn = cloneNodeForSim(childData);
      cn.x = simNode.x + Math.cos(angle) * dist * 0.3;
      cn.y = simNode.y + Math.sin(angle) * dist * 0.3;
      newNodes.push(cn);
    });

    // Gather links
    const allVisibleIds = new Set(visibleNodes.map(n => n.id));
    newNodes.forEach(n => allVisibleIds.add(n.id));

    const newLinks = [];
    graphData.links.forEach(l => {
      const s = srcId(l), t = tgtId(l);
      if (allVisibleIds.has(s) && allVisibleIds.has(t)) {
        if (!visibleLinks.find(vl => srcId(vl) === s && tgtId(vl) === t)) {
          newLinks.push(cloneLink(l));
        }
      }
    });

    visibleNodes.push(...newNodes);
    visibleLinks.push(...newLinks);
    rebuildSimNodeMap();
    render();
  }

  function expandAllRecursive(data, simNode) {
    if (!data.expanded) expandNode(data, simNode);
    data.children.forEach(cid => {
      const child = nodeMap.get(cid);
      const childSim = simNodeMap.get(cid);
      if (child && childSim && child.children.length > 0 && !child.expanded) {
        expandAllRecursive(child, childSim);
      }
    });
  }

  function collapseNode(data) {
    data.expanded = false;
    const toRemove = new Set();
    collectDescendants(data.id, toRemove);

    toRemove.forEach(id => {
      const d = nodeMap.get(id);
      if (d) d.expanded = false;
    });

    visibleNodes = visibleNodes.filter(n => !toRemove.has(n.id));
    visibleLinks = visibleLinks.filter(l =>
      !toRemove.has(srcId(l)) && !toRemove.has(tgtId(l)));

    rebuildSimNodeMap();
    render();
  }

  function collectDescendants(parentId, set) {
    const data = nodeMap.get(parentId);
    if (!data) return;
    data.children.forEach(cid => {
      set.add(cid);
      collectDescendants(cid, set);
    });
  }

  // ─── Drag ───────────────────────────────────────────────────────
  function dragStart(e, d) {
    if (!e.active) simulation.alphaTarget(0.08).restart();
    d.fx = d.x; d.fy = d.y;
  }
  function dragging(e, d) {
    d.fx = e.x; d.fy = e.y;
  }
  function dragEnd(e, d) {
    if (!e.active) simulation.alphaTarget(0);
    d.fx = null; d.fy = null;
  }

  // ─── Tooltip ────────────────────────────────────────────────────
  function showTooltip(event, d) {
    const data = nodeMap.get(d.id);
    if (!data) return;
    const levels = { 0: "Query", 1: "Channel", 2: "Semantic Tag", 3: "Content" };
    const hasChildren = data.children.length > 0;
    tooltip.html(`
      <div class="tooltip-label">${data.icon || ""} ${data.label}</div>
      <div class="tooltip-sub">${levels[data.level]} · ${data.strategy} · ${(data.relevance * 100).toFixed(0)}%</div>
      ${hasChildren ? `<div class="tooltip-hint">${data.expanded ? "Click to collapse" : `Click to reveal ${data.children.length} nodes · Double-click for all`}</div>` : ""}
    `);
    tooltip.classed("visible", true)
      .style("left", (event.pageX + 14) + "px")
      .style("top", (event.pageY - 10) + "px");
  }
  function hideTooltip() {
    tooltip.classed("visible", false);
  }

  // ─── Detail Panel ───────────────────────────────────────────────
  function showPanel(data) {
    detailPanel.classList.remove("panel-hidden");

    // Badge
    const badge = document.getElementById("panel-badge");
    const levelLabels = { 0: "QUERY", 1: "CHANNEL", 2: "TAG", 3: "CONTENT" };
    const badgeClasses = { 0: "badge-query", 1: "badge-l1", 2: "badge-l2", 3: "badge-l3" };
    badge.textContent = levelLabels[data.level];
    badge.className = "panel-badge " + badgeClasses[data.level];

    // Title
    document.getElementById("panel-title").textContent =
      (data.icon ? data.icon + " " : "") + data.label;

    // Relevance
    const pct = (data.relevance * 100).toFixed(1);
    document.getElementById("panel-relevance").textContent = pct + "%";
    document.getElementById("panel-relevance").style.color = CFG.colors[data.level];
    const bar = document.getElementById("panel-rel-bar");
    bar.style.width = pct + "%";
    bar.style.background = CFG.colors[data.level];

    // Strategy
    document.getElementById("panel-strategy").textContent = data.strategy;

    // Tags
    const tagsEl = document.getElementById("panel-tags");
    tagsEl.innerHTML = data.tags.map(t =>
      `<span class="tag-chip">${t}</span>`).join("");
    document.getElementById("tag-count").textContent = data.tags.length;

    // Preview
    document.getElementById("panel-preview").textContent = data.preview;

    // Connections
    const connEl = document.getElementById("panel-connections");
    connEl.innerHTML = "";
    let connCount = 0;

    if (data.parentId) {
      const parent = nodeMap.get(data.parentId);
      if (parent) {
        connCount++;
        const li = document.createElement("li");
        li.innerHTML = `<span class="conn-dot" style="background:${CFG.colors[parent.level]};color:${CFG.colors[parent.level]}"></span>
          <span>↑ ${parent.label} <span style="color:var(--text-dim)">(parent)</span></span>`;
        li.style.cursor = "pointer";
        li.addEventListener("click", () => {
          const pData = nodeMap.get(data.parentId);
          if (pData) showPanel(pData);
        });
        connEl.appendChild(li);
      }
    }

    data.children.forEach(cid => {
      const child = nodeMap.get(cid);
      if (!child) return;
      connCount++;
      const li = document.createElement("li");
      li.innerHTML = `<span class="conn-dot" style="background:${CFG.colors[child.level]};color:${CFG.colors[child.level]}"></span>
        <span>↓ ${child.label} <span style="color:var(--text-dim)">(${(child.relevance * 100).toFixed(0)}%)</span></span>`;
      li.style.cursor = "pointer";
      li.addEventListener("click", () => showPanel(child));
      connEl.appendChild(li);
    });

    document.getElementById("conn-count").textContent = connCount;
  }

  function closePanel() {
    detailPanel.classList.add("panel-hidden");
  }

  // ─── Search History ─────────────────────────────────────────────
  function addToHistory(query) {
    // Deduplicate
    searchHistory = searchHistory.filter(q => q.toLowerCase() !== query.toLowerCase());
    searchHistory.unshift(query);
    if (searchHistory.length > 12) searchHistory.pop();
    renderHistory();
  }

  function renderHistory() {
    if (searchHistory.length === 0) {
      historyBar.classList.remove("has-history");
      graphContainer.classList.remove("with-history");
      return;
    }
    historyBar.classList.add("has-history");
    graphContainer.classList.add("with-history");

    historyChips.innerHTML = searchHistory.map(q =>
      `<span class="history-chip${q === activeQuery ? " active" : ""}" data-query="${q}">${q}</span>`
    ).join("");

    historyChips.querySelectorAll(".history-chip").forEach(chip => {
      chip.addEventListener("click", () => {
        searchInput.value = chip.dataset.query;
        runSearch(chip.dataset.query);
      });
    });
  }

  // ─── Stats Bar ──────────────────────────────────────────────────
  function updateStats() {
    if (!graphData) return;
    const l1 = graphData.nodes.filter(n => n.level === 1).length;
    const l2 = graphData.nodes.filter(n => n.level === 2).length;
    const l3 = graphData.nodes.filter(n => n.level === 3).length;

    document.getElementById("stat-l1").textContent = l1;
    document.getElementById("stat-l2").textContent = l2;
    document.getElementById("stat-l3").textContent = l3;
    document.getElementById("stat-visible").textContent = visibleNodes.length;

    statsBar.classList.add("visible");

    // Also update header meta
    searchMeta.textContent = `${l1} channels · ${l2} tags · ${l3} content`;
  }

  // ─── Helpers ────────────────────────────────────────────────────
  function cloneNodeForSim(data) {
    return {
      id: data.id,
      label: data.label,
      level: data.level,
      relevance: data.relevance,
      strategy: data.strategy,
      icon: data.icon,
      parentId: data.parentId,
    };
  }

  function cloneLink(l) {
    return {
      source: typeof l.source === "object" ? l.source.id : l.source,
      target: typeof l.target === "object" ? l.target.id : l.target,
      level: l.level,
      cross: l.cross || false,
    };
  }

  function srcId(l) { return typeof l.source === "object" ? l.source.id : l.source; }
  function tgtId(l) { return typeof l.target === "object" ? l.target.id : l.target; }
  function linkKey(l) { return srcId(l) + "->" + tgtId(l); }

  function truncLabel(text, level) {
    const max = level === 0 ? 28 : (level === 1 ? 16 : 14);
    return text.length > max ? text.slice(0, max - 1) + "…" : text;
  }

  // ─── Boot ───────────────────────────────────────────────────────
  init();
})();
