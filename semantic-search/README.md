# Sovereign Semantic Search — Visual Graph Brain

A hybrid between a search engine and Obsidian-style graph maps for exploring Sovereign Network's semantic channeling layer.

## Quick Start

Open `index.html` in any modern browser. No build step needed.

```
cd semantic-search
# Option A: just open the file
start index.html

# Option B: local server (avoids CORS issues with future API calls)
python -m http.server 8080
```

## Architecture

```
index.html   — Shell: search bar, SVG canvas, detail panel, legend
style.css    — Dark theme, node colors, animations, responsive layout
data.js      — Mock semantic channeling data generator (deterministic)
graph.js     — D3 v7 force-directed graph engine
```

## Three Depth Levels

| Level | Color  | Description |
|-------|--------|-------------|
| L1    | Red    | Top-ranked categories (Images, Videos, Recipes…) |
| L2    | Blue   | Top results within a tapped category |
| L3    | Orange | Neural mesh suggestions from exploratory channeling |

## Interaction

1. **Search** — type a query and press Enter (or click an example chip)
2. **L1 burst** — red category nodes radiate outward from the center query node
3. **Click L1** → blue result nodes cluster around the category
4. **Click L2** → orange suggestion nodes emerge from the result
5. **Click again** to collapse children
6. **Double-click** to expand an entire subtree recursively
7. **Drag** any node to rearrange
8. **Scroll** to zoom, **drag background** to pan
9. **Hover** for tooltip + focus spotlight (dims non-neighbors)
10. **Click** for detail panel with relevance bar, tags, connections

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+K` | Focus search bar |
| `Escape` | Close detail panel |

## Layout

The graph uses a hybrid of three D3 force strategies:

- **Force-directed** — organic Obsidian-style floating
- **Radial** — nodes pushed to concentric rings based on depth
- **Clustered bubbles** — custom force pulls children toward their parent

## Visual Features

- **Dot grid background** with radial vignette
- **Glassmorphism** on all panels (backdrop-filter blur)
- **Radial gradient** node fills with relevance-proportional sizing
- **Curved bezier links** (quadratic paths, cross-links animated)
- **Focus mode** — hover a node to spotlight its neighborhood
- **Pulsing ring** indicator on expanded nodes
- **Search history bar** — click any past query to re-run it
- **Live stats bar** — shows category/result/suggestion counts
- **Orbital loading animation** with nested spinning rings

## Connecting to Live Backend

Replace `SemanticData.generate(query)` in `graph.js` (`runSearch`) with:

```javascript
const response = await fetch(`/api/semantic-channel?q=${encodeURIComponent(query)}`);
const graphData = await response.json();
```

The expected payload shape matches the `SemanticData.generate()` output:

```json
{
  "query": "...",
  "nodes": [{ "id", "label", "level", "relevance", "strategy", "icon", "tags", "preview", "parentId", "expanded", "children" }],
  "links": [{ "source", "target", "level", "cross?" }]
}
```

## Dependencies

- [D3.js v7](https://d3js.org/) — loaded from CDN (`d3js.org/d3.v7.min.js`)
- No other runtime dependencies
