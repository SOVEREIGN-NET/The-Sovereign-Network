# Sovereign Explorer (Leptos WASM)

This is a client-side WASM SPA for the Sovereign Network block explorer.
It is served under `/explorer` and expects the node API at `/api/v1/blockchain/*`.

## Build (Trunk)

From the repo root:

```bash
cd explorer
trunk build --release
```

Output goes to `zhtp/static/explorer` (configured in `explorer/Trunk.toml`).

## API Dependencies

The UI uses:
- `GET /api/v1/blockchain/stats`
- `GET /api/v1/blockchain/blocks?limit=...`
- `GET /api/v1/blockchain/transactions?limit=...`
- `GET /api/v1/blockchain/search?q=...`

## Web4 Publishing

To register a `.sov` domain and publish this explorer as a Web4 citizen, build
and upload the generated `zhtp/static/explorer` directory as Web4 content, then
register the domain to point at the manifest CID.
