# zhtp-daemon

`zhtp-daemon` is the local browser companion for QUIC-native ZHTP/Web4 access.

It runs on `127.0.0.1` by default and does three things:

- persists a local device identity in `~/.zhtp-daemon/keystore`
- connects to ZHTP/Web4 nodes over QUIC using the existing `lib-network` client
- relays resolved domain metadata and Web4 content to the browser over localhost

## Default layout

- config: `~/.zhtp-daemon/config.toml`
- trust database: `~/.zhtp-daemon/trustdb.json`
- trust audit log: `~/.zhtp-daemon/trust-audit.log`
- daemon keystore: `~/.zhtp-daemon/keystore/`

## API surface

- `GET /healthz`
- `GET /api/v1/status`
- `GET /api/v1/resolve?domain=site.zhtp`
- `GET /api/v1/resolve/site.zhtp`
- `GET /api/v1/content?domain=site.zhtp&path=/`
- `GET /web4/content/site.zhtp`
- `GET /web4/content/site.zhtp/index.html`

`/web4/content/...` is intended for direct browser rendering. The daemon preserves upstream content type and cache headers so the browser extension can load pages and assets from localhost while the canonical network path remains QUIC.

## Trust modes

`config.toml` supports:

- `strict`: use pinned trust only
- `tofu`: trust on first use and persist anchors locally
- `bootstrap`: dev-only mode, skips certificate verification

The default is `tofu`.
