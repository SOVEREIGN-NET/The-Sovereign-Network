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

Service installs can override the root/config path with:

- `ZHTP_DAEMON_ROOT_DIR`
- `ZHTP_DAEMON_CONFIG`

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

## Linux release artifact

The Linux release pipeline produces:

- `zhtp-daemon-linux-x86_64.tar.gz`
- `zhtp-daemon-linux-x86_64.sha256`

Archive contents:

- `bin/zhtp-daemon`
- `config/config.toml`
- `systemd/zhtp-daemon.service`
- `scripts/install-zhtp-daemon-linux.sh`
- `README.md`

## Linux install

### 1. Extract the release

```bash
tar -xzf zhtp-daemon-linux-x86_64.tar.gz
cd zhtp-daemon-linux-x86_64
```

Optional checksum verification:

```bash
sha256sum -c ../zhtp-daemon-linux-x86_64.sha256
```

### 2. Install the binary and service unit

Fast path:

```bash
sudo bash scripts/install-zhtp-daemon-linux.sh
```

Manual path:

```bash
sudo install -m 0755 bin/zhtp-daemon /usr/local/bin/zhtp-daemon
sudo install -m 0644 systemd/zhtp-daemon.service /etc/systemd/system/zhtp-daemon.service
```

### 3. Create the service user and state directory

```bash
sudo useradd --system --home /var/lib/zhtp-daemon --create-home --shell /usr/sbin/nologin zhtp-daemon || true
sudo install -d -o zhtp-daemon -g zhtp-daemon -m 0750 /var/lib/zhtp-daemon
sudo install -o zhtp-daemon -g zhtp-daemon -m 0640 config/config.toml /var/lib/zhtp-daemon/config.toml
```

### 4. Enable and start the daemon

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zhtp-daemon
sudo systemctl status zhtp-daemon
```

### 5. Inspect logs

```bash
journalctl -u zhtp-daemon -f
```

## Filesystem paths for the systemd install

With the provided `deploy/zhtp-daemon.service` unit:

- binary: `/usr/local/bin/zhtp-daemon`
- root dir: `/var/lib/zhtp-daemon`
- config: `/var/lib/zhtp-daemon/config.toml`
- trust database: `/var/lib/zhtp-daemon/trustdb.json`
- trust audit log: `/var/lib/zhtp-daemon/trust-audit.log`
- keystore: `/var/lib/zhtp-daemon/keystore/`

## Building the release package locally

```bash
cargo build --release -p zhtp-daemon
bash scripts/package-zhtp-daemon-linux.sh
```
