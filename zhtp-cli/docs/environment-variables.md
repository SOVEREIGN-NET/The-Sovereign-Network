# ZHTP CLI Environment Variables

The ZHTP CLI supports configuration via environment variables with the `ZHTP_*` prefix. Environment variables follow this precedence:

1. **CLI Arguments** (highest priority)
2. Environment Variables
3. Configuration File
4. Default Values (lowest priority)

## Global Options

These environment variables apply to all commands:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ZHTP_SERVER` | string | `127.0.0.1:9333` | API server address (host:port) |
| `ZHTP_FORMAT` | string | `table` | Output format (json, yaml, table) |
| `ZHTP_CONFIG` | string | (optional) | Path to CLI config file |
| `ZHTP_API_KEY` | string | (optional) | API authentication key |
| `ZHTP_USER_ID` | string | (optional) | User ID for authenticated requests |
| `ZHTP_VERBOSE` | bool | false | Enable verbose debug output |
| `ZHTP_PROFILE` | string | (optional) | Named server profile from `~/.zhtp/cli.toml` |

## Node Command Options

Configuration for `zhtp-cli node start`:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ZHTP_NODE_CONFIG` | string | `./config` | Node configuration file path |
| `ZHTP_NODE_PORT` | u16 | (from config) | Mesh network port override |
| `ZHTP_NODE_NETWORK` | string | `development` | Network environment (mainnet, testnet, dev) |
| `ZHTP_NODE_DEV` | bool | false | Enable development mode (debug logging) |
| `ZHTP_NODE_PURE_MESH` | bool | false | Enable pure mesh mode (ISP-free networking) |
| `ZHTP_NODE_EDGE_MODE` | bool | false | Enable edge node mode (lightweight sync) |
| `ZHTP_NODE_EDGE_MAX_HEADERS` | usize | 500 | Max headers in edge mode (~100KB per 500) |
| `ZHTP_NODE_KEYSTORE` | string | `~/.zhtp/keystore` | Path to identity keystore directory |

## CLI Config File

The CLI can load defaults and server aliases from `~/.zhtp/cli.toml` (or via `--config` / `ZHTP_CONFIG`).

Example:

```toml
[defaults]
server = "127.0.0.1:9334"
keystore = "~/.zhtp/keystore"

[servers.central]
address = "central.sov:9334"
keystore = "~/.zhtp/keystore"
```

Usage:

```bash
zhtp-cli --profile central domain status central.sov
zhtp-cli --server central domain info central.sov
```

## Usage Examples

### Example 1: Connect to Different API Server

```bash
# Via environment variable
export ZHTP_SERVER=192.168.1.100:9333
zhtp-cli version

# Via CLI argument (overrides environment variable)
zhtp-cli --server 192.168.1.100:9333 version
```

### Example 2: Start Node with Custom Network

```bash
# Via environment variables
export ZHTP_NODE_NETWORK=testnet
export ZHTP_NODE_DEV=true
export ZHTP_NODE_KEYSTORE=~/.zhtp/testnet-keystore
zhtp-cli node start

# Via CLI arguments
zhtp-cli node start --network testnet --dev --keystore ~/.zhtp/testnet-keystore
```

### Example 3: Run in Production with API Key

```bash
# Via environment variables
export ZHTP_SERVER=api.zhtp.network:9333
export ZHTP_API_KEY=your-api-key-here
export ZHTP_FORMAT=json
zhtp-cli diagnostics quick

# Useful for scripts and CI/CD pipelines
```

### Example 4: Batch Operations with Verbose Logging

```bash
# Enable verbose output for all commands
export ZHTP_VERBOSE=true
export ZHTP_FORMAT=json

zhtp-cli config show
zhtp-cli version
zhtp-cli diagnostics full
```

## Environment Variable Loading

Clap loads environment variables in the following order:

1. **At startup**: All `ZHTP_*` variables are read
2. **Case-insensitive**: `ZHTP_SERVER` and `zhtp_server` are equivalent
3. **Boolean handling**:
   - `true`, `1`, `yes`, `on` → true
   - `false`, `0`, `no`, `off` → false
4. **Numeric parsing**: Strings are parsed to appropriate types (u16, usize, etc.)

## Shell Integration

### Bash

Add to `~/.bashrc`:

```bash
# ZHTP Configuration
export ZHTP_SERVER="127.0.0.1:9333"
export ZHTP_FORMAT="table"
export ZHTP_NODE_NETWORK="development"
```

### Zsh

Add to `~/.zshrc`:

```bash
# ZHTP Configuration
export ZHTP_SERVER="127.0.0.1:9333"
export ZHTP_FORMAT="table"
export ZHTP_NODE_NETWORK="development"
```

### Fish

Add to `~/.config/fish/config.fish`:

```bash
# ZHTP Configuration
set -x ZHTP_SERVER "127.0.0.1:9333"
set -x ZHTP_FORMAT "table"
set -x ZHTP_NODE_NETWORK "development"
```

### PowerShell

Add to `$PROFILE`:

```powershell
# ZHTP Configuration
$env:ZHTP_SERVER = "127.0.0.1:9333"
$env:ZHTP_FORMAT = "table"
$env:ZHTP_NODE_NETWORK = "development"
```

## Docker Integration

When running ZHTP CLI in Docker:

```dockerfile
FROM rust:latest

ENV ZHTP_SERVER="0.0.0.0:9333"
ENV ZHTP_FORMAT="json"
ENV ZHTP_NODE_NETWORK="testnet"

COPY . /app
WORKDIR /app

RUN cargo install --path zhtp-cli

ENTRYPOINT ["zhtp-cli"]
```

Usage:

```bash
docker run -e ZHTP_SERVER=192.168.1.100:9333 zhtp-cli version
```

## Kubernetes Integration

For Kubernetes deployments:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: zhtp-cli-job
spec:
  containers:
  - name: zhtp-cli
    image: zhtp:latest
    env:
    - name: ZHTP_SERVER
      value: "zhtp-node-service:9333"
    - name: ZHTP_API_KEY
      valueFrom:
        secretKeyRef:
          name: zhtp-secrets
          key: api-key
    - name: ZHTP_NODE_NETWORK
      value: "testnet"
```

## Best Practices

1. **For Development**: Set variables in shell config (`~/.bashrc`, `~/.zshrc`)
2. **For CI/CD**: Pass via environment during job execution
3. **For Containers**: Use Dockerfile ENV or container orchestration secrets
4. **For Scripts**: Use `export VAR=value` before script execution
5. **Security**: Never commit API keys; use secret management systems

## Troubleshooting

### Variable Not Being Recognized

Check that the variable name is spelled correctly (case-insensitive):

```bash
# These all work:
export ZHTP_SERVER=localhost:9333
export zhtp_server=localhost:9333
export Zhtp_Server=localhost:9333

# Debug: See actual values
echo $ZHTP_SERVER
```

### Precedence Issues

Remember: CLI arguments override environment variables:

```bash
export ZHTP_SERVER=localhost:9333
zhtp-cli --server 192.168.1.1:9333 version  # Uses 192.168.1.1:9333
```

### Type Conversion Errors

Ensure values match expected types:

```bash
# Wrong: Port must be a number
export ZHTP_NODE_PORT=abc  # ❌ Error

# Correct:
export ZHTP_NODE_PORT=9999  # ✅ Works
```
