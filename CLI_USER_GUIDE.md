# ZHTP CLI User Guide - Web4 Deployment & Domain Management

Complete reference for the ZHTP command-line interface with focus on Web4 site deployment and domain management.

## Quick Start

### Prerequisites
- ZHTP Node running locally (default: `127.0.0.1:9333`)
- Identity keystore directory (for production operations)
- Static files ready to deploy (HTML, CSS, JS, etc.)

### Basic Deployment (5 minutes)
```bash
# 1. Register a domain
zhtp-cli domain register --domain myapp.zhtp --duration 365

# 2. Deploy your site
zhtp-cli deploy site ./build --domain myapp.zhtp --keystore ~/.zhtp/keystore

# 3. Check deployment status
zhtp-cli deploy status myapp.zhtp
```

---

## Table of Contents

1. [Deploy Commands](#deploy-commands) - Deploy and manage Web4 sites
2. [Domain Commands](#domain-commands) - Register and manage domains
3. [Trust & Security](#trust--security) - Manage trust relationships
4. [Configuration](#configuration) - Trust flags and options
5. [Examples & Workflows](#examples--workflows) - Real-world usage patterns

---

## Deploy Commands

Web4 site deployment to ZHTP domains with versioning and rollback support.

### `deploy site` - Deploy a New Site

**Syntax:**
```bash
zhtp-cli deploy site <BUILD_DIR> --domain <DOMAIN> --keystore <KEYSTORE> [OPTIONS]
```

**Parameters:**
- `BUILD_DIR` - Directory containing your static site files (required)
- `--domain, -d` - Target domain name, e.g., `myapp.zhtp` (required)
- `--keystore, -k` - Path to identity keystore directory (required for production)
- `--mode, -m` - Deployment mode: `spa` (single page app) or `static` (default: `spa`)
- `--fee, -f` - ZHTP tokens to pay for deployment (optional)
- `--dry-run` - Preview deployment without actually deploying (optional)

**Trust flags** (optional, for network security):
- `--pin-spki` - Pin to specific SPKI hash (hex encoded, most secure)
- `--node-did` - Expected node DID (verified after handshake)
- `--tofu` - Trust on first use (stores fingerprint)
- `--trust-node` - Bootstrap mode (accept any cert, dev only, INSECURE)

**Examples:**
```bash
# Deploy a React SPA
zhtp-cli deploy site ./dist --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore --mode spa

# Dry run to preview
zhtp-cli deploy site ./dist --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore --dry-run

# Deploy with custom fee
zhtp-cli deploy site ./dist --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore --fee 10
```

**What happens:**
1. Scans `BUILD_DIR` for all static files
2. Calculates BLAKE3 hashes for each file
3. Creates manifest with file metadata
4. Uploads files to content storage
5. Registers domain with initial manifest version
6. Returns manifest CID and deployment details

---

### `deploy status` - Check Deployment Status

**Syntax:**
```bash
zhtp-cli deploy status <DOMAIN> [OPTIONS]
```

**Parameters:**
- `DOMAIN` - Domain name to check (required)
- `--keystore, -k` - Path to keystore (optional)
- `--pin-spki` - Pin to specific SPKI hash
- `--node-did` - Expected node DID
- `--tofu` - Trust on first use
- `--trust-node` - Bootstrap mode (dev only)

**Examples:**
```bash
# Check status of a domain
zhtp-cli deploy status myapp.zhtp

# Check with specific keystore
zhtp-cli deploy status myapp.zhtp --keystore ~/.zhtp/keystore
```

**Output includes:**
- Domain found (yes/no)
- Current version number
- Current manifest CID
- Owner DID
- Manifest file count
- Created timestamp

---

### `deploy list` - List All Deployments

**Syntax:**
```bash
zhtp-cli deploy list [OPTIONS]
```

**Parameters:**
- `--keystore, -k` - Path to keystore (optional)
- Trust flags as above

**Examples:**
```bash
# List all deployments
zhtp-cli deploy list

# List with keystore context
zhtp-cli deploy list --keystore ~/.zhtp/keystore
```

**Output:** Table of all registered domains with their versions and status.

---

### `deploy history` - View Deployment Versions

**Syntax:**
```bash
zhtp-cli deploy history <DOMAIN> [OPTIONS]
```

**Parameters:**
- `DOMAIN` - Domain to check (required)
- `--limit, -l` - Maximum versions to show (default: 10)
- `--keystore, -k` - Path to keystore (optional)
- Trust flags as above

**Examples:**
```bash
# Show last 10 versions
zhtp-cli deploy history myapp.zhtp

# Show last 5 versions
zhtp-cli deploy history myapp.zhtp --limit 5

# Show all versions
zhtp-cli deploy history myapp.zhtp --limit 1000
```

**Version details:**
- Version number
- Manifest CID
- Build hash (deployment signature)
- Created timestamp
- Deployment message (if provided)

---

### `deploy update` - Update Existing Deployment

**Syntax:**
```bash
zhtp-cli deploy update <BUILD_DIR> --domain <DOMAIN> --keystore <KEYSTORE> [OPTIONS]
```

**Parameters:**
- `BUILD_DIR` - New build directory with updated files (required)
- `--domain, -d` - Domain to update (required)
- `--keystore, -k` - Path to keystore (required)
- `--mode, -m` - Deployment mode: `spa` or `static` (default: `spa`)
- `--fee, -f` - ZHTP tokens for update (optional)
- `--dry-run` - Preview update without deploying
- Trust flags as above

**Examples:**
```bash
# Update site after rebuilding
zhtp-cli deploy update ./dist --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore

# Preview update
zhtp-cli deploy update ./dist --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore --dry-run
```

**What happens:**
1. Validates domain ownership
2. Scans new build directory
3. Creates new manifest with updated files
4. Uploads new content
5. Increments version number
6. Previous version remains in history (rollback available)

---

### `deploy rollback` - Revert to Previous Version

**Syntax:**
```bash
zhtp-cli deploy rollback --domain <DOMAIN> --to-version <VERSION> \
  --keystore <KEYSTORE> [OPTIONS]
```

**Parameters:**
- `--domain, -d` - Domain to rollback (required)
- `--to-version` - Target version number (required)
- `--keystore, -k` - Path to keystore (required)
- `--force, -f` - Skip confirmation prompt
- Trust flags as above

**Examples:**
```bash
# Rollback to version 3
zhtp-cli deploy rollback --domain myapp.zhtp --to-version 3 \
  --keystore ~/.zhtp/keystore

# Force rollback without confirmation
zhtp-cli deploy rollback --domain myapp.zhtp --to-version 3 \
  --keystore ~/.zhtp/keystore --force
```

**What happens:**
1. Validates rollback is to a previous version
2. Retrieves historical manifest for that version
3. Updates domain pointer to old manifest
4. Creates new version entry referencing the rolled-back content
5. Clients receive old version content

---

### `deploy delete` - Delete Deployment

**Syntax:**
```bash
zhtp-cli deploy delete --domain <DOMAIN> --keystore <KEYSTORE> [OPTIONS]
```

**Parameters:**
- `--domain, -d` - Domain to delete (required)
- `--keystore, -k` - Path to keystore (required)
- `--force, -f` - Skip confirmation
- Trust flags as above

**Examples:**
```bash
# Delete a deployment
zhtp-cli deploy delete --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore

# Force delete
zhtp-cli deploy delete --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore --force
```

**What happens:**
1. Validates ownership
2. Removes domain from registry
3. Deletes from persistent storage
4. Returns ownership rights
5. Cannot be undone (consider rollback if you need recovery)

---

## Domain Commands

Domain registration, management, and lifecycle operations.

### `domain register` - Register a New Domain

**Syntax:**
```bash
zhtp-cli domain register --domain <DOMAIN> [OPTIONS]
```

**Parameters:**
- `--domain, -d` - Domain name (required), e.g., `mysite.zhtp`
- `--duration` - Registration duration in days (default: 365)
- `--metadata, -m` - Domain metadata as JSON string (optional)
- `--keystore, -k` - Path to keystore (optional)
- Trust flags as above

**Examples:**
```bash
# Register with defaults (365 days)
zhtp-cli domain register --domain mysite.zhtp

# Register with custom duration
zhtp-cli domain register --domain mysite.zhtp --duration 730

# Register with metadata
zhtp-cli domain register --domain mysite.zhtp \
  --metadata '{"description": "My awesome site"}'
```

**Output:**
- Domain name
- Registration confirmed
- Owner identity (your DID)
- Expiration date

---

### `domain check` - Check Domain Availability

**Syntax:**
```bash
zhtp-cli domain check --domain <DOMAIN> [OPTIONS]
```

**Parameters:**
- `--domain, -d` - Domain name to check (required)
- `--keystore, -k` - Path to keystore (optional)
- Trust flags as above

**Examples:**
```bash
# Check if domain is available
zhtp-cli domain check --domain mysite.zhtp

# Check multiple domains
for d in app1 app2 app3; do
  zhtp-cli domain check --domain "$d.zhtp"
done
```

**Output:**
- Available: yes/no
- If registered: owner DID, version

---

### `domain info` - Get Domain Information

**Syntax:**
```bash
zhtp-cli domain info --domain <DOMAIN> [OPTIONS]
```

**Parameters:**
- `--domain, -d` - Domain name (required)
- `--keystore, -k` - Path to keystore (optional)
- Trust flags as above

**Examples:**
```bash
# Get domain details
zhtp-cli domain info --domain mysite.zhtp
```

**Output includes:**
- Domain name
- Owner DID
- Current version
- Current manifest CID
- Created timestamp
- File count in manifest
- Metadata

---

### `domain transfer` - Transfer Ownership

**Syntax:**
```bash
zhtp-cli domain transfer --domain <DOMAIN> --new-owner <NEW_OWNER_DID> \
  --keystore <KEYSTORE> [OPTIONS]
```

**Parameters:**
- `--domain, -d` - Domain to transfer (required)
- `--new-owner` - New owner's DID (required)
- `--keystore, -k` - Your keystore path (required)
- Trust flags as above

**Examples:**
```bash
# Transfer to another identity
zhtp-cli domain transfer --domain mysite.zhtp \
  --new-owner "did:zhtp:bob-device" \
  --keystore ~/.zhtp/keystore
```

**What happens:**
1. Validates your ownership
2. Updates domain ownership record
3. New owner can now manage the domain
4. Content remains accessible (address doesn't change)

---

### `domain release` - Release Domain

**Syntax:**
```bash
zhtp-cli domain release --domain <DOMAIN> --keystore <KEYSTORE> [OPTIONS]
```

**Parameters:**
- `--domain, -d` - Domain to release (required)
- `--keystore, -k` - Your keystore path (required)
- `--force, -f` - Skip confirmation
- Trust flags as above

**Examples:**
```bash
# Release a domain
zhtp-cli domain release --domain mysite.zhtp \
  --keystore ~/.zhtp/keystore

# Force release
zhtp-cli domain release --domain mysite.zhtp \
  --keystore ~/.zhtp/keystore --force
```

**What happens:**
1. Validates ownership
2. Removes domain from registry
3. Domain becomes available for others to register
4. Deletes associated storage
5. Cannot be undone

---

## Trust & Security

### Trust Configuration Flags

Used with all deploy and domain commands for network security:

**--pin-spki** - Pin to specific SPKI hash (most secure)
```bash
zhtp-cli deploy status myapp.zhtp \
  --pin-spki "abc123def456..."
```
- Use when you know the exact server certificate
- Immune to MITM attacks
- Requires certificate hash update if server cert changes

**--node-did** - Verify specific node identity
```bash
zhtp-cli deploy status myapp.zhtp \
  --node-did "did:zhtp:node-device"
```
- Verified after handshake
- Ensures you're connecting to expected node
- Protects against identity spoofing

**--tofu** - Trust On First Use
```bash
zhtp-cli deploy status myapp.zhtp --tofu
```
- Stores server fingerprint on first connection
- Future connections verify against stored fingerprint
- Balance between security and convenience
- Good for dev environments

**--trust-node** - Bootstrap Mode (INSECURE - Dev Only)
```bash
zhtp-cli deploy status myapp.zhtp --trust-node
```
- Accepts any certificate
- No verification whatsoever
- **DO NOT USE IN PRODUCTION**
- Development and testing only

### Trust Database

```bash
# List trusted nodes
zhtp-cli trust list

# Show trust audit log
zhtp-cli trust audit

# Reset trust for a node
zhtp-cli trust reset "192.168.1.1:9333"
```

---

## Configuration

### Server Address

By default, CLI connects to `127.0.0.1:9333`.

Override with environment variable:
```bash
export ZHTP_SERVER="192.168.1.100:9333"
zhtp-cli deploy list

# Or on command line
ZHTP_SERVER="192.168.1.100:9333" zhtp-cli deploy list
```

### Output Formats

```bash
# Default table format
zhtp-cli deploy list

# JSON format
ZHTP_FORMAT=json zhtp-cli deploy list

# YAML format
ZHTP_FORMAT=yaml zhtp-cli deploy list
```

### Verbosity

```bash
# Enable verbose output
ZHTP_VERBOSE=true zhtp-cli deploy site ./dist --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore
```

### API Authentication

For secured nodes:
```bash
export ZHTP_API_KEY="your-api-key"
export ZHTP_USER_ID="your-user-id"
zhtp-cli deploy list
```

---

## Examples & Workflows

### Workflow 1: Deploy a React SPA

```bash
# 1. Build your React app
cd my-react-app
npm run build

# 2. Register domain
zhtp-cli domain register --domain myreactapp.zhtp --duration 365

# 3. Deploy
zhtp-cli deploy site ./dist --domain myreactapp.zhtp \
  --keystore ~/.zhtp/keystore --mode spa

# 4. Verify
zhtp-cli deploy status myreactapp.zhtp
```

Access at: `https://myreactapp.zhtp`

### Workflow 2: Deploy and Update

```bash
# Initial deployment
zhtp-cli deploy site ./dist --domain blog.zhtp \
  --keystore ~/.zhtp/keystore

# Make changes locally
# ... edit files, rebuild ...
npm run build

# Deploy update
zhtp-cli deploy update ./dist --domain blog.zhtp \
  --keystore ~/.zhtp/keystore

# Check version changed
zhtp-cli deploy status blog.zhtp
```

### Workflow 3: Rollback on Error

```bash
# View recent versions
zhtp-cli deploy history blog.zhtp --limit 5

# See version 2 was good, current is version 3 (broken)
# Rollback to version 2
zhtp-cli deploy rollback --domain blog.zhtp --to-version 2 \
  --keystore ~/.zhtp/keystore

# Verify rollback
zhtp-cli deploy status blog.zhtp
```

### Workflow 4: Multi-site Management

```bash
#!/bin/bash

DOMAINS=("app1" "app2" "app3")
KEYSTORE="$HOME/.zhtp/keystore"

for domain in "${DOMAINS[@]}"; do
  echo "Checking $domain.zhtp..."
  zhtp-cli deploy status "$domain.zhtp"
  echo ""
done
```

### Workflow 5: Batch Deploy with Dry Run

```bash
#!/bin/bash

SITES_DIR="$HOME/web-projects"
KEYSTORE="$HOME/.zhtp/keystore"

# First: preview all deploys
for site_dir in "$SITES_DIR"/*/; do
  site_name=$(basename "$site_dir")
  echo "=== DRY RUN: $site_name ==="
  zhtp-cli deploy site "$site_dir/dist" \
    --domain "$site_name.zhtp" \
    --keystore "$KEYSTORE" \
    --dry-run
done

# If all look good, actually deploy
read -p "Deploy all sites? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  for site_dir in "$SITES_DIR"/*/; do
    site_name=$(basename "$site_dir")
    echo "=== DEPLOYING: $site_name ==="
    zhtp-cli deploy site "$site_dir/dist" \
      --domain "$site_name.zhtp" \
      --keystore "$KEYSTORE"
  done
fi
```

### Workflow 6: Domain Lifecycle

```bash
# 1. Check availability
zhtp-cli domain check --domain nextproject.zhtp

# 2. Register
zhtp-cli domain register --domain nextproject.zhtp --duration 730

# 3. Get details
zhtp-cli domain info --domain nextproject.zhtp

# 4. Deploy content
zhtp-cli deploy site ./dist --domain nextproject.zhtp \
  --keystore ~/.zhtp/keystore

# ... operate domain ...

# 5. Transfer when needed
zhtp-cli domain transfer --domain nextproject.zhtp \
  --new-owner "did:zhtp:new-owner" \
  --keystore ~/.zhtp/keystore

# Or release if done
zhtp-cli domain release --domain nextproject.zhtp \
  --keystore ~/.zhtp/keystore
```

---

## Troubleshooting

### Connection Issues

```bash
# Check if node is running
ping 127.0.0.1

# Try different server address
ZHTP_SERVER="192.168.1.100:9333" zhtp-cli deploy list
```

### Authentication Issues

If you get "Invalid owner identity" errors:
```bash
# Verify keystore exists
ls -la ~/.zhtp/keystore

# Use correct keystore path
zhtp-cli deploy site ./dist --domain myapp.zhtp \
  --keystore /full/path/to/keystore
```

### Domain Already Exists

```bash
# Check who owns it
zhtp-cli domain info --domain existing.zhtp

# If you own it and want to redeploy
zhtp-cli deploy update ./dist --domain existing.zhtp \
  --keystore ~/.zhtp/keystore
```

### Manifest Not Found

```bash
# Check domain status
zhtp-cli deploy status myapp.zhtp

# Verify files were uploaded
zhtp-cli deploy history myapp.zhtp

# Redeploy if needed
zhtp-cli deploy update ./dist --domain myapp.zhtp \
  --keystore ~/.zhtp/keystore
```

---

## Help & Documentation

```bash
# Show all commands
zhtp-cli --help

# Help for a specific command
zhtp-cli deploy --help
zhtp-cli domain --help

# Version information
zhtp-cli --version
```

---

## Summary

| Command | Purpose | Requires Keystore |
|---------|---------|-------------------|
| `deploy site` | Deploy new site | Yes |
| `deploy update` | Update existing site | Yes |
| `deploy status` | Check deployment status | No |
| `deploy history` | View version history | No |
| `deploy list` | List all deployments | No |
| `deploy rollback` | Revert to previous version | Yes |
| `deploy delete` | Remove deployment | Yes |
| `domain register` | Register new domain | No |
| `domain check` | Check availability | No |
| `domain info` | Get domain details | No |
| `domain transfer` | Change ownership | Yes |
| `domain release` | Release domain | Yes |

---

**Last Updated:** December 2025
**Version:** 1.0
**For Issues:** See [Web4 CLI Testing Issue](#)
