# Web4 Domain Management Guide

Register and manage `.sov` domains on the Sovereign Network.

## Overview

Sovereign Network domains (`.sov`) are quantum-resistant, decentralized domain names secured by your ZHTP identity. Domain ownership is cryptographically verified, and only the owner can deploy or modify sites.

## Prerequisites

- `zhtp-cli` installed locally
- ZHTP keystore with identity credentials
- Network connectivity to Sovereign Network nodes

## Installation

### Linux/macOS

```bash
# Download latest zhtp-cli
curl -L https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases/latest/download/zhtp-cli-linux-x86_64.tar.gz -o zhtp-cli.tar.gz

# Verify checksum
curl -L https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases/latest/download/SHA256SUMS -o SHA256SUMS
grep zhtp-cli-linux-x86_64.tar.gz SHA256SUMS | sha256sum -c

# Extract and install
tar -xzf zhtp-cli.tar.gz
sudo mv zhtp-cli /usr/local/bin/
chmod +x /usr/local/bin/zhtp-cli

# Verify installation
zhtp-cli --version
```

### Windows

```powershell
# Download from releases page
# https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases/latest

# Extract to desired location
# Add to PATH environment variable

# Verify installation
zhtp-cli --version
```

## Keystore Setup

### Generate New Identity

```bash
# Create keystore directory
mkdir -p ~/.zhtp/keystore

# Generate new identity
zhtp-cli identity create --keystore ~/.zhtp/keystore

# Output:
# Identity created: did:sov:abc123...
# Public key: <base64-encoded-key>
```

**Important:** Backup your keystore immediately:

```bash
# Create encrypted backup
tar -czf keystore-backup.tar.gz ~/.zhtp/keystore
gpg --symmetric --cipher-algo AES256 keystore-backup.tar.gz

# Store keystore-backup.tar.gz.gpg securely offline
```

### Import Existing Identity

```bash
# If you have an existing keystore
cp -r /path/to/existing/keystore ~/.zhtp/keystore

# Verify identity
zhtp-cli identity show --keystore ~/.zhtp/keystore
```

## Domain Registration

### Check Domain Availability

```bash
zhtp-cli domain check mysite.sov

# Output:
# Domain 'mysite.sov' is available
```

### Register Domain

```bash
zhtp-cli domain register mysite.sov --keystore ~/.zhtp/keystore

# Output:
# Registering domain 'mysite.sov'...
# Transaction ID: tx_abc123...
# Domain registered successfully
# Owner: did:sov:abc123...
```

**Registration Process:**
1. CLI signs registration request with your identity
2. Request submitted to network consensus
3. Domain registered after network confirmation (~30 seconds)
4. DNS records propagated across network

### Registration Cost

Domain registration requires network fees:

- **Initial registration:** 10 SVRN tokens
- **Annual renewal:** 5 SVRN tokens
- **Transfer fee:** 2 SVRN tokens

Check your token balance:

```bash
zhtp-cli wallet balance --keystore ~/.zhtp/keystore
```

### Domain Naming Rules

**Valid domains:**
- Lowercase letters: `mysite.sov`
- Numbers: `site123.sov`
- Hyphens: `my-site.sov`
- Length: 3-63 characters

**Invalid domains:**
- Starting/ending with hyphen: `-mysite.sov`, `mysite-.sov`
- Consecutive hyphens: `my--site.sov`
- Special characters: `my_site.sov`, `my.site.sov`
- Uppercase letters: `MySite.sov` (auto-converted to lowercase)

## Domain Management

### View Domain Information

```bash
zhtp-cli domain info mysite.sov

# Output:
# Domain: mysite.sov
# Owner: did:sov:abc123...
# Registered: 2026-01-15T10:30:00Z
# Expires: 2027-01-15T10:30:00Z
# Status: Active
# Current deployment: https://mysite.sov/
# Last updated: 2026-01-20T14:22:10Z
```

### List Your Domains

```bash
zhtp-cli domain list --keystore ~/.zhtp/keystore

# Output:
# Domains owned by did:sov:abc123...:
#   mysite.sov      (expires 2027-01-15)
#   myblog.sov      (expires 2027-02-01)
#   myapp.sov       (expires 2026-12-10)
```

### Renew Domain

Domains expire after 1 year. Renew before expiration:

```bash
zhtp-cli domain renew mysite.sov --keystore ~/.zhtp/keystore

# Output:
# Renewing domain 'mysite.sov'...
# Transaction ID: tx_def456...
# Domain renewed successfully
# New expiration: 2028-01-15T10:30:00Z
```

Set up auto-renewal:

```bash
zhtp-cli domain auto-renew enable mysite.sov --keystore ~/.zhtp/keystore
```

### Transfer Domain

Transfer ownership to another identity:

```bash
# Initiate transfer
zhtp-cli domain transfer mysite.sov \
  --to did:sov:xyz789... \
  --keystore ~/.zhtp/keystore

# Output:
# Transfer initiated for 'mysite.sov'
# Transfer ID: tr_abc123...
# Recipient must accept within 7 days
```

Recipient accepts transfer:

```bash
# Recipient runs
zhtp-cli domain accept-transfer tr_abc123... \
  --keystore ~/.zhtp/keystore

# Output:
# Transfer accepted
# Domain 'mysite.sov' now owned by did:sov:xyz789...
```

### Update Domain Records

Set custom DNS records:

```bash
# Add TXT record
zhtp-cli domain record add mysite.sov \
  --type TXT \
  --value "v=spf1 include:_spf.sovereign.network ~all" \
  --keystore ~/.zhtp/keystore

# Add CNAME record
zhtp-cli domain record add mysite.sov \
  --type CNAME \
  --name www \
  --value mysite.sov \
  --keystore ~/.zhtp/keystore
```

View current records:

```bash
zhtp-cli domain records mysite.sov

# Output:
# DNS Records for mysite.sov:
#   A      @      10.20.30.40
#   AAAA   @      2001:db8::1
#   TXT    @      "v=spf1 include:_spf.sovereign.network ~all"
#   CNAME  www    mysite.sov
```

## Deployment Management

### Current Deployment

View active deployment:

```bash
zhtp-cli deployment info mysite.sov

# Output:
# Domain: mysite.sov
# Status: Active
# Mode: static
# Files: 42
# Total size: 2.3 MB
# Deployed: 2026-01-20T14:22:10Z
# Deployed by: did:sov:abc123...
# IPFS CID: QmXyz123...
```

### Deployment History

View past deployments:

```bash
zhtp-cli deployment history mysite.sov

# Output:
# Deployment history for mysite.sov:
#   2026-01-20 14:22:10  QmXyz123...  2.3 MB  (current)
#   2026-01-18 09:15:32  QmAbc456...  2.1 MB
#   2026-01-15 16:44:21  QmDef789...  1.9 MB
```

### Rollback Deployment

Revert to previous deployment:

```bash
zhtp-cli deployment rollback mysite.sov \
  --to QmAbc456... \
  --keystore ~/.zhtp/keystore

# Output:
# Rolling back mysite.sov to QmAbc456...
# Deployment complete
# Site reverted to 2026-01-18 09:15:32 version
```

### Delete Deployment

Remove site (domain remains registered):

```bash
zhtp-cli deployment delete mysite.sov --keystore ~/.zhtp/keystore

# Output:
# Deleting deployment for mysite.sov...
# Deployment deleted
# Domain still registered, ready for new deployment
```

## Security

### Keystore Protection

**Encrypt keystore:**

```bash
# Encrypt with GPG
gpg --encrypt --recipient your@email.com ~/.zhtp/keystore

# Or use password protection
tar -czf - ~/.zhtp/keystore | gpg --symmetric --cipher-algo AES256 > keystore.tar.gz.gpg
```

**Secure permissions:**

```bash
chmod 700 ~/.zhtp
chmod 600 ~/.zhtp/keystore/*
```

**Environment variable for keystore path:**

```bash
export ZHTP_KEYSTORE_PATH=~/.zhtp/keystore
zhtp-cli domain list  # Uses ZHTP_KEYSTORE_PATH automatically
```

### Identity Verification

Verify you own a domain:

```bash
# Sign challenge
zhtp-cli identity prove-ownership mysite.sov --keystore ~/.zhtp/keystore

# Output:
# Ownership proof for mysite.sov:
# Signature: <base64-signature>
# Public key: <base64-pubkey>
# Valid until: 2026-01-21T10:30:00Z
```

Share proof with others:

```bash
# Generate verifiable proof
zhtp-cli identity prove-ownership mysite.sov \
  --keystore ~/.zhtp/keystore \
  --format json > ownership-proof.json

# Others can verify
zhtp-cli identity verify-proof ownership-proof.json
```

### Multi-Signature Domains

Require multiple identities to approve deployments:

```bash
# Enable multi-sig (2-of-3)
zhtp-cli domain multisig enable mysite.sov \
  --signers did:sov:abc123,did:sov:def456,did:sov:ghi789 \
  --threshold 2 \
  --keystore ~/.zhtp/keystore
```

Deployment requires approval from 2 of 3 signers.

## Troubleshooting

### Domain Already Registered

```
Error: Domain 'mysite.sov' is already registered
```

**Solutions:**
1. Check availability: `zhtp-cli domain check mysite.sov`
2. Find owner: `zhtp-cli domain info mysite.sov`
3. Try alternative name: `zhtp-cli domain check mysite2.sov`
4. Contact owner for transfer (if purchasing)

### Insufficient Balance

```
Error: Insufficient SVRN balance for registration
```

**Solutions:**
1. Check balance: `zhtp-cli wallet balance --keystore ~/.zhtp/keystore`
2. Acquire tokens: Contact network administrators or token exchange
3. Transfer tokens from another wallet

### Keystore Not Found

```
Error: Keystore not found at ~/.zhtp/keystore
```

**Solutions:**
1. Verify path: `ls ~/.zhtp/keystore`
2. Specify custom path: `--keystore /path/to/keystore`
3. Generate new identity: `zhtp-cli identity create --keystore ~/.zhtp/keystore`
4. Restore from backup

### Network Unreachable

```
Error: Failed to connect to network node
```

**Solutions:**
1. Check internet connectivity
2. Verify network status: `https://status.sovereign.network`
3. Try alternative node: `--node https://alt-node.sovereign.network`
4. Check firewall settings (QUIC port 4433)

### Expired Domain

```
Error: Domain 'mysite.sov' has expired
```

**Solutions:**
1. Renew within grace period (30 days): `zhtp-cli domain renew mysite.sov`
2. If past grace period, must re-register
3. Enable auto-renewal to prevent future expiration

## API Integration

### Programmatic Domain Management

Use zhtp-cli in scripts:

```bash
#!/bin/bash
# check-domains.sh - Monitor domain expiration

KEYSTORE=~/.zhtp/keystore
DOMAINS=$(zhtp-cli domain list --keystore $KEYSTORE --format json)

echo "$DOMAINS" | jq -r '.[] | select(.expires_in_days < 30) | .domain' | while read domain; do
  echo "Domain $domain expires soon!"
  zhtp-cli domain renew $domain --keystore $KEYSTORE
done
```

### JSON Output

All commands support `--format json`:

```bash
zhtp-cli domain info mysite.sov --format json

# Output:
# {
#   "domain": "mysite.sov",
#   "owner": "did:sov:abc123...",
#   "registered": "2026-01-15T10:30:00Z",
#   "expires": "2027-01-15T10:30:00Z",
#   "status": "active",
#   "deployment": {
#     "cid": "QmXyz123...",
#     "mode": "static",
#     "size_bytes": 2415360,
#     "deployed_at": "2026-01-20T14:22:10Z"
#   }
# }
```

## Best Practices

1. **Backup keystores** - Multiple encrypted backups in different locations
2. **Monitor expiration** - Set calendar reminders or enable auto-renewal
3. **Use staging domains** - Test deployments on `staging.sov` before `production.sov`
4. **Document ownership** - Keep records of domain purpose and deployment credentials
5. **Review access** - Regularly audit who has keystore access
6. **Update regularly** - Keep zhtp-cli updated for security patches
7. **Test recovery** - Periodically verify backup restoration procedures

## Advanced Topics

### Custom Network Configuration

Connect to alternative networks:

```bash
# Development network
zhtp-cli --network dev domain list

# Private network
zhtp-cli --network https://private.network.com domain list
```

### Batch Operations

Register multiple domains:

```bash
# domains.txt contains one domain per line
cat domains.txt | while read domain; do
  zhtp-cli domain register $domain --keystore ~/.zhtp/keystore
  sleep 5  # Rate limit
done
```

### Monitoring and Alerts

Set up monitoring:

```bash
# Cron job to check domain health
0 9 * * * /usr/local/bin/check-domains.sh | mail -s "Domain Status" you@example.com
```

## Next Steps

- [Deploy your site](./WEB4_DEPLOYMENT_GUIDE.md)
- [CLI Reference](./CLI_REFERENCE.md)
- [Network Architecture](./ARCHITECTURE.md)
