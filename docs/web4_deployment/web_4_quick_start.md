# WEB4 Quick Start

This document is a **procedural checklist** for deploying a website to the Sovereign Network.

Follow steps in order. Do not skip steps.

---

## Scope

This guide covers:

- Installing required tools
- Creating an identity
- Registering a `.sov` domain
- Deploying a site using GitHub Actions

---

## Identity Rules

- One identity controls the domain
- The same identity authorizes deployment
- No secondary or CI-specific identities exist

---

## Requirements

You must have:

1. A computer (Linux, macOS, or Windows)
2. A GitHub account
3. A GitHub repository
4. Network values:
   - `ZHTP_SERVER`
   - `ZHTP_SERVER_SPKI`

If any requirement is missing, stop.

---

## Step 1: Install zhtp-cli

```bash
curl -L https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases/latest/download/zhtp-cli-linux-x86_64.tar.gz -o zhtp-cli.tar.gz
curl -L https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases/latest/download/SHA256SUMS -o SHA256SUMS
grep ' zhtp-cli-linux-x86_64.tar.gz' SHA256SUMS | sha256sum -c
tar -xzf zhtp-cli.tar.gz
sudo mv zhtp-cli /usr/local/bin/
```

Verify:

```bash
zhtp-cli --version
```

---

## Step 2: Create Identity

```bash
zhtp-cli identity create --keystore ~/.zhtp/keystore
zhtp-cli identity show --keystore ~/.zhtp/keystore
```

---

## Step 3: Register Domain

```bash
zhtp-cli domain register your-site.sov --keystore ~/.zhtp/keystore
```

---

## Step 4: Configure GitHub Actions

Create this file in your repository:

```
.github/workflows/deploy.yml
```

Use the workflow from `WEB4_GITHUB_ACTIONS_AND_BOILERPLATE.md`.

---

## Step 5: Add GitHub Secrets

Add the following repository secrets:

- `ZHTP_KEYSTORE_B64`
- `ZHTP_SERVER`
- `ZHTP_SERVER_SPKI`

To generate the `ZHTP_KEYSTORE_B64` value, tar and base64-encode your keystore directory:

```bash
tar -czf - -C ~/.zhtp keystore | base64 | tr -d '\n' > keystore.b64
cat keystore.b64  # Paste this into the GitHub secret
```

Or, for a keystore directory:

```bash
tar -czf - -C ~/.zhtp keystore | base64 | tr -d '\n' > keystore.b64
cat keystore.b64
```

---

## Step 6: Deploy

Push to `main`.

Deployment runs automatically.

---

## Completion Criteria

Deployment is complete when:

- GitHub Actions succeeds
- Your `.sov` domain serves your site

