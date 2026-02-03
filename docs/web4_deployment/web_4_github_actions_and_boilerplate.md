# WEB4 GitHub Actions and Boilerplate

This document explains how site builds and deployments work using GitHub Actions and provides a minimal boilerplate that deploys successfully.

---

## Scope

This document covers:

- What GitHub Actions does
- How to create a deployment workflow
- A minimal static-site boilerplate

---

## Minimal Boilerplate Repository

Create the following files:

```
repo-root/
├─ index.html
├─ package.json
└─ .github/
   └─ workflows/
      └─ deploy.yml
```

---

### index.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>WEB4 Site</title>
</head>
<body>
  <h1>Deployment Successful</h1>
</body>
</html>
```

---

### package.json

```json
{
  "name": "web4-site",
  "version": "1.0.0",
  "scripts": {
    "build": "mkdir -p dist && cp index.html dist/index.html"
  }
}
```

---

## GitHub Actions Workflow

Create this file:

```
.github/workflows/deploy.yml
```

```yaml
name: Deploy to Sovereign Network

on:
  push:
    branches: ["main"]

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - run: npm run build

      - run: |
          curl -L https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases/latest/download/zhtp-cli-linux-x86_64.tar.gz -o zhtp-cli.tar.gz
          tar -xzf zhtp-cli.tar.gz
          sudo mv zhtp-cli /usr/local/bin/

      - env:
          ZHTP_KEYSTORE_B64: ${{ secrets.ZHTP_KEYSTORE_B64 }}
          ZHTP_SERVER: ${{ secrets.ZHTP_SERVER }}
          ZHTP_SERVER_SPKI: ${{ secrets.ZHTP_SERVER_SPKI }}
        run: |
          mkdir -p ~/.zhtp
          echo "$ZHTP_KEYSTORE_B64" | base64 -d | tar -xzf - -C ~/.zhtp
          zhtp-cli deploy site \
            --domain your-site.sov \
            --keystore ~/.zhtp/keystore \
            --mode static \
            dist/
```

---

## Required Secrets

Add the following repository secrets:

| Secret | How to Create |
|--------|---------------|
| `ZHTP_KEYSTORE_B64` | `tar -czf - -C ~/.zhtp keystore \| base64 -w 0` |
| `ZHTP_SERVER` | Provided by network administrator |
| `ZHTP_SERVER_SPKI` | Provided by network administrator |

The keystore is a **directory**, not a file. You must tar it before encoding:

```bash
tar -czf - -C ~/.zhtp keystore | base64 -w 0 > keystore.b64
cat keystore.b64  # Paste this into ZHTP_KEYSTORE_B64 secret
```

---

## Build Output Mapping

| Framework | Output Directory |
|---------|------------------|
| Vite | `dist` |
| Create React App | `build` |
| Next.js (static export) | `out` |
| Hugo / Jekyll | `public` |

---

## Verification

After pushing to `main`:

- GitHub Actions runs
- Deployment step succeeds
- Domain serves the site

---

## Security Best Practices

### Use Full Commit SHAs for External Workflows

When referencing external or reusable workflows, **always use the full commit SHA** instead of branch names or tags. This prevents supply chain attacks where a malicious actor could push changes to a branch or move a tag.

**WRONG - Branch reference (vulnerable):**
```yaml
uses: SOVEREIGN-NET/The-Sovereign-Network/.github/workflows/deploy-site.yml@main
uses: SOVEREIGN-NET/The-Sovereign-Network/.github/workflows/deploy-site.yml@feat/some-branch
```

**WRONG - Tag reference (vulnerable to tag reassignment):**
```yaml
uses: SOVEREIGN-NET/The-Sovereign-Network/.github/workflows/deploy-site.yml@v1.0.0
```

**CORRECT - Full commit SHA (immutable):**
```yaml
uses: SOVEREIGN-NET/The-Sovereign-Network/.github/workflows/deploy-site.yml@4a53b4af5a6d3bc6f28c3125bae611958e15bdc8
```

To get the SHA for a branch:
```bash
git ls-remote origin refs/heads/development | cut -f1
# or
git rev-parse origin/development
```

This is enforced by SonarCloud security scanning (rule S7637).

### Pass Only Required Secrets to Reusable Workflows

When calling reusable workflows, **explicitly pass only the secrets the workflow needs** instead of using `secrets: inherit`. This follows the principle of least privilege and prevents accidentally exposing unrelated secrets.

**WRONG - Passes ALL repository secrets:**
```yaml
jobs:
  deploy:
    uses: SOVEREIGN-NET/The-Sovereign-Network/.github/workflows/deploy-site.yml@abc123...
    with:
      domain: my-site.sov
    secrets: inherit  # Exposes ALL secrets to the called workflow
```

**CORRECT - Pass only required secrets:**
```yaml
jobs:
  deploy:
    uses: SOVEREIGN-NET/The-Sovereign-Network/.github/workflows/deploy-site.yml@abc123...
    with:
      domain: my-site.sov
    secrets:
      ZHTP_KEYSTORE_B64: ${{ secrets.ZHTP_KEYSTORE_B64 }}
      ZHTP_SERVER: ${{ secrets.ZHTP_SERVER }}
      ZHTP_SERVER_SPKI: ${{ secrets.ZHTP_SERVER_SPKI }}
```

The deployment workflow requires exactly three secrets:
- `ZHTP_KEYSTORE_B64` - Base64-encoded keystore tarball
- `ZHTP_SERVER` - Server address for deployment
- `ZHTP_SERVER_SPKI` - Server public key for certificate pinning

