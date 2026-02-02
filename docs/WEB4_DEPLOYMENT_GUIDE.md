# Web4 Deployment Guide

Deploy your website to the Sovereign Network's Web4 infrastructure using GitHub Actions.

## Overview

Web4 deployment allows you to host static sites and SPAs on the Sovereign Network's decentralized infrastructure. Sites are accessed via `.sov` domains and benefit from quantum-resistant security and distributed hosting.

## Prerequisites

- GitHub repository with your website code
- A `.sov` domain registered on the Sovereign Network
- ZHTP keystore with identity credentials
- GitHub Actions enabled on your repository

## Quick Start

### 1. Prepare Your Build Output

Your site must build to a directory containing static files (HTML, CSS, JS, assets). Common setups:

**Static Sites:**
```bash
# Output directory: out/, dist/, or build/
npm run build
```

**Frameworks:**
- Next.js: `npm run build && npm run export` → `out/`
- Vite: `npm run build` → `dist/`
- Create React App: `npm run build` → `build/`

### 2. Set Up Repository Secrets

Navigate to your repository's **Settings → Secrets and variables → Actions**:

#### Required Secret: ZHTP_KEYSTORE_B64

Your identity keystore encoded as base64 gzipped tarball:

```bash
# Create keystore tarball and encode
cd ~/.zhtp
tar -czf - keystore | base64 -w 0 > keystore-secret.b64

# Copy contents to GitHub secret
cat keystore-secret.b64
```

**Important:** Keep this secret secure. Anyone with access can deploy to your domain.

#### Inherited Secrets (from SOVEREIGN-NET/The-Sovereign-Network)

These are automatically available if your repository is in the same organization:

- `ZHTP_SERVER`: Server endpoint for deployments
- `ZHTP_SERVER_SPKI`: Server public key for pinning

If deploying from a different organization, contact network administrators for these values.

### 3. Add Workflow File

Create `.github/workflows/deploy-web4.yml`:

```yaml
name: Deploy to Web4

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  build:
    name: Build site
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/  # Change to your build directory
          retention-days: 1

  deploy:
    name: Deploy to Web4
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          name: build-output
          path: out/

      - name: Verify build output
        run: ls -la out/

      - name: Download zhtp-cli
        run: |
          cd /tmp
          gh release download cli-v0.2.0 \
            --repo SOVEREIGN-NET/The-Sovereign-Network \
            --pattern 'zhtp-cli-linux-x86_64.tar.gz' \
            --pattern 'SHA256SUMS'
          grep ' zhtp-cli-linux-x86_64.tar.gz' SHA256SUMS > SHA256SUMS.cli
          sha256sum -c SHA256SUMS.cli
          tar -xzf zhtp-cli-linux-x86_64.tar.gz -C /tmp
          chmod +x /tmp/zhtp-cli
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Restore keystore
        run: |
          mkdir -p ~/.zhtp
          echo "${{ secrets.ZHTP_KEYSTORE_B64 }}" | base64 --decode | tar -xzf - -C ~/.zhtp
        shell: bash

      - name: Deploy site
        run: |
          /tmp/zhtp-cli deploy site \
            --domain "your-site.sov" \
            --keystore ~/.zhtp/keystore \
            --mode "static" \
            --pin-spki "$ZHTP_SERVER_SPKI" \
            out/
        env:
          ZHTP_SERVER: ${{ secrets.ZHTP_SERVER }}
          ZHTP_SERVER_SPKI: ${{ secrets.ZHTP_SERVER_SPKI }}
```

### 4. Configure for Your Project

Update these values in the workflow:

1. **Build output path** (line 32): Change `dist/` to your framework's output directory
2. **Domain** (line 58): Replace `your-site.sov` with your registered domain
3. **Deployment mode** (line 60): Use `static` or `spa` depending on your site type

### 5. Deploy

**Automatic:** Push to main branch
```bash
git push origin main
```

**Manual:** Trigger from GitHub Actions tab
1. Go to **Actions** → **Deploy to Web4**
2. Click **Run workflow**
3. Select branch and click **Run workflow**

### 6. Verify Deployment

Visit your site at `https://your-site.sov`

Check deployment logs in the GitHub Actions tab for any errors.

## Configuration Options

### Deployment Modes

**Static (`--mode static`):**
- Traditional static sites
- All files served as-is
- Best for: HTML/CSS/JS sites, blogs, documentation

**SPA (`--mode spa`):**
- Single Page Applications
- Routes fallback to `index.html`
- Best for: React, Vue, Angular apps with client-side routing

### CLI Version

Update the CLI version in the workflow:
```yaml
gh release download cli-v0.2.0 \  # Change version here
```

Available versions: Check [releases page](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases)

### Build Output Directory

Common framework outputs:

| Framework | Default Output | Build Command |
|-----------|----------------|---------------|
| Next.js (static) | `out/` | `npm run build && npm run export` |
| Vite | `dist/` | `npm run build` |
| Create React App | `build/` | `npm run build` |
| Hugo | `public/` | `hugo` |
| Jekyll | `_site/` | `jekyll build` |
| Gatsby | `public/` | `gatsby build` |

## Advanced Configuration

### Multiple Domains

Deploy the same site to multiple domains:

```yaml
- name: Deploy to primary domain
  run: |
    /tmp/zhtp-cli deploy site \
      --domain "primary.sov" \
      --keystore ~/.zhtp/keystore \
      --mode "static" \
      --pin-spki "$ZHTP_SERVER_SPKI" \
      out/

- name: Deploy to secondary domain
  run: |
    /tmp/zhtp-cli deploy site \
      --domain "secondary.sov" \
      --keystore ~/.zhtp/keystore \
      --mode "static" \
      --pin-spki "$ZHTP_SERVER_SPKI" \
      out/
```

### Environment-Specific Deployments

Deploy to different domains based on branch:

```yaml
- name: Set deployment domain
  id: domain
  run: |
    if [ "${{ github.ref }}" == "refs/heads/main" ]; then
      echo "domain=production.sov" >> $GITHUB_OUTPUT
    else
      echo "domain=staging.sov" >> $GITHUB_OUTPUT
    fi

- name: Deploy site
  run: |
    /tmp/zhtp-cli deploy site \
      --domain "${{ steps.domain.outputs.domain }}" \
      --keystore ~/.zhtp/keystore \
      --mode "static" \
      --pin-spki "$ZHTP_SERVER_SPKI" \
      out/
```

### Custom Build Steps

Add additional build steps as needed:

```yaml
- name: Build
  run: |
    npm run build
    npm run post-process
    npm run optimize-images

- name: Generate sitemap
  run: npm run sitemap

- name: Run tests
  run: npm test
```

## Security Best Practices

### Keystore Management

1. **Never commit keystores to git**
   - Add to `.gitignore`: `keystore`, `*.b64`, `.zhtp/`

2. **Rotate secrets regularly**
   - Generate new keystores periodically
   - Update GitHub secret immediately

3. **Limit secret access**
   - Use environment-specific secrets for staging/production
   - Restrict repository access to trusted collaborators

4. **Backup keystores securely**
   - Store encrypted backups offline
   - Document recovery procedures

### Workflow Security

1. **Pin CLI version**
   - Don't use `latest`, specify exact version
   - Review release notes before upgrading

2. **Verify checksums**
   - Always validate `SHA256SUMS` (included in workflow)
   - Report checksum mismatches immediately

3. **Review workflow changes**
   - All workflow modifications should be reviewed
   - Test in staging before production

## Troubleshooting

### Build Failures

**Symptom:** Build job fails
```
Error: Cannot find module 'package.json'
```

**Solution:** Ensure `npm ci` runs before build:
```yaml
- name: Install dependencies
  run: npm ci

- name: Build
  run: npm run build
```

### Artifact Not Found

**Symptom:** Deploy job fails
```
Error: Artifact 'build-output' not found
```

**Solution:** Verify upload path matches your build output:
```yaml
- name: Upload artifacts
  uses: actions/upload-artifact@v4
  with:
    name: build-output
    path: dist/  # Must match your actual build directory
```

### Keystore Decoding Error

**Symptom:** Deploy fails at restore step
```
Error: gzip: stdin: not in gzip format
```

**Solution:** Re-encode keystore correctly:
```bash
cd ~/.zhtp
tar -czf - keystore | base64 -w 0 > keystore-secret.b64
```

Ensure no line breaks in the GitHub secret.

### Domain Not Found

**Symptom:** Deploy succeeds but site not accessible
```
Error: Domain 'mysite.sov' not registered
```

**Solution:** Register domain first using zhtp-cli:
```bash
zhtp-cli domain register mysite.sov
```

### SPKI Pinning Failure

**Symptom:** Connection fails during deploy
```
Error: Server SPKI mismatch
```

**Solution:** Verify `ZHTP_SERVER_SPKI` secret is current. Contact network administrators if issue persists.

### Permission Denied

**Symptom:** Deploy rejected
```
Error: Keystore identity not authorized for domain
```

**Solution:** Ensure keystore identity owns the domain:
```bash
zhtp-cli domain info mysite.sov
```

If ownership incorrect, transfer domain or use correct keystore.

## Support

### Documentation
- [CLI Reference](./CLI_REFERENCE.md)
- [Domain Management](./DOMAIN_MANAGEMENT.md)
- [Network Architecture](./ARCHITECTURE.md)

### Community
- GitHub Issues: [Report bugs](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues)
- Discussions: [Ask questions](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/discussions)

### Network Status
- Status Page: `https://status.sovereign.network`
- Incident Reports: Check GitHub Issues with `incident` label

## Examples

### Example 1: Static Blog

```yaml
name: Deploy Blog

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: site
          path: public/

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: site
          path: out/
      - name: Deploy
        run: |
          # ... (standard deployment steps)
          /tmp/zhtp-cli deploy site \
            --domain "myblog.sov" \
            --keystore ~/.zhtp/keystore \
            --mode "static" \
            out/
```

### Example 2: React SPA

```yaml
name: Deploy React App

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm run build
      - run: npm run test
      - uses: actions/upload-artifact@v4
        with:
          name: react-app
          path: build/

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: react-app
          path: out/
      - name: Deploy
        run: |
          # ... (standard deployment steps)
          /tmp/zhtp-cli deploy site \
            --domain "myapp.sov" \
            --keystore ~/.zhtp/keystore \
            --mode "spa" \
            out/
```

## Next Steps

1. **Test your deployment** - Use a staging domain first
2. **Set up monitoring** - Track deployment success/failure
3. **Configure CD** - Automate deployments on merge to main
4. **Document your setup** - Help your team understand the workflow
5. **Join the community** - Share your experience and help others
