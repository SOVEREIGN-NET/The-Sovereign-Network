# Web4 Quick Start

Get your site deployed to the Sovereign Network in 5 minutes.

## Step 1: Get Your Keystore (30 seconds)

Your keystore is your identity on the network. If you don't have one:

```bash
# Install zhtp-cli
curl -L https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases/latest/download/zhtp-cli-linux-x86_64.tar.gz | tar -xz
sudo mv zhtp-cli /usr/local/bin/

# Create identity
zhtp-cli identity create --keystore ~/.zhtp/keystore

# Backup immediately!
tar -czf - ~/.zhtp/keystore | base64 -w 0 > keystore-secret.b64
```

Save `keystore-secret.b64` - you'll need it for GitHub Actions.

## Step 2: Register Domain (1 minute)

```bash
# Check if available
zhtp-cli domain check mysite.sov

# Register it
zhtp-cli domain register mysite.sov --keystore ~/.zhtp/keystore
```

Done! Your domain is registered.

## Step 3: Set Up GitHub Secret (1 minute)

1. Go to your repo: **Settings → Secrets and variables → Actions**
2. Click **New repository secret**
3. Name: `ZHTP_KEYSTORE_B64`
4. Value: Paste contents of `keystore-secret.b64`
5. Click **Add secret**

## Step 4: Add Workflow (2 minutes)

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Web4

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
          name: build-output
          path: dist/  # ← Change to your build folder

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build-output
          path: out/
      - run: |
          cd /tmp
          gh release download cli-v0.2.0 \
            --repo SOVEREIGN-NET/The-Sovereign-Network \
            --pattern 'zhtp-cli-linux-x86_64.tar.gz' \
            --pattern 'SHA256SUMS'
          sha256sum -c <(grep zhtp-cli-linux SHA256SUMS)
          tar -xzf zhtp-cli-linux-x86_64.tar.gz
          chmod +x zhtp-cli
        env:
          GH_TOKEN: ${{ github.token }}
      - run: |
          mkdir -p ~/.zhtp
          echo "${{ secrets.ZHTP_KEYSTORE_B64 }}" | base64 -d | tar -xzf - -C ~/.zhtp
      - run: |
          /tmp/zhtp-cli deploy site \
            --domain "mysite.sov" \
            --keystore ~/.zhtp/keystore \
            --mode "static" \
            --pin-spki "$ZHTP_SERVER_SPKI" \
            out/
        env:
          ZHTP_SERVER: ${{ secrets.ZHTP_SERVER }}
          ZHTP_SERVER_SPKI: ${{ secrets.ZHTP_SERVER_SPKI }}
```

**Customize:**
- Change `dist/` in the upload artifact step to your build folder (`build/`, `out/`, `public/`)
- Change `mysite.sov` in the deploy step to your domain

## Step 5: Deploy (30 seconds)

```bash
git add .github/workflows/deploy.yml
git commit -m "Add Web4 deployment"
git push
```

Watch the Actions tab. In ~2 minutes your site is live!

Visit: `https://mysite.sov`

---

## Common Build Folders

| Framework | Build Folder |
|-----------|--------------|
| Next.js | `out/` |
| Vite | `dist/` |
| Create React App | `build/` |
| Hugo | `public/` |

## SPA Mode

If your site uses client-side routing (React Router, Vue Router), change line 42:

```yaml
--mode "spa" \
```

## Troubleshooting

**"Domain not found"**
- Did you register it? `zhtp-cli domain check mysite.sov`

**"Keystore decode error"**
- Regenerate: `tar -czf - ~/.zhtp/keystore | base64 -w 0 > keystore-secret.b64`
- No line breaks in the GitHub secret!

**"Build failed"**
- Check your build script: `npm run build` works locally?
- Correct build folder in workflow?

## Next Steps

- [Full Deployment Guide](./WEB4_DEPLOYMENT_GUIDE.md) - Advanced configuration
- [Domain Management](./DOMAIN_MANAGEMENT.md) - Transfer, renew, DNS records
- [Examples](https://github.com/SOVEREIGN-NET/web4-examples) - Sample projects

## Need Help?

- [GitHub Discussions](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/discussions)
- [Report Issues](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues)

---

**That's it!** Your site is now on Web4 with quantum-resistant security and decentralized hosting.
