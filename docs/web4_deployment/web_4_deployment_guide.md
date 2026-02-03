# WEB4 Deployment Guide

This guide covers full deployment details, CI behavior, and troubleshooting.

---

## Identity & Authority Model

- The network uses a **single identity model**
- One DID owns the domain and deploys content
- CI/CD uses the same identity via the keystore you provide

If CI can deploy, **you authorized it**.

---

## Required Secrets

| Secret | Purpose |
|------|--------|
| `ZHTP_KEYSTORE_B64` | Domain authority identity |
| `ZHTP_SERVER` | Network endpoint |
| `ZHTP_SERVER_SPKI` | TLS pin |

Missing any of these will cause deployment failure.

---

## Preflight Checklist (RUN LOCALLY)

```bash
zhtp-cli identity show --keystore ~/.zhtp/keystore
zhtp-cli domain info your-site.sov --keystore ~/.zhtp/keystore
ls -la dist/  # or build/out/public
```

Do not proceed until all checks pass.

---

## Deployment Modes

| Mode | Use Case |
|----|---------|
| `static` | Plain HTML/CSS |
| `spa` | Client-side routing frameworks |

SPA mode rewrites unknown paths to `index.html`.

---

## Example GitHub Actions Workflow (Static)

```yaml
- name: Deploy to Sovereign Network
  run: |
    zhtp-cli deploy \
      --domain your-site.sov \
      --path dist \
      --mode static
```

---

## Example GitHub Actions Workflow (SPA)

```yaml
- name: Deploy to Sovereign Network
  run: |
    zhtp-cli deploy \
      --domain your-site.sov \
      --path dist \
      --mode spa
```

---

## Common Failures

### Domain Not Found
- Verify ownership:
```bash
zhtp-cli domain info your-site.sov
```

### TLS / SPKI Error
- Check `ZHTP_SERVER_SPKI`
- Ensure it matches network-provided value

### Blank Page on Refresh
- Use `--mode spa`

---

## Security Reality

- Anyone with the keystore can deploy
- CI is trusted because you placed the keystore there
- This mirrors SSH keys and wallet signing models

There is no role abstraction by design.

