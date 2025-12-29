---
name: "[BUG] Node or CLI Issue"
about: Report a bug in the ZHTP node, CLI, or Web4 system
title: "[BUG] "
labels: bug
assignees: ''

---

## Description

Clear description of what's broken. Include:
- What you were trying to do
- What you expected to happen
- What actually happened

## Steps to Reproduce

1. [First step]
2. [Second step]
3. [...]

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happened]

## Environment

- **Platform:** [macOS/Windows/Linux]
  - Version: [e.g., macOS 14.2, Ubuntu 22.04, Windows 11]
- **Rust Version:** [output of `rustc --version`]
- **Node/CLI Version:** [output of `./target/release/zhtp --version`]
- **Installation:** [source build / pre-built / Docker]

## Error Message

```
[Paste full error message/output here]
```

## Logs

```bash
# Run with debug logging:
RUST_LOG=debug ./target/release/zhtp node start --config my-node.toml
```

```
[Paste relevant log output]
```

## Additional Context

- Previous working version: [if known]
- Configuration changes: [any recent changes?]
- Network setup: [VPN, firewall rules, etc.]
- Related issues: [link to related #issues]

## Checklist

- [ ] Issue title includes `[BUG]` prefix
- [ ] Platform and version specified
- [ ] Reproduction steps are clear
- [ ] Full error message included
- [ ] No sensitive data in logs
