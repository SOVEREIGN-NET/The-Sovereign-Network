# Sovereign Network - Project Board Guide

## Overview

This document explains how to use the GitHub Projects board for managing development in the monorepo.

---

## Repository Structure

**Repository:** [SOVEREIGN-NET/The-Sovereign-Network](https://github.com/SOVEREIGN-NET/The-Sovereign-Network)
**Default Branch:** `development`
**Architecture:** Monorepo (all libraries in one repository)

---

## Project Board Workflow

### Board Columns

1. **Backlog** - Future work, not yet prioritized
2. **Todo** - Prioritized, ready to work on
3. **In Progress** - Currently being worked on
4. **Review** - Code complete, awaiting review
5. **Done** - Merged and complete

### Moving Issues

- **Todo → In Progress:** When you start working on an issue
- **In Progress → Review:** When you open a PR
- **Review → Done:** When PR is merged
- **Done → Closed:** When work is verified in production

---

## Issue Organization

### Labels

- **`lib-identity`** - Identity and authentication work
- **`lib-proofs`** - Zero-knowledge proof work
- **`lib-crypto`** - Cryptography work
- **`lib-blockchain`** - Blockchain core work
- **`lib-network`** - Networking and mesh
- **`lib-consensus`** - Consensus mechanisms
- **`lib-economy`** - Economic models
- **`bug`** - Something isn't working
- **`enhancement`** - New feature or improvement
- **`documentation`** - Documentation updates
- **`alpha-blocker`** - Blocks alpha release

### Milestones

- **Alpha** - Must be done for alpha release
- **Beta** - Post-alpha features
- **V1.0** - Production release features

---

## Creating Issues

### Issue Template

```markdown
## Goal
[What needs to be accomplished]

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2

## Technical Details
[Implementation notes, file locations, dependencies]

## Definition of Done
- [ ] Code implemented
- [ ] Tests passing
- [ ] Documentation updated
- [ ] PR reviewed and merged
```

### Linking Issues

- Use `Closes #123` in PR description to auto-close issues
- Use `Relates to #123` to reference without closing
- Cross-reference between issues with `See #123`

---

## Branch Strategy

### Creating Feature Branches

```bash
# Create from development
git checkout development
git pull origin development
git checkout -b feature/your-feature-name

# Work on feature
git add .
git commit -m "feat: your feature description"

# Push to remote
git push origin feature/your-feature-name
```

### Branch Naming

- **Feature:** `feature/description`
- **Bug fix:** `fix/description`
- **Documentation:** `docs/description`
- **Refactor:** `refactor/description`

### Pull Requests

1. **Create PR** against `development` branch
2. **Link issue** in PR description (`Closes #123`)
3. **Request review** from team
4. **Merge** after approval (squash or merge commit)
5. **Delete** feature branch after merge

---

## Monorepo-Specific Workflow

### Working on Individual Libraries

```bash
# Build specific library
cargo build -p lib-identity

# Test specific library
cargo test -p lib-identity

# Run specific library tests
cargo test -p lib-identity -- --nocapture
```

### Cross-Library Changes

When changes affect multiple libraries:

1. **Create single issue** describing the change
2. **Label with all affected libraries** (e.g., `lib-identity`, `lib-proofs`)
3. **Make changes in one PR** to keep atomicity
4. **Test all affected libraries** before merging

### Testing Strategy

```bash
# Test all workspace
cargo test --workspace

# Test specific libraries
cargo test -p lib-identity -p lib-proofs -p lib-crypto

# Build entire workspace
cargo build --release --workspace
```

---

## Alpha Release Tracking

### Critical Path

Issues labeled `alpha-blocker` must be completed before alpha release.

**Current Alpha Blockers:**
1. Feature 2: Autonomous Mesh Networking (P1-7 complete ✅)
2. Proof Governance V0 (ProofEnvelope complete ✅)
3. Integration testing
4. Deployment scripts

### Alpha Checklist

- [x] P1-7 seed-anchored identity
- [x] Proof governance V0
- [ ] Feature 2 mesh networking integration tests
- [ ] Build and deployment scripts
- [ ] Alpha documentation
- [ ] Go/no-go decision

---

## Communication

### Issue Comments

- Tag team members with `@username`
- Reference code with backticks: `function_name()`
- Link to files: `lib-identity/src/identity/lib_identity.rs:278`
- Use checkboxes for task lists

### Status Updates

Update issues with progress:
- Daily updates for in-progress work
- Blockers immediately flagged
- ETA updates when timeline changes

---

## Quick Reference

### Common Commands

```bash
# Clone monorepo
git clone https://github.com/SOVEREIGN-NET/The-Sovereign-Network.git
cd The-Sovereign-Network

# Create feature branch
git checkout development
git checkout -b feature/my-feature

# Build and test
cargo build --workspace
cargo test --workspace

# Create PR
gh pr create --base development --title "feat: my feature"
```

### Useful Links

- [Main Repository](https://github.com/SOVEREIGN-NET/The-Sovereign-Network)
- [Project Board](https://github.com/orgs/SOVEREIGN-NET/projects)
- [Architecture Docs](./lib-identity/docs/adr/)
- [Alpha Strategy](./pm-docs/ZHTPPM/)

---

## Tips

1. **Keep issues focused** - One issue = one feature/bug
2. **Update regularly** - Move cards as status changes
3. **Close promptly** - Close issues when merged
4. **Test before PR** - All tests must pass
5. **Document decisions** - ADRs for architectural choices

---

## Need Help?

- Check existing issues for similar work
- Review ADR documents in `lib-*/docs/adr/`
- Ask in issue comments
- Tag relevant team members

---

**Last Updated:** 2025-11-30
