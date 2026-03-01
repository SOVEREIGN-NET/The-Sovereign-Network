<!--
⚠️ CRITICAL: All PRs must target `development` branch
🚫 DO NOT target `main` - release process handles main merges
-->

## Target Branch Check
- [ ] I have selected `development` as the target branch (NOT `main`)

## Branch Policy
| Branch | Purpose | Who Merges |
|--------|---------|------------|
| `development` | Active development, feature integration | Anyone with approval |
| `main` | Production releases only | Release manager only |

## Type of Change
- [ ] Bug fix (non-breaking)
- [ ] New feature
- [ ] Breaking change
- [ ] Refactoring
- [ ] Documentation
- [ ] Other: ___

## Related Issues
Fixes #(issue number)

## Description
<!-- Describe your changes -->

## Testing
- [ ] `cargo check --workspace` passes
- [ ] `cargo test --workspace` passes
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated (if needed)
- [ ] No direct merges to `main`

## Type Architecture Check (for type-related changes)
- [ ] New data types are in `lib-types` (not domain crates)
- [ ] Behavior is in domain crates via extension traits (`<Type>Ext`)
- [ ] No duplicate type definitions across crates
- [ ] Domain crates re-export from `lib-types` for backward compatibility
- [ ] Serialization stability considered for consensus-relevant types
- [ ] See [lib-types/README.md](lib-types/README.md) for full architecture rule

## For Maintainers Only
> ⚠️ **DO NOT MERGE TO MAIN** - This PR must target `development`
> 
> If this PR accidentally targets `main`, change it to `development` before merging.
