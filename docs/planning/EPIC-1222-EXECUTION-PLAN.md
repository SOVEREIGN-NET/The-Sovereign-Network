# EPIC #1222 Execution Plan

This document tracks parallel delivery for:
- https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/1222

## Git Flow Lanes

1. `feature/epic-1222-api-schema`
- Scope: #1227, #1229
- Goal: align DAO client/server schemas and unblock canonical DAO propose/vote flows
- PR: TBD

2. `feature/epic-1222-exec-pipeline`
- Scope: #1223, #1224, #1228
- Goal: execution-path parity for contract + DAO transaction types
- PR: TBD

3. `feature/epic-1222-e2e`
- Scope: #1232
- Goal: multi-node E2E coverage for deploy/call/propose/vote/execute lifecycle
- PR: TBD

## Semantic Commit Convention

- `feat(scope): ...` for capability additions
- `fix(scope): ...` for behavior corrections
- `test(scope): ...` for new/updated tests
- `docs(scope): ...` for documentation only changes

## PR Reference Template

Use in each PR description:

- `Relates to #1222`
- `Closes #<child-issue>` (when fully completed)
- Link sibling PRs in same epic lane
