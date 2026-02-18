# EPIC #1222 Lane: Execution Pipeline

Branch: `feature/epic-1222-exec-pipeline`

## Scope
- #1223 Wire contract runtime into canonical block processing
- #1224 Extend sync/import BlockExecutor for contract and DAO tx types
- #1228 Implement DAO proposal execution_params construction and validation

## Implementation Checklist
- [ ] Audit canonical block processing entry points for contract tx execution hooks
- [ ] Add parity tests: local commit path vs sync/import path
- [ ] Implement deterministic execution_params codec + validation guards
- [ ] Add regression tests for malformed execution_params and replay/import parity

## PR References
- Relates to #1222
- Relates to #1223
- Relates to #1224
- Relates to #1228
