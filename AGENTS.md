# AGENTS.md

Purpose: define specialized engineering agents for The Sovereign Network so work can be split by domain without breaking consensus, determinism, or security.

## Global Rules (All Agents)

- Preserve consensus determinism. No logic may depend on wall clock, local cache, or non-canonical side effects.
- Keep one canonical mutation path per state domain.
- Never write consensus state outside block transaction boundaries.
- Treat replay protection and nonce continuity as consensus requirements.
- Prefer additive migrations with explicit compatibility behavior.
- Every change must ship with tests in the owning crate.

## Agent 0: Orchestrator Agent

Focus: intake, triage, sequencing, and cross-agent handoff control.

Owned surfaces:
- `AGENT_TASKS.md`
- cross-crate change plans
- integration acceptance matrix

Responsibilities:
- Convert requests into a scoped execution plan.
- Route work to exactly one primary domain agent plus optional reviewers.
- Block merges when an invariant owner has not signed off.

Done criteria:
- Scope, risks, and acceptance checks are explicit.
- All required domain agents completed signoff.

## Agent 1: Blockchain Core State Agent

Focus: canonical chain state and restart reconstruction.

Owned surfaces:
- `lib-blockchain/src/blockchain.rs`
- `lib-blockchain/src/execution/*`
- `lib-blockchain/src/snapshot.rs`

Responsibilities:
- Guarantee deterministic reconstruction from persisted canonical state.
- Ensure state transitions are replay-safe and node-consistent.
- Remove non-deterministic reconstruction paths.

Critical invariants:
- Restarted node state equals pre-restart committed state.
- Cross-node replay converges to the same state.

Done criteria:
- Restart equivalence tests pass.
- Cross-node replay determinism tests pass.

## Agent 2: Storage and Atomicity Agent

Focus: persistence correctness and transaction boundaries.

Owned surfaces:
- `lib-blockchain/src/storage/*`
- `lib-storage/*`

Responsibilities:
- Enforce `begin_block -> process -> append_block -> commit_block` semantics.
- Eliminate consensus writes outside active block transactions.
- Ensure crash safety reflects last fully committed block only.

Critical invariants:
- No out-of-transaction consensus writes.
- Commit atomicity behavior is explicit and tested.

Done criteria:
- Crash/recovery tests pass.
- No direct storage write paths bypass block transaction flow.

## Agent 3: Token Consensus Agent

Focus: canonical token execution for SOV and multi-token safety.

Owned surfaces:
- `lib-blockchain/src/transaction/validation.rs`
- `lib-blockchain/src/contracts/tokens/*`
- `lib-tokens/*` (shared primitives only, no independent consensus engine)
- `zhtp/src/api/handlers/token/*`

Responsibilities:
- Keep a single canonical token mutation path.
- Enforce nonce protection and replay consistency.
- Reject deprecated mutation paths (`ContractExecution` token mutations).

Critical invariants:
- Exactly one token execution model in consensus path.
- Nonce validation outcome does not depend on in-memory history.

Done criteria:
- Replay-after-restart nonce tests pass.
- Deprecated path rejection tests pass at API and consensus layers.

## Agent 4: Runtime/API Contract Agent

Focus: zhtp API surface and runtime consistency with consensus rules.

Owned surfaces:
- `zhtp/src/api/handlers/*`
- `zhtp/src/runtime/*`

Responsibilities:
- Prevent API routes from exposing non-canonical or unsafe execution paths.
- Keep request validation aligned with consensus validator behavior.
- Ensure typed transaction paths are the only mutation entrypoints.

Critical invariants:
- API cannot mutate consensus state through deprecated pathways.
- Runtime and consensus reject/accept decisions are consistent.

Done criteria:
- Handler-level regression tests for forbidden routes and valid typed flows pass.

## Agent 5: DAO and Governance Agent

Focus: governance proposal/vote/execution correctness and deterministic replay.

Owned surfaces:
- `zhtp/src/api/handlers/dao/*`
- `lib-blockchain/src/integration/consensus_integration.rs`
- `lib-governance/*`

Responsibilities:
- Keep DAO execution in canonical blockchain state path.
- Remove dual-engine governance divergence.
- Ensure delegation/proposal/vote state can be reconstructed from chain history.

Critical invariants:
- No secondary DAO engine mutating consensus state in parallel.
- Delegation/proposal/vote reconstruction is deterministic.

Done criteria:
- DAO restart/replay tests pass.
- Governance execution path is single-source.

## Agent 6: Identity and Wallet Agent

Focus: DID ownership, wallet authorization, and auth-linked consensus mutations.

Owned surfaces:
- `lib-identity/*`
- `lib-identity-core/*`
- identity/wallet handlers in `zhtp`

Responsibilities:
- Enforce identity ownership checks for sensitive actions.
- Maintain deterministic identity state updates.
- Keep wallet mapping rules explicit and testable.

Done criteria:
- Authn/authz tests cover privileged write paths.
- Identity/wallet replay behavior is deterministic.

## Agent 7: Consensus and Mempool Agent

Focus: proposal, validation ordering, and mempool admission safety.

Owned surfaces:
- `lib-consensus/*`
- `lib-mempool/*`
- consensus integration layer in `lib-blockchain`

Responsibilities:
- Align mempool admission with final consensus validation rules.
- Prevent inconsistent acceptance between precheck and block execution.
- Keep transaction ordering deterministic where required.

Done criteria:
- Admission-vs-validation parity tests pass.
- Deterministic block application tests pass.

## Agent 8: Security and Replay Assurance Agent

Focus: threat-model-driven review for consensus safety.

Owned surfaces:
- Cross-cutting review role across all crates.

Responsibilities:
- Review replay, double-spend, nonce bypass, and signature trust boundaries.
- Validate no consensus writes occur from non-canonical code paths.
- Review crash-consistency and rollback semantics.

Done criteria:
- Security review checklist completed for critical changes.
- No known consensus divergence vectors in changed paths.

## Agent 9: Economics and Fees Agent

Focus: fee model integrity and treasury/accounting correctness.

Owned surfaces:
- `lib-fees/*`
- `lib-economy/*`
- fee handling paths in `lib-blockchain`

Responsibilities:
- Keep fee calculation deterministic and versioned by protocol height.
- Ensure fee distribution and sinks are persisted and auditable.

Done criteria:
- Fee vector tests and distribution accounting tests pass.

## Agent 10: QA and Release Readiness Agent

Focus: production readiness gates for multi-token and contract deployment.

Owned surfaces:
- `scripts/validate-*.sh`
- test strategy across workspace
- release checklist docs

Responsibilities:
- Maintain critical acceptance suites for restart, replay, crash safety, and cross-node determinism.
- Define go/no-go criteria for enabling new token deployments beyond SOV.

Required gate checks:
- ContractExecution token mutation rejection.
- Restart equivalence for token state (balances, supply, nonces).
- Cross-node deterministic reconstruction.
- Nonce replay rejection after restart.
- Crash safety to last committed block.
- Single token execution engine in consensus path.

Done criteria:
- Gate suite green on target branch.
- Release recommendation documented with residual risks.

## Handoff Protocol

- Primary agent opens the change with explicit invariants.
- Secondary reviewer agent validates domain-specific risks.
- Security agent signs off on critical consensus changes.
- QA agent validates required gates before merge.

## Escalation Rules

- Any detected consensus divergence risk is a merge blocker.
- Any out-of-transaction consensus write path is a merge blocker.
- Any duplicate executable token or DAO engine in consensus path is a merge blocker.

## Standard Deliverables Per Change

- Scope summary.
- Invariants affected.
- File-level diff map.
- Tests added or updated.
- Risk note and rollback strategy.
