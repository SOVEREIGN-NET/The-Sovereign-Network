---
name: "[BFT-A] Deterministic Finality Task"
about: Task template for BFT deterministic finality work
title: "[BFT-A][R#] <short, precise description>"
labels: ''
assignees: ''

---

## Title
[R#] <short, precise description>

## Category
- R1 Validator Lifecycle
- R2 Validator Set Snapshot
- R3 Finality Semantics
- R4 Crash Safety
- R5 Network Partition
- R6 Protocol Upgrade
- R7 Emergency Controls
- R8 Invariants & Observability
- R9 Negative Spec Enforcement

## Problem
Describe the unsafe or ambiguous behavior observed in the code.

Include:
- File(s)
- Function(s)
- Code path(s)

## Current Behavior
What the system does today.

## Required Behavior
What the system MUST do to satisfy BFT deterministic finality.

## Safety Impact
Explain how the current behavior can:
- Break safety
- Break liveness
- Cause equivocation
- Allow forks or reorgs

## Proposed Fix
High-level fix description (no implementation detail required).

## Acceptance Criteria
- [ ] Unsafe code path removed or disabled
- [ ] Invariant enforced in code
- [ ] No regression in consensus correctness
- [ ] Tests updated or added

## Notes
(Optional)
