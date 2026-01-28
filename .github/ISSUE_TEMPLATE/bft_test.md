---
name: "[BFT-A] Consensus Invariant Test"
about: Test template for BFT deterministic finality invariants
title: "[BFT-A][R8] Add Test: <Invariant Description>"
labels: ''
assignees: ''

---

## Title
[R8] Add Test: <Invariant Description>

## Invariant
Describe the invariant being enforced.

Example:
- No two blocks can be committed at the same height

## Test Scenario
Describe the setup:
- Validator count
- Faulty behavior
- Expected outcome

## Expected Result
- Test MUST fail if invariant is violated
- Node MUST panic or halt

## Acceptance Criteria
- [ ] Test added
- [ ] Test fails on unsafe behavior
- [ ] Test passes after fix
