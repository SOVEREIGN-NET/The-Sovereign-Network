---
name: "[EPIC] Enforce Pure BFT Consensus (Deterministic Finality)"
about: Epic template for BFT deterministic finality work
title: "[BFT-A][EPIC] Enforce Pure BFT Consensus (Deterministic Finality)"
labels: ''
assignees: ''

---

# EPIC: Enforce Pure BFT Consensus (Deterministic Finality)

## Context
The blockchain MUST operate exclusively as a **BFT chain with deterministic finality (Tendermint-like)**.

All Nakamoto / PoW / fork-choice logic is legacy or defensive code and MUST be removed or fully disabled.

This epic tracks the engineering work required to:
- Enforce a single coherent consensus model (Option A)
- Guarantee irreversible finality
- Eliminate all fork, reorg, or probabilistic behavior

## Non-Goals
- Tokenomics
- Governance policy
- UX / wallets
- Economics or incentives

## Required Invariants
- A block committed by ≥2/3 validators is final forever
- No chain reorganization after commit
- No longest-chain or cumulative-work logic
- Consensus does not depend on wall-clock time
- Validator membership is snapshot-based per height

## Scope
- Consensus engine
- Block acceptance logic
- Validator lifecycle & slashing
- Sync and bootstrap behavior
- Protocol upgrade paths

## Completion Criteria
- All issues linked to this epic are closed
- No code path allows Option B behavior
- Deterministic finality can be reasoned about formally
