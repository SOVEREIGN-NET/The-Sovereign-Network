---
name: "[BFT-A] Removal Task (PoW/Fork/Longest-Chain)"
about: Removal template for Nakamoto or fork-choice components
title: "[BFT-A][R9] Remove <PoW / Fork / Longest-Chain Component>"
labels: ''
assignees: ''

---

## Title
[R9] Remove <PoW / Fork / Longest-Chain Component>

## Problem
This component introduces Nakamoto-style behavior that conflicts with BFT finality.

## Location
- File:
- Module:
- Function:

## Why This Is Unsafe
Explain how this logic:
- Enables fork selection
- Allows reorg after commit
- Depends on probabilistic finality

## Required Action
- [ ] Remove code entirely
- [ ] OR hard-disable behind compile-time flag
- [ ] OR guard with unreachable assertion

## Acceptance Criteria
- Component no longer influences block acceptance
- No fallback path exists
- BFT commit is the sole finality mechanism
