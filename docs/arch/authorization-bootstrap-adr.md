# ADR: Authorization model — bootstrap → decentralized

**Status:** Proposed (bootstrap) — becomes Accepted when Phase 1 wallet-read enforcement lands under [#2935](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2935)  
**Date:** 2026-07-24  
**Epic:** [#2935](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2935)  
**Supersedes:** Identity ACL epic #2272 and children; DID UnifiedAccessControl track #227–#230; network PoQ research #2111 (as prerequisite for API privacy)

---

## Context

The network is **decentralized by design** but **operator-bootstrapped today**: council-run validators, a small on-chain council list, and one practical end-user principal (`Role::Citizen`). Access control work split across:

- `lib-access-control` (principal × relation × domain × op) — incomplete enforcement
- Older DID “UnifiedAccessControl” issues (#228–#230) — parallel, unused
- Wallet reads intentionally ungated for mobile compat (#2299)
- Roles `InfraAdmin` / `PolicyAdmin` / `Emergency` defined but never assigned

**Urgent:** any authenticated DID can read any wallet balance/list/stats/history.

---

## Decision

### 1. Three orthogonal axes (never collapse into one enum)

| Axis | Question | Where it lives |
|------|----------|----------------|
| **A. Subject kind** | What is this DID? | `IdentityType` (Human, Organization, Device, Agent, Contract) |
| **B. Principal role** | What may this session do at the API / mesh boundary? | `lib-access-control::Role` + capabilities / grants |
| **C. Economic authority** | What may this key sign on-chain? | Consensus (creator, governance proof, spend delegate, council txs, `dao_class` on assets) |

**DAO for-profit vs non-profit** is axis C (`dao_class` on `SovereignAsset`), not a DID kind and not an API role.

**Citizenship / AccessLevel** (Visitor, FullCitizen, …) remains product/eligibility state; it does not replace axis B for request authorization.

### 2. Bootstrap vs mature network

| Concern | Bootstrap (now) | Mature |
|---------|-----------------|--------|
| Root of trust | On-chain **Council** list + operator validators | Council / governance evolution |
| End users | Registered **Citizen** (Human DID) | Same + Organization / Device principals |
| Maintenance / ops team | **InfraAdmin** or **ScopedGrant** (not “everyone is Council”) | Same, audited grants |
| Cross-identity wallet privacy | **Must enforce** (default deny sensitive) | Same |
| System god-mode | Eliminate over time via ScopedGrant | No `Role::System` bypass |
| Mesh PoQ / network capabilities | **Out of scope** for Phase 1 | Optional later (was #2111 research) |

### 3. Principal assignment (live rules)

| Source | Role |
|--------|------|
| Unauthenticated | `Public` |
| Authenticated DID, not council | `Citizen` |
| Authenticated DID on council list | `Council` |
| Attested validator / registered node only | `Node` (never trust client-declared `x-node-type` alone) |
| Ops allowlist / grant (to implement) | `InfraAdmin` / `PolicyAdmin` / scoped capabilities |
| Bearer without bound DID | **Deny / Public** — not fake `Citizen` |

Device QUIC key → canonical DID binding remains required for owner-gated endpoints.

### 4. Default policy (axis B)

- **Default DENY** for unmatched (principal, relation, domain, op).
- **Self:** full access to own domains except `ZkProofPrivate`.
- **External Citizen:** public core identity only; **no** balances, wallet graphs, private metadata.
- **Council (bootstrap):** full audit read except `ZkProofPrivate`; admin endpoints Council-only until ScopedGrant.
- **Reads that must not 403 for UX:** return empty / zero / filtered body (see Phase 1) rather than erroring when product requires soft privacy.

### 5. Phase plan

#### Phase 1 — Stop the bleed (immediate)

1. Enforce wallet **read** filters: self or Council (or tx involvement for history); non-owners get empty/zero/types-only per #2299 model.
2. Feature flag: default **on** for new testnet deploys; document mobile must use own DID only (already true for primary UX).
3. Remove bearer → fake Citizen elevation.
4. Fail closed on unauthenticated NodeType headers (do not trust spoofable node role).
5. Regression matrix: self OK, cross-identity balance empty, Council full, writes still owner-gated.

#### Phase 2 — Bootstrap ops clearance

1. Assign **InfraAdmin** (config or on-chain ops list) separate from Council.
2. Gate halt/export/import/provision-class surfaces to Council | InfraAdmin.
3. Structured access-decision logging (denies INFO).
4. Subset of E2E matrix in CI.

#### Phase 3 — Mature access

1. **ScopedGrant**: council-issued, scoped, expiring; remove `Role::System` bypass.
2. Kill external raw identity getters; views only.
3. Per-edge graph traversal checks.
4. Wire Organization / Device principals and `SameDao` when identity types ship.
5. Optional mesh domain restrictions after Node attestation.

### 6. Non-goals

- Replacing `lib-access-control` with a second UnifiedAccessControl Permission mega-enum.
- PoQ / ZK quota as a blocker for wallet privacy.
- Treating WASM contract deploy permissions as part of Phase 1.
- Using Council membership as the only ops mechanism forever.

---

## Consequences

### Positive

- One vocabulary for product, protocol, and security.
- Bootstrap honesty: council and operators exist without pretending pure P2P privacy.
- Clear close path for duplicate GitHub issues.
- Phase 1 is implementable without full ScopedGrant.

### Negative / costs

- Mobile or any multi-identity explorer that scraped others’ balances will break (correct).
- Ops must get real InfraAdmin/grants instead of overusing Council keys.
- Phase 3 is large; must not block Phase 1.

### Compliance with existing crates

- Keep `SecurityPrincipal`, `AccessPolicy`, identity views.
- Extend assignment and **handler enforcement**; do not redesign the policy engine first.

---

## References

- `lib-access-control` (`Role`, `AccessDomain`, `AccessPolicy`)
- `zhtp/src/api/principal.rs` (`extract_principal_from_request`)
- Wallet ungated reads: historical #2299
- Sovereign assets / dao_class: `docs/arch/sovereign-asset.md`, `docs/arch/dao-launch-decision-register.md`
