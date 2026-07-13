# DAO Launch v1 — Decision Register (Q1–Q10)

**Epic:** [#2799](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2799) — DAO Launch v1 (Sovereign Asset)  
**Status:** **Locked** (2026-07-13)  
**Companion:** [`sovereign-asset.md`](./sovereign-asset.md) (primitive design), [`dao-launch-bootstrap.md`](../ops/dao-launch-bootstrap.md) (operator runbook)

---

## Governing principle (locked)

> **Consensus owns economic rules; governance owns treasury decisions; the UI only exposes features the protocol can enforce.**

No economic rule should exist only in the CLI, mobile application, registry, or operator runbook. If it affects supply, balances, ownership, fees, or authorization, the **executor must enforce it deterministically**.

Leaving Q1–Q10 open was already causing divergent implementations and replay risk. This register is the authoritative lock set for implementation.

---

## Numbering collision (read this first)

**Two different `Qn` namespaces exist in the repo.**

| Namespace | Where | Example Q1 | Example Q7 |
|-----------|--------|------------|------------|
| **Epic #2799 (this doc)** | Child issues P2, P8–P11, M2 | Post-launch mint & class-based split | `dao_class` NP/FP economics |
| **`sovereign-asset.md` §11** | SA primitive open questions | Symbol tombstone after sunset | Token-weighted governance (out of scope v1) |

When an issue says “Blocked by Q7”, it means **epic Q7** (non-profit economics), not token-weighted votes from the arch doc. Prefer renaming arch-doc items to `SA-Q*` in a follow-up doc pass to eliminate ambiguity.

---

## Executor persistence checkpoint (locked)

**Decision:** Validator registration persistence follows the **identity-registration pattern**.

| Layer | Responsibility |
|-------|----------------|
| `apply_tx` | Validates and updates deterministic execution state as required |
| Blockchain-layer **metadata batch** | **Single** durable write for validator records |
| Executor persistence | **Intentional no-op** |

**Explicitly rejected for validators:**

- Temporary dual-write paths
- Divergence detectors between executor and finalization
- Copying the current **observer** persistence path (treat observer inconsistency as technical debt to eliminate, not a pattern to extend)

**Reason:** Consensus-critical persistence must have **one owner** and **one atomic commit boundary**. Splitting storage between executor and block finalization creates ambiguity during replay, rollback, partial failure, and future migrations.

---

## Final locked set

| Question | Decision |
|----------|----------|
| Executor validator persistence | Blockchain-layer metadata batch only |
| **Q1** | Fixed rejects mint; elastic uses mandatory **class-based** split |
| **Q2** | Governance-controlled treasury; no hard-coded spending categories |
| **Q3** | Dedicated delegate float funded **explicitly** from treasury |
| **Q4** | Keep current consensus `RewardClaim` (spend delegate) |
| **Q5** | Keep decrease timelock on rewards policy |
| **Q6** | Keep rewards state on-chain |
| **Q7** | FP = 80/20; NP = 100% treasury; `dao_class` stored on-chain |
| **Q8** | Transfer-only true burn; governance-timelocked; capped |
| **Q9** | Curve-derived price; derived APY; registry-level welfare sector |
| **Q10** | Separate domain tx; 100 native SOV to protocol treasury |

### Summary table

| ID | Topic | Status | Unblocks |
|----|--------|--------|----------|
| **Q1** | Post-launch mint & class-based split | **Locked** | P2 #2801 |
| **Q2** | Treasury spend authorization | **Locked** | P10 #2809 |
| **Q3** | Rewards funding | **Locked** | P10 #2809 |
| **Q4** | Rewards spend-delegate settlement | **Locked** (shipped) | — |
| **Q5** | Rewards policy decrease timelock | **Locked** (shipped) | — |
| **Q6** | Rewards state on-chain only | **Locked** (shipped) | — |
| **Q7** | `dao_class` NP/FP economics | **Locked** | P8 #2807, M2 #2827 |
| **Q8** | Per-transfer burn | **Locked** | P9 #2808, M2 #2827 |
| **Q9** | Curve / APY / welfare sector | **Locked** | M2 #2827 Phase 4 |
| **Q10** | Domain binding & claim fee | **Locked** | P11 #2810 |

---

## Q1 — Post-launch mint and treasury split

**Status:** **Locked — Option B, with `dao_class` determining the split**

**Blocks:** [P2 #2801](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2801)

### Fixed supply

After launch:

- **Reject all net-new mint transactions.**
- Governance **must not** bypass fixed supply.
- A future conversion from `Fixed` → `Elastic`, if ever supported, must be a **separate explicit protocol upgrade with a timelock** — not an ordinary mint authorization.

### Elastic supply

Every net-new mint must follow the asset’s canonical **class-based** allocation:

| Class | Recipient | Treasury |
|-------|-----------|----------|
| **FP** (for-profit) | 80% designated recipient | 20% DAO treasury |
| **NP** (non-profit) | — | 100% DAO treasury |

Applies to:

- Curve-generated supply
- Governance-authorized inflation
- Any transaction that increases `total_supply`

### Implementation requirement

- **One shared `mint_and_allocate()` consensus function** for all supply increases.
- Do **not** implement separate split logic in curve, governance, and executor paths.
- A governance proof **authorizes the mint**; it does **not** authorize bypassing the economic split.

---

## Q2 — Treasury spend rules

**Status:** **Locked — governance-controlled treasury, unrestricted purpose at consensus level**

**Blocks:** [P10 #2809](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2809)

### Rules

- The treasury allocation must **not** be immediately spendable by the creator or by a plain treasury private key.
- Canonical `treasury_key_id` resolves to a **deterministic DAO-controlled authority** derived from the DAO governance configuration.
- Treasury spending requires:
  - valid governance authorization;
  - configured approval threshold;
  - ordinary balance and transaction validation.

### What consensus must not do

Do **not** hard-code spending categories (grants, rewards, domain fees, reserves, welfare programs) into consensus. That embeds current product assumptions into the protocol.

| Consensus answers | Consensus does not answer |
|-------------------|---------------------------|
| “Was this transfer validly authorized by the DAO?” | “Was this transfer a good use of treasury funds?” |

### Creator-supplied treasury address

May be accepted **only** when it represents the configured governance authority. It must **not** provide a hidden unilateral escape route.

---

## Q3 — Rewards funding

**Status:** **Locked — dedicated spend-delegate float, funded explicitly from treasury**

**Blocks:** [P10 #2809](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2809)

### Flow

1. DAO governance authorizes a **treasury transfer**.
2. Treasury funds the **rewards spend delegate**.
3. Delegate signs consensus `RewardClaim` transactions.
4. Claims debit the **delegate balance** (not the general treasury per claim).

Do **not** automatically carve another percentage out of the initial creator/treasury allocation at launch. The launch split stays canonical and understandable.

### Underfunding

| Situation | Behavior |
|-----------|----------|
| Launch with rewards configured, delegate unfunded | **Valid** — launch must not reject |
| Claim against underfunded delegate | **Deterministic failure:** `InsufficientRewardLiquidity` (protocol-level) |
| API | Expose as valid economic state — **not** generic 503 |
| CLI / UI | Show clearly: **“Rewards configured, but not funded.”** |

---

## Q4 — Rewards spend-delegate settlement

**Status:** **Locked — keep; no reopening**

- Consensus `RewardClaim` signed by the on-chain spend delegate.
- Policy validated via `policy_hash` / DHT document.
- Shipped: P4, P5, N2, N3, N4.

Reopen only if a concrete security or consensus defect is discovered.

---

## Q5 — Rewards policy decrease timelock

**Status:** **Locked — keep; no reopening**

- Decrease-only policy updates queue `pending_policy` with timelock (`REWARDS_POLICY_DECREASE_TIMELOCK_BLOCKS` = 7200).
- Shipped: P7.

---

## Q6 — Rewards eligibility storage

**Status:** **Locked — keep; no reopening**

- Eligibility, streaks, history, and deduplication remain **on-chain** consensus state.
- Node-local `rewards.sled` retired (N4).

---

## Q7 — Non-profit and for-profit `dao_class`

**Status:** **Locked — consensus data; changes initial and future mint allocation**

**Blocks:** [P8 #2807](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2807), [M2 #2827](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2827)

### For-profit (FP)

| Event | Allocation |
|-------|------------|
| Initial launch | 80% creator / 20% treasury |
| Every future elastic mint | 80% designated recipient / 20% treasury |

### Non-profit (NP)

| Event | Allocation |
|-------|------------|
| Initial launch | **100% treasury** (no direct creator allocation) |
| Every future elastic mint | **100% treasury** |

This is a **meaningful protocol distinction**, not a cosmetic registry label.

### Storage (required)

`dao_class` must exist in:

1. `AssetLaunchPayloadV1`
2. Canonical `SovereignAsset` state
3. Registry projections **derived from chain state**

The registry must **not** independently default or override class. Remove current registry-only / default-`fp` behavior.

### Staking proof

**Do not require** staking proof for DAO launch v1.

Existing `PendingDao` / SOV staking may later become admission, discovery/ranking, or a launch prerequisite in a **subsequent version**. Do not mix into this launch primitive until economic and slashing semantics are fully defined.

---

## Q8 — Per-transaction burn

**Status:** **Locked — optional transfer burn only; burned supply destroyed**

**Blocks:** [P9 #2808](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2808), M2

### v1 semantics

| Rule | Value |
|------|-------|
| Applies to | **Transfers only** (not mints) |
| Burned atoms | Reduce `total_supply` — **not** routed to treasury |
| Sender debited | Full submitted transfer amount |
| Recipient receives | `amount - burn` |
| Formula | `burn = floor(amount × burn_bps / 10_000)` |

Routing burn proceeds to treasury is a **transfer tax**, not a burn. Keep concepts separate.

### Governance changes

Any change to `burn_bps` is **timelocked** (increases **and** decreases). Both materially affect token economics and deserve visible advance notice.

### Caps

| Parameter | Value |
|-----------|-------|
| Default | `0` |
| Protocol maximum | **1000 bps (10%)** per transfer |

DAOs needing more aggressive mechanics should use a **specialized module**, not unrestricted transfer burn.

---

## Q9 — Curve, staking APY, and welfare sector

**Status:** **Locked — three distinct concepts (not one launch-economics bundle)**

**Blocks:** M2 Phase 4

### Initial price

- Valid **only** when a **curve module** is enabled.
- Must be **derived** from curve configuration and reserve state.
- Must **not** be an independent display field that contradicts protocol economics.
- **Fixed-supply, no curve:** no canonical protocol “initial price”; UI must not present one as guaranteed.

### Staking APY

- **Calculated display value** from on-chain staking parameters when integrated.
- Do **not** store promised APY as arbitrary marketing metadata.
- UI may show **estimated** APY from emission rate, staked amount, duration, protocol assumptions — labelled **variable and derived**.
- Until on-chain staking is integrated: field stays **disabled**.

### Welfare sector

- **Registry-level classification** with optional canonical sector identifier.
- Binds DAO to existing sector/root registry record; supports discovery and governance organization.
- Does **not** alter monetary consensus rules in v1.
- May appear in launch payload as optional registry reference; launch validity must **not** depend on mutable external content.

---

## Q10 — Domain binding and claim fee

**Status:** **Locked — separate `DomainRegister` tx; launch workflow may bundle UX only**

**Blocks:** [P11 #2810](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2810)

### Transaction model

- **Do not** place domain registration inside `AssetLaunch` (different failure conditions and lifecycle).
- CLI / mobile may present one **workflow**:
  1. Submit `AssetLaunch`
  2. Wait for finality
  3. Submit `DomainRegister` referencing `asset_id`

### Fee

| Field | Value |
|-------|-------|
| Denomination | **Native SOV only** |
| Amount | **100 SOV** (v1 standard claim; governance may reconfigure later) |
| Sink | **Protocol treasury** |
| Not allowed | Bridged token, DAO token, burn |

Native SOV prevents every DAO from inventing circular payment mechanics for scarce global namespace.

### Failure behavior

| Outcome | Rule |
|---------|------|
| Domain registration fails | DAO launch **remains valid** |
| Fee | Charged **only** if domain tx succeeds |
| Retry | User may retry same or different domain |

### Domain record binds

- Normalized domain
- `asset_id`
- Controlling governance authority
- Registration height
- Renewal / expiry policy (once defined)

---

## UI / protocol conflicts (C1–C10)

Epic guiding principle: protocol wins; UI adapts (notably **C6, C7**).

| ID | Conflict | Resolution after lock |
|----|----------|------------------------|
| **C1** | Launch command completeness | Phase 3 largely shipped; align with Q7 on-chain `dao_class` |
| **C2** | `new_partner` amount discrepancy | **Resolved** (D1) |
| **C3** | Identity / keystore | **Resolved** (C3) |
| **C4** | Rewards API vs chain | **Resolved** (Q4–Q6) |
| **C5** | Governance CLI vs proof validation | **Partial** — finish P6 `GovernanceProof` |
| **C6** | Unsupported economic fields | **Unlock per rule:** Q7/Q8/Q9 + implementation order below |
| **C7** | Stricter UI validation | **Resolved** — `validate_dao_launch_ui_constraints()` |
| **C8** | Registry class vs launch | **Resolved by Q7** — class on-chain; registry projects only |
| **C9** | Template preview vs executor | Split/allocations via executor; APY display-only per Q9 |
| **C10** | Domain in launch flow | **Resolved by Q10** — separate tx, unified UX workflow |

---

## Implementation order (locked)

Execute in this sequence. Do not enable advanced UI fields until the corresponding chain rule ships.

1. Add canonical **`dao_class`** to `AssetLaunchPayloadV1` and `SovereignAsset` state.
2. Centralize all supply increases in one **class-aware `mint_and_allocate()`** function.
3. Enforce **fixed-supply mint rejection** (Q1).
4. Introduce **governance-controlled treasury authorization** (Q2).
5. Formalize **rewards delegate funding** and `InsufficientRewardLiquidity` (Q3).
6. Add **transfer-burn** semantics with timelock and cap (Q8).
7. Add **`DomainRegister`** as separate transaction + 100 SOV fee (Q10).
8. Enable M2 Phase 4 UI fields only after their chain rules exist (Q9 sub-items).

**Parallel / already in flight:** P6 governance proof validation (C5); validator persistence refactor per executor checkpoint above.

---

## Delivery phases (epic)

| Phase | Scope |
|-------|--------|
| **1** | Minimal launch (name, symbol, supply, treasury) |
| **2** | Schemas, templates, rewards policy, discovery |
| **3** | Full `dao launch` flags, governance CLI, mobile submit |
| **4** | Advanced UI (burn, NP split, curve price, welfare) — **gated on implementation order** |

---

## Sovereign Asset primitive (D1–D10)

Unchanged; see [`sovereign-asset.md` §2](./sovereign-asset.md). Epic Q1–Q10 extend D2/D3 with **economic enforcement** detail.

---

## Change log

| Date | Change |
|------|--------|
| 2026-07-13 | Initial draft from epic child issues and codebase |
| 2026-07-13 | **Locked** full Q1–Q10, executor persistence checkpoint, implementation order, governing principle |