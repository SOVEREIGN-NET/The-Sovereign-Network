# CBE Compensation DAO Contracts — Data Schemas and Treasury Payout Flow (No Code)

Version: 1.0
Scope: Stable on-chain schema requirements and operational flow for payout execution.
This document is normative for contract implementers.

---

## A. Core Data Schemas (Stable ABI)

All schemas below are "stable ABI": changes require explicit versioning and migration strategy.
No free-text fields for reasons; use enums.

### A1) RoleDefinition
Represents a compensation-eligible role policy.

Required fields:
- role_id: unique identifier
- params_hash: hash of policy parameters for audit (role metadata snapshot)
- active: bool
- cap:
  - annual_cap: hard cap per period
  - lifetime_cap: hard cap across assignment lifetime (0 if unused)
  - bonus_cap: optional cap for bonuses (0 if unused)
  - uses_assignment_snapshot: bool (MUST be true for exec roles)

Rules:
- RoleDefinition updates MUST be delayed-effect (never same-epoch).
- RoleDefinition update MUST emit RoleUpdated with old and new params_hash.

### A2) Assignment
Binds a role to a principal.

Required fields:
- assignment_id: unique identifier
- role_id
- principal: on-chain principal (address or DID-bound key)
- valid_from_epoch
- valid_until_epoch (optional)
- suspended: bool

Assignment-level cap snapshots (REQUIRED for exec roles):
- snap_annual_cap: immutable ceiling per period for this assignment
- snap_lifetime_cap: immutable ceiling across assignment lifetime (0 if unused)
- consumed_lifetime: monotonically increasing

Rules:
- Assignment snapshots MUST NOT be mutable by governance.
- Suspension MAY ONLY block future payouts; it MUST NOT retroactively change accrued vesting.

### A3) CapLedger
Tracks monotonic "spent" values for cap enforcement.

Cap scopes:
- GlobalPool
- Role
- Assignment

Key:
- scope
- id (pool_id OR role_id OR assignment_id)
- period_id (e.g., fiscal year or epoch bucket)

Value:
- spent_amount (monotonic)

Rules:
- CapLedger increments MUST occur at grant time (payout request acceptance), not at vesting release time.
- CapLedger MUST be updated before vesting creation is finalized to prevent partial execution states.

### A4) ReasonCode (enum)
Purpose: replace narrative strings with immutable categories.

Minimum set (expand only by appending new values):
- BaseCompensation
- PerformanceBonus
- RoleAssignment (structural)
- RoleRevocation (structural)
- EmergencyPause / EmergencyUnpause
- Slashing (if supported)

Rules:
- ReasonCode is an enum only; no free text.

### A5) Event Enums (Stable ABI)
Events MUST be sufficient to reconstruct:
- policy at time X
- org chart at time X
- cap exposure and consumption
- why money moved
- overrides and emergency actions

Structural events (Role Registry):
- RoleCreated
- RoleUpdated (includes old and new params_hash)
- RoleAssigned (includes assignment_id + cap snapshots)
- RoleUnassigned
- RoleSuspended / RoleUnsuspended

Financial events (Treasury):
- PayoutRequested (epoch, assignment_id, role_id, principal, amount, reason_code, metrics_root, params_hash)
- VestingCreated (vesting_id, assignment_id, schedule, amount)
- VestingReleased (vesting_id, amount, remaining_locked)
- VestingRevoked (if supported)
- CapConsumed (scope, id, period, cap_before, cap_after, amount)

Governance/control events:
- CapAdjusted (scope, id, old, new, activates_at_epoch)
- EmergencyPause / EmergencyUnpause
- TreasuryRebalanced (only if cross-pool transfer is ever allowed)

Rules:
- Events MUST use fixed fields; avoid dynamic strings.
- If schema changes are needed, version by adding new event types or new payload versions, never by mutating existing meanings.

---

## B. Treasury.request_payout() — Normative Flow (No Code)

This describes the required order of checks and state updates.
Any deviation must be justified and reviewed as a security risk.

### Inputs (required)
- epoch_id
- assignment_id
- amount
- reason_code
- proposed_vesting_schedule (cliff + start + end expressed in epochs)

Context dependencies (read-only):
- role_registry: assignment + role definition
- epoch_clock: epoch closed?
- metric_book: finalized metrics_root for epoch + epoch params_hash
- cap_ledger: spent amounts for period

### Step 0: Authorization and pause
- MUST require caller == Compensation Engine contract principal.
- MUST reject if treasury paused.
- Emergency roles MAY ONLY pause/unpause; they MUST NOT call payout.

### Step 1: Epoch and metrics finality gating
- MUST require epoch is closed.
- MUST require metrics_root exists and is final for epoch.
- MUST require epoch params_hash exists (parameter snapshot).

### Step 2: Load assignment and validate eligibility
- MUST require assignment exists.
- MUST require assignment is active for epoch (within valid_from/valid_until).
- MUST reject if assignment suspended.
- MUST load RoleDefinition for assignment.role_id and require active role.

### Step 3: Idempotency check
- MUST reject if (epoch_id, assignment_id) already paid.
- The idempotency marker MUST be set exactly once per successful payout request.

### Step 4: Cap checks (hard fail on any breach)
Determine period_id for epoch_id.

Check all caps below before any funds are committed:

4.1 Global/Pool cap
- global_spent(period) + amount MUST be <= global_annual_cap(period)

4.2 Role cap (current policy)
- role_spent(period) + amount MUST be <= role.annual_cap(period)

4.3 Assignment snapshot cap (per period)
- assignment_spent(period) + amount MUST be <= assignment.snap_annual_cap(period)

4.4 Assignment lifetime cap snapshot (optional but supported)
- assignment.consumed_lifetime + amount MUST be <= assignment.snap_lifetime_cap (if non-zero)

### Step 5: Commit cap ledger updates (monotonic)
- MUST update CapLedger for GlobalPool, Role, and Assignment scopes.
- MUST emit CapConsumed events for each scope including cap_before and cap_after.
- MUST increment assignment consumed_lifetime (if tracked) as part of the same logical commit.

### Step 6: Emit "why funds moved" event
- MUST emit PayoutRequested including:
  - epoch_id
  - role_id
  - assignment_id
  - principal
  - amount
  - reason_code
  - metrics_root
  - params_hash

### Step 7: Vesting schedule validation (treasury enforces cliffs)
Treasury MUST validate the schedule against system policy:

- cliff_epoch MUST enforce Month-3 (liquidity) and Month-5 (equity movement) requirements.
- end_epoch MUST be >= start_epoch.
- Vesting MUST be monotonic.

If invalid, the payout MUST fail (and no partial state must remain).

### Step 8: Create vesting lock and emit event
- MUST create a vesting record/lock for (principal, amount, schedule).
- MUST emit VestingCreated including vesting_id, assignment_id, amount, schedule.

### Step 9: Finalize idempotency marker
- MUST set the "paid" marker for (epoch_id, assignment_id) as part of success completion.
- MUST NOT be set if any prior step fails.

---

## C. Assignment-Level Cap Snapshots — Required Behavior

### Definition
When an assignment is created, it stores immutable ceilings:
- snap_annual_cap
- snap_lifetime_cap (optional)

### Purpose
- Prevent retroactive policy drift from breaking existing obligations.
- Ensure governance policy changes apply prospectively.
- Provide direct audit answers: "What was the maximum liability for this person at assignment time?"

### End-state behavior under cap reduction (explicit)
If role annual cap is reduced after an assignment is created:
- Existing assignment keeps snap_annual_cap unchanged.
- Existing assignment continues to vest/payout up to its snapshot ceiling.
- New assignments use the updated role annual cap when created.
- Governance MUST NOT mutate snapshots.

---

## D. Contract Interface Expectations (Implementation-level)

No code, but required semantic guarantees:

Role Registry MUST provide:
- read assignment by assignment_id
- read role definition by role_id
- emit structural events with cap snapshots

Metric Book MUST provide:
- finalized metrics_root(epoch)
- epoch params_hash(epoch)
- append-only and finality guarantees

Epoch Clock MUST provide:
- is_closed(epoch)
- deterministic epoch numbering

Treasury MUST provide:
- request_payout() with flow above
- vesting create/release logic enforcing cliffs and monotonicity
- pause/unpause that cannot move value

Comp Engine MUST provide:
- deterministic compute for payout
- paid ledger per (epoch, assignment_id)
- only requests payout when metrics are final and epoch is closed
