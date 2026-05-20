# Node Operator Control Panel — Design Spec

> Epic: #2594 — "Node Operator Control Panel — full node lifecycle from the UI".
> Status: **planned** (next sprint). This is a forward-looking design spec;
> API shapes and UI layout below are proposals to be confirmed during
> implementation of each sub-item.

## 1. Scope summary

Give node operators end-to-end control of their node from the web UI —
register it, watch it sync, see what it earns, run it, and apply updates
safely — without ever touching a terminal.

The work extends the existing `setup.html` / `setup_ui.rs` UI. It builds
on the node-local reward ledger (#2586) and the consensus sync /
catch-up machinery. The common foundation is a **node-status /
node-control API surface** that the UI polls and drives; most sub-items
add one endpoint group plus one UI panel.

## 2. Sub-deliverables

| Item | Issue | Deliverable |
|------|-------|-------------|
| T1 | #2595 | Node registration panel — generate/import node identity, submit registration, show `pending → registered → active`. |
| T2 | #2596 | Node status & health dashboard — run state, role, height, peers, uptime, version. Foundational API surface. |
| T3 | #2597 | Sync progress view — local vs network height, rate, ETA, sync state. |
| T4 | #2598 | Rewards & earnings panel — earnings by activity (routing / relaying / consensus / storage), totals, history. |
| T5 | #2599 | Node lifecycle controls — start/stop/restart with clean-stop, logs, config. |
| T6 | #2600 | Update detection & notification — node polls a signed release manifest, UI banner on a newer version. |
| T7 | #2601 | Guided update & relaunch wizard — clean stop → install → restart → resync → verify, with rollback. |

### Sequencing

```
T1  (standalone)
T2  ──▶ T3
    └─▶ T5
T4  (standalone)
T6  ──▶ T7   (T7 also reuses T5 clean-stop + T3 resync view)
```

T2 lands first — it establishes the node-status/control API surface the
other UI panels poll. T1 and T4 are independent and can run in parallel.

## 3. Proposed API surface

All endpoints are node-local operator APIs (served by the node to its
own operator UI), versioned under `/api/v1/node/`. Shapes are proposals.

| Endpoint | Item | Purpose |
|----------|------|---------|
| `GET  /api/v1/node/status` | T2 | run state, role, height, peer count, uptime, version |
| `GET  /api/v1/node/sync`   | T3 | local height, observed network height, blocks/sec, ETA, sync state |
| `GET  /api/v1/node/rewards`| T4 | earnings grouped by activity, running totals, history series |
| `POST /api/v1/node/control`| T5 | `{ "action": "start | stop | restart" }` — clean-stop enforced |
| `GET  /api/v1/node/logs`   | T5 | recent log tail |
| `GET  /api/v1/node/config` | T5 | current effective config (read; edit scoped per T5) |
| `GET  /api/v1/node/update` | T6 | current version, available version, changelog |
| `POST /api/v1/node/update/apply` | T7 | drive the guided update steps; reports per-step progress |

Node registration (T1) reuses the **existing** node registration
transaction / endpoint — no new chain logic is expected.

**Existing node-control endpoints.** The node already exposes verb-specific
control routes — `/api/v1/node/shutdown`, `/api/v1/node/force-sync`,
`/api/v1/node/halt-consensus`. T5 must decide whether `POST /api/v1/node/control`
*replaces/aliases* these (single action endpoint) or is an *additional*
surface alongside them; the spec proposes consolidating onto `control` to
avoid a diverging API, but this is T5's call to confirm.

### Authentication

These endpoints control the node and MUST NOT be world-reachable. They
are gated to the local operator only — bound to loopback and/or behind
the operator session the UI already establishes. Confirm the exact gate
during T2 (it sets the pattern for T3/T5).

## 4. UI layout

New panels in `setup.html`, wired in `setup_ui.rs`, following the panel
pattern used by the observer-admission UI work (#2527/#2528):

- **Register** (T1) — identity generate/import + registration state.
- **Status** (T2) — health summary card; always visible once a node exists.
- **Sync** (T3) — progress bar; prominent while catching up, collapses to
  a "synced" badge once caught up.
- **Rewards** (T4) — total + per-activity breakdown + history chart.
- **Controls** (T5) — start/stop/restart buttons (destructive actions
  require explicit confirmation), logs viewer, config viewer.
- **Update banner** (T6) — non-intrusive, shown only when a newer version
  exists; links into the T7 wizard.
- **Update wizard** (T7) — modal/stepper driving the five update steps
  with live per-step status.

## 5. Per-item acceptance criteria

### T1 — Node registration panel (#2595)
- Operator can generate a new node identity or import an existing one.
- Registration state shown through `pending → registered → active`.
- Re-opening for an already-registered node is idempotent (no duplicate).
- Rejections (insufficient funds, duplicate) surface a clear error.

### T2 — Node status & health dashboard (#2596)
- `GET /api/v1/node/status` returns run state, role, height, peer count, uptime, version.
- UI panel polls and renders live; clearly distinguishes running vs stopped.
- Endpoint is sane mid-startup and when stopped — no panic, clear state.
- Sourced from existing chain-tip / peer / version state, not duplicated.

### T3 — Sync progress view (#2597)
- While behind, UI shows local vs network height and a moving progress bar.
- Transitions cleanly to "synced" at the network tip.
- Surfaces a "sync stalled" hint when height does not advance for a window.
- Sourced from the existing catch-up / height-divergence machinery.

### T4 — Rewards & earnings panel (#2598)
- Total earned plus per-activity breakdown (routing / relaying / consensus / storage).
- History viewable per epoch / per day.
- Values reconcile with the on-chain / node-local reward ledger (#2586).
- Sensible empty state for a node that has not yet earned.

### T5 — Node lifecycle controls (#2599)
- Operator can start, stop, restart from the UI.
- Stop is graceful — consensus is halted before the process exits.
- Action results and failures surface clearly.
- Recent logs and current config are viewable.
- Stop/restart require explicit in-UI confirmation.

### T6 — Update detection & notification (#2600)
- Node detects a newer published version within a bounded interval and
  exposes target version + changelog.
- UI banner appears only when a newer version exists.
- The release manifest is integrity-protected (signed / pinned) — a
  tampered manifest cannot push a malicious version.
- Graceful when the manifest is unreachable (no crash, no false prompt).

### T7 — Guided update & relaunch wizard (#2601)
- Operator applies a detected update entirely from the UI.
- Steps: clean stop → install new binary → restart → resync → verify.
- Each step shows live progress; node is cleanly stopped before the swap.
- Post-restart, resync progress is shown and a healthy synced state confirmed.
- A failure at any step rolls back to the previous binary and leaves the
  node running — never bricked.
- The downloaded binary's integrity is verified before install.

## 6. Open questions

1. **Release manifest + publishing (T6).** T6 consumes a release manifest;
   the publishing side (how a release is cut, signed, and pushed into the
   manifest) is a prerequisite and currently does not exist. Decide whether
   it is an ops task tracked separately or folded into T6.
2. **Update binary delivery (T7).** Where node binaries are hosted and how
   they are fetched — same channel as the manifest, or separate.
3. **Multi-node operators.** Whether one UI instance manages a single node
   or several. This spec assumes single-node; revisit if not.
4. **Endpoint auth gate (§3).** Exact mechanism locking the `/api/v1/node/*`
   control endpoints to the local operator — settled during T2.
