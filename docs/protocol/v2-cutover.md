# v1 → v2 Cutover Runbook (CONS-605)

**Status:** Draft. Promote to **Approved** after operations review.
**Owner:** Operations + protocol leads.
**Audience:** Validator operators executing the cutover.

The Sovereign Network consensus rewrite (epic CONS-001..606) lands as a
**clean chain restart**, not an in-place upgrade. This document is the
operator-facing runbook for halting v1, deploying v2 binaries, and
booting v2 from genesis-v2.toml. v1 sled state is preserved at every
node for forensic recovery; nothing is wiped automatically.

## Why a clean restart, not an in-place upgrade

The consensus rewrite changes:
- The wire format for `ValidatorMessage` (CONSENSUS_PROTOCOL_VERSION
  bump from 1 to 2 — pinned by
  `lib-consensus-net/src/codec/mod.rs::tests::byte_stability::*`).
- The action-channel-driven engine (CONS-306 / CONS-307) — old nodes
  cannot interoperate with new nodes' broadcast envelopes.
- The `BlockFinalizationSink` finalization model (CONS-402 / CONS-504)
  — replaces the legacy `BlockCommitCallback`.

A heterogeneous quorum (some v1, some v2 validators) cannot reach BFT
finality across these breaks. Restart at a fresh genesis is simpler,
safer, and reversible if cutover fails.

## Pre-cutover checklist

Operators MUST complete every item before the cutover window opens.

- [ ] **Soak passed.** CONS-602 (#2360) 24h soak ran on a 4-validator
      and a 21-validator local network with all four scenarios
      (network partition, slow peer, slow disk, byzantine equivocation).
      Soak report posted to `docs/epics/consensus-rewrite-soak-report.md`
      with no unresolved findings.
- [ ] **CI ratchets green.**
      `cargo test -p architecture-invariants --tests` passes (CONS-603).
      `cargo test -p lib-consensus-net --lib byte_stability` passes
      (CONS-601 wire-format pin).
      `cargo test -p lib-consensus-runtime --lib` passes
      (watchdog + executor + catch-up sync tests).
- [ ] **genesis-v2.toml finalized.** The `[chain] genesis_time`
      replaced with the actual cutover datetime. Bootstrap council
      members + initial validator set populated from the v2 key
      ceremony. Operators have signed off on the validator-set list.
- [ ] **archive/genesis-v1.toml preserved.** This repo ships
      `archive/genesis-v1.toml` containing the exact bytes of the v1
      genesis. Verify the SHA-256 matches the v1-deployed bytes
      (operator-recorded at v1 launch).
- [ ] **Validator binaries built.** Every v2-participating validator
      has `cargo build --release --features validator` run against
      this repo's tip. Binary hashes recorded for chain-of-custody.
- [ ] **Node configs updated.** Every validator's node config points
      at `genesis-v2.toml`'s `chain_id = 2` and the new
      `bootstrap_council` members. v1 configs MUST NOT be reused —
      `chain_id = 1` against a v2 binary will refuse to start.
- [ ] **Cutover datetime announced.** Validators have ≥48 hours
      notice. The datetime is recorded in `[chain] genesis_time` of
      `genesis-v2.toml` AND in this section below.

## Cutover datetime

> **Set this when the date is finalized.** Until then the runbook is
> draft.

```
v2 genesis_time:  2026-05-01T00:00:00Z   (placeholder)
v1 halt height:   <to-be-recorded at halt step>
```

## Halt sequence (v1)

Run on every validator simultaneously at the announced cutover
datetime minus 30 minutes.

1. **Drain the mempool.** Stop accepting new transactions:
   ```
   zhtp-cli admin mempool-pause
   ```
   Confirm `mempool-pause` returns the new pending count = 0 within
   60 s.

2. **Wait for finality of in-flight blocks.** Watch the BFT-active
   height advance until it stops:
   ```
   zhtp-cli admin consensus-status --watch
   ```
   When the same height appears for 3 consecutive 12 s rounds and
   the round counter resets to 0, in-flight is drained.

3. **Halt consensus.** Issue the halt:
   ```
   zhtp-cli admin halt --reason "v2-cutover"
   ```
   The runtime transitions to `Halting{ resume_condition: ManualRestart }`
   per the FSM (CONS-301 ValidatorState). Record the halt height and
   block hash:
   ```
   zhtp-cli admin chain-tip > /var/log/zhtp/v1-halt-tip.json
   ```
   This artefact is the operator's proof of the v1→v2 boundary.

4. **Stop the node.** systemctl path:
   ```
   sudo systemctl stop zhtp.service
   ```
   sled is **preserved** automatically — never wipe at this step.

5. **Snapshot sled.** `cp -a` the sled directory to
   `~/zhtp/v1-snapshot-<halt-height>/`. This snapshot is the
   forensic record. If cutover fails it's also the rollback path.

## Deploy sequence (v2)

After every validator confirms step 4 of the halt sequence.

6. **Install v2 binary.** Replace the v1 binary at
   `/usr/local/bin/zhtp` with the v2 build. Hash check against the
   pre-cutover record.

7. **Replace genesis.** `cp genesis-v2.toml /etc/zhtp/genesis.toml`.
   The runtime loads `genesis.toml` by path; the v2 file's
   `chain_id = 2` is what makes the chain distinct.

8. **Move v1 sled out of the data dir.**
   ```
   mv /opt/zhtp/data/sled /opt/zhtp/data/sled.v1
   mkdir -p /opt/zhtp/data/sled
   ```
   v2 boots from an empty sled. The `sled.v1` directory is
   inviolable until step 12 declares cutover success.

9. **Update node config.** Every config file referencing
   `chain_id = 1`, the v1 bootstrap_council, or the v1 validator
   set must be updated to v2. Confirm with:
   ```
   zhtp-cli config validate /etc/zhtp/config.toml
   ```

10. **Start v2.** systemctl path:
    ```
    sudo systemctl start zhtp.service
    ```
    Watch the first 5 minutes of logs for:
    - `ConsensusRuntime starting (transport=zhtp-quic-mesh, watchdog_threshold=...)`
      — the runtime boots (CONS-502).
    - `BFT consensus loop started in BFT MODE` once ≥3 validators
      connect.
    - First block production: search for `BFT BLOCK COMMITTED`.

## Verification

Run on each validator after step 10. All checks must pass before
declaring success.

11. **Health gates.**
    - `zhtp-cli admin chain-tip` shows `chain_id = 2`, `height >= 1`.
    - `zhtp-cli admin validators` lists the v2 initial validator set.
    - The audit log has zero `WARN AD-011 collision` lines (the
      transport-idle / budget-ceiling check passed) — assumes the
      reconciliation in CONS-403's deferred follow-up landed.
    - `cargo test -p architecture-invariants --tests` green against
      the deployed tip. (Optional; run on a build host.)
    - The structured-tracing field
      `lib_consensus::engine.fsm_state` reaches `Committed{...}` and
      cycles to `Idle` for the next height — i.e. the FSM is making
      progress, not stuck in `Hung` or `Halting`.

12. **Declare success.** When every validator reports green for 1
    hour continuous, declare cutover success. Post an "OK at height
    N" message to the operator channel. Move on to step 13.

13. **Retain v1 archive.** `~/zhtp/v1-snapshot-<halt-height>/` and
    `/opt/zhtp/data/sled.v1/` are kept indefinitely as forensic
    record. Do NOT delete; storage cost is small relative to the
    cost of needing them and not having them.

## Rollback procedure (cutover failure)

If verification fails or the network cannot reach quorum within 1 hour
of step 10, rollback to v1:

R1. `sudo systemctl stop zhtp.service` on every validator.

R2. `mv /opt/zhtp/data/sled /opt/zhtp/data/sled.v2-failed`.
    `mv /opt/zhtp/data/sled.v1 /opt/zhtp/data/sled`.

R3. Reinstall the v1 binary from your pre-cutover archive. Replace
    `/etc/zhtp/genesis.toml` with `archive/genesis-v1.toml`.

R4. Revert config to the v1 chain_id + council.

R5. `sudo systemctl start zhtp.service`. Watch for v1 to resume from
    the halt height. Quorum should reform within 5 minutes if the
    halt was clean.

R6. File a postmortem in `docs/epics/consensus-rewrite-cutover-failure-<date>.md`
    with the failing health gate, captured logs, and the recovery
    timeline. Open a follow-up issue in the consensus-rewrite-v2
    label set with the failing acceptance criterion.

The `sled.v2-failed` directory is preserved like `sled.v1` — never
wipe, regardless of how confident the failure analysis feels.

## Post-cutover follow-ups

- Update `lib-consensus-runtime/src/runtime.rs::ConsensusRuntime::new`
  startup-check log to mention `chain_id = 2` in the
  AD-011-collision message (purely cosmetic; helps operators who hit
  the warning post-cutover.)
- Open the engine-migration tracking issue (CONS-508 follow-up) so
  `lib-consensus`'s remaining engine code moves into
  `lib-consensus-core::engine` and `lib-consensus-runtime` becomes
  the only top-level consensus crate.
- Schedule a 7-day post-cutover review: confirm no chain divergence,
  no Hung/Halting episodes, no AD-011 watchdog suppression.

## References

- CONS-606 (#2364): chain restart cutover (the execution side of this
  runbook).
- CONS-602 (#2360): soak report — must be green before cutover.
- CONS-603 (#2361): architecture-invariants ratchet.
- CONS-502 (#2352, closed): `ConsensusRuntime` — what's running after step 10.
- CONS-505 (#2355, closed): parallel orchestrator deletion — why v1
  binaries cannot interoperate with v2.
- AD-011: budget vs. transport-idle relationship (referenced by the
  startup check in step 11).
