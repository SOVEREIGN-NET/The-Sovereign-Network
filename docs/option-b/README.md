# Option B Plan: QUIC Transport, UDP Discovery-Only, No TCP

## Status
In progress.

## Target Invariants (the "law")
- All application payloads MUST run over QUIC (tickets, envelopes, RPCs, sync, everything meaningful).
- UDP is permitted only for link-local discovery (multicast announcements + optional unicast replies).
- TCP is forbidden in default builds. If kept, it exists only behind feature = "legacy_tcp" and is never advertised unless enabled.
- Discovery advertisement MUST reflect reality: a node that cannot accept TCP must never advertise tcp.

## Phases and Tracking Issues
- Phase 0: Make QUIC-only peers not fail (fastest win)
  - docs/option-b/PHASE_0_ISSUE.md
- Phase 1: Remove TCP from bootstrap gatekeepers (or hard-gate it)
  - docs/option-b/PHASE_1_ISSUE.md
- Phase 2: Kill TCP preference in routing and type-level defaults
  - docs/option-b/PHASE_2_ISSUE.md
- Phase 3: Treat WiFi Direct as a legacy link, or re-home it
  - docs/option-b/PHASE_3_ISSUE.md
- Phase 4: UDP-based subsystems (DHT, ZDNS) get an explicit status
  - docs/option-b/PHASE_4_ISSUE.md
- Phase 5: Mesh config cleanup
  - docs/option-b/PHASE_5_ISSUE.md
