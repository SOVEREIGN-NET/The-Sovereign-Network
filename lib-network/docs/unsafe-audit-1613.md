# NETWORK-1 Unsafe Audit (Issue #1613)

Date: 2026-03-03
Branch: `fix/1613-audit-unsafe-blocks`
Scope: `lib-network/src/**/*.rs`

## Method

Unsafe usage was audited with:

```bash
rg -n "unsafe\s*\{|unsafe\s+fn|unsafe\s+impl" lib-network/src --glob '*.rs'
```

For each matched unsafe construct, an adjacent `SAFETY:` comment was required, documenting preconditions/invariants for that unsafe boundary.

## Unsafe Inventory (Current)

- `lib-network/src/protocols/bluetooth/classic.rs`: 31
- `lib-network/src/protocols/bluetooth/macos_core.rs`: 27
- `lib-network/src/protocols/bluetooth/macos_delegate.rs`: 7
- `lib-network/src/protocols/bluetooth/macos_error.rs`: 3
- `lib-network/src/mesh/server.rs`: 1
- `lib-network/src/socket_utils.rs`: 1
- `lib-network/src/web4/trust.rs`: 1

Total audited unsafe constructs: 71

## Changes Made

- Added inline `SAFETY:` comments for unsafe blocks and unsafe declarations across all files above.
- Clarified invariants in non-Bluetooth unsafe boundaries:
  - `mesh/server.rs` (initialization-time interior mutation)
  - `socket_utils.rs` (`setsockopt` FFI boundary)
  - `web4/trust.rs` (`geteuid` FFI call)
- Added `SAFETY:` coverage for Objective-C runtime / CoreBluetooth unsafe boundaries in:
  - `protocols/bluetooth/macos_core.rs`
  - `protocols/bluetooth/macos_delegate.rs`
  - `protocols/bluetooth/macos_error.rs`
- Added `SAFETY:` coverage for libc socket and errno boundaries in:
  - `protocols/bluetooth/classic.rs`

## Follow-ups

- No immediate unsoundness was identified during this pass.
- Existing broader crate warnings remain outside the scope of issue #1613 (this issue targets unsafe audit/docs).
