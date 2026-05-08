# AUTH-1877 — End-to-End Demo

Demonstrates the complete mobile-to-web authentication delegation flow against a real local chain. No mocks. No pre-built binaries required.

## What it does

1. Builds the `zhtp` node from source
2. Starts a single-node local chain (`auth-demo`, port 9334)
3. Runs the CLI demo — generates real Dilithium5 keys, requests a challenge, signs it, receives a Bearer token, polls the session event log, signs out

## Requirements

- Rust toolchain — install from https://rustup.rs
- ~5 min for first build (incremental after that)
- Port 9334 available

## Run

**Linux / macOS**
```bash
# from repo root
chmod +x demos/auth-1877/run.sh
./demos/auth-1877/run.sh
```

**Windows (PowerShell)**
```powershell
# from repo root
.\demos\auth-1877\run.ps1
```

## What you will see

```
=== AUTH-1877 Demo ===

[1/4] Building zhtp binary and demo example...
[2/4] Starting demo node (chain: auth-demo, port: 9334)...
[3/4] Waiting for node on http://localhost:9334...
[4/4] Running CLI demo (real Dilithium5 keys)...

=== AUTH-1877 Mobile Auth Demo ===
Node: http://localhost:9334

[1/7] POST /challenge ...           OK
      session_id      = a3f7c2b1...
      challenge_nonce = 8b2cd491...
      qr_payload      = zhtp://auth?d=7b22...

[2/7] Generate Dilithium5 keypair ...  OK
      pk_bytes = 2592 bytes

[3/7] Sign challenge nonce with Dilithium5 ...  OK
      sig_bytes = 4595 bytes

[4/7] POST /verify (submit Dilithium5 signature) ...  OK
      access_token = 9d4e1f2a3b...
      expires_at   = 1746564834 (unix)

[5/7] GET /session (validate Bearer) ...  OK
[6/7] GET /session/events (poll event log) ...  OK (2 event(s))
      seq=0 event=challenge_issued
      seq=1 event=session_approved

[7/7] POST /signout (revoke session) ...  OK

=== Demo complete — all 7 steps passed ===
```

## Files

| File | Purpose |
|------|---------|
| `node.toml` | Single-node demo chain config (chain ID 1877, port 9334) |
| `run.sh` | Linux/macOS entrypoint |
| `run.ps1` | Windows PowerShell entrypoint |
| `node.log` | Node output (created at runtime, deleted on exit) |

## Implementation

The production code exercised by this demo lives in:

- `lib-identity/src/auth/mobile_delegation.rs` — challenge store, Dilithium5 verification, session management, event log
- `zhtp/src/api/handlers/mobile_auth/mod.rs` — all 13 HTTP handlers
- `zhtp/examples/mobile_auth_demo.rs` — this CLI demo
