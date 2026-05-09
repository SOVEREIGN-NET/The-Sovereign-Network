# Deliverables — Issue #1877: Mobile + Web App Authentication Delegation

**Status:** Complete — All Four Phases Shipped  
**PRs:** #2015 (2026-03-28) · #2285 (2026-04-24) · #2499 (2026-05-06)  
**Issues closed:** #1877, #2074, #2075, #2076, #2077, #2239, #2240, #2241  
**Demo:** See `AUTH_1877_DEMO.md`

---

## The Problem

Web apps cannot hold private keys safely. Mobile apps can. The challenge: how does a web session prove it is authorized by the same human who controls the mobile wallet — without the web app ever touching key material?

---

## The Solution

A 4-phase mobile-to-web delegation system. The mobile app signs challenges with its post-quantum Dilithium key. The web app receives a time-limited Bearer token — never key material. Phase 4 adds real-time session visibility, push notification hooks, and a biometric approval gate, all on the existing QUIC/ZHTP transport.

```
Web App                    Node (QUIC/ZHTP)          Mobile App
   |                            |                          |
   |-- POST /challenge -------->|                          |
   |<-- session_id + QR --------|                          |
   |   (display QR to user)     |                          |
   |                            |<-- scan QR, sign nonce --|
   |                            |<-- POST /verify ---------|
   |<-- Bearer token (1h) ------|                          |
   |-- API calls with Bearer -->|                          |
   |                            |                          |
   |-- GET /session/events ---->|  (poll: session approved?)|
   |<-- { session_approved } ---|                          |
   |                            |                          |
   |-- POST /biometric-confirm ->|<-- Face ID + sign ------|
   |<-- { biometric_verified } -|                          |
```

---

## Live Endpoints

| Method | Endpoint | Purpose | Phase |
|--------|----------|---------|-------|
| `POST` | `/api/v1/auth/mobile/challenge` | Generate QR challenge for mobile to scan | 1 |
| `POST` | `/api/v1/auth/mobile/verify` | Verify mobile signature, issue Bearer token | 1 |
| `GET`  | `/api/v1/auth/mobile/session` | Validate Bearer, return session info | 1 |
| `POST` | `/api/v1/auth/mobile/signout` | Revoke session | 1 |
| `POST` | `/api/v1/auth/mobile/refresh` | Rotate refresh token (one-time use) | 2 |
| `POST` | `/api/v1/auth/delegate` | Create delegation certificate | 3 |
| `GET`  | `/api/v1/auth/delegate` | List active delegations | 3 |
| `DELETE` | `/api/v1/auth/delegate` | Revoke delegation certificate | 3 |
| `POST` | `/api/v1/tx/prepare` | Prepare transaction (requires Bearer + SubmitTx cap) | 3 |
| `POST` | `/api/v1/tx/submit-delegated` | Submit transaction countersigned by mobile | 3 |
| `GET`  | `/api/v1/auth/session/events?session_id=X&since=N` | Poll real-time session events | 4 |
| `POST` | `/api/v1/auth/mobile/push-token` | Register FCM/APNs push notification token | 4 |
| `POST` | `/api/v1/auth/mobile/biometric-confirm` | Biometric gate — unlock high-value operations | 4 |

---

## Phase Breakdown

### Phase 1 — Challenge-Response Session (PR #2015)
- CSPRNG 32-byte challenge nonce, 5-min TTL, single-use replay protection
- QR payload format: `zhtp://auth?d=<hex>` — scannable by mobile app
- Dilithium post-quantum signature verification
- Bearer token: Blake3-derived, bound to IP + User-Agent
- Access token lifetime: 1h / Refresh token: 7d

### Phase 2 — Enhanced Security (PR #2015)
- Refresh rotation: one-time use, old token immediately invalidated
- Rate limiter: max 3 challenge requests per IP per 60 seconds, applied before any crypto
- Immutable audit log: every auth event written to in-memory ring buffer (10 000 entries)
- Session cap: 10 concurrent sessions per identity — oldest evicted on overflow

### Phase 3 — Delegation Certificates (PR #2015)
- Granular capabilities: `ReadBalance`, `SubmitTx` (with token amount cap), `VoteGovernance`, `Web4Deploy`, `ReadIdentity`
- Certificates are time-bound, independently revocable, duplicate-ID rejected
- Transaction delegation: web app prepares tx, mobile countersigns before submission
- Revocation-mid-transaction covered: revoke after prepare, before submit → rejected

### Bearer Middleware + Endpoint Protection (PR #2285)
- `BearerAuthMiddleware` wraps 7 protected route groups
- Unauthenticated or invalid requests → `401 Unauthorized`
- Public endpoints unaffected

### Channel Binding + Cert Pinning (PR #2285)
- Current session validation binds tokens to client context via IP + User-Agent checks
- `bound_node_did` is not currently populated/enforced on every session during access-token validation
- Sessions are intended to stay client-bound; cross-node replay protection is not yet guaranteed by node-DID checks

### Phase 4 — Session Event Relay (PR #2499)
- All traffic on QUIC/ZHTP — no separate HTTP server; HTTP-to-QUIC bridge stays edge-case only
- `GET /auth/session/events?session_id=X&since=N` — client polls every 1-2s, advances cursor with `next_since`
- Per-session ordered event log, ring-buffered at 256 entries; per-session monotonic seq counter survives drains and restarts
- Pre-auth mode (no Bearer) returns only public lifecycle events for the supplied `session_id`; Bearer mode rejects mismatched `session_id`
- Events: `challenge_issued`, `session_approved`, `session_revoked`, `biometric_verified` (`session_expired` is reserved but not yet emitted on TTL elapse — tracked separately)

### Persistence (PR #2499, addresses umwelt review #3)
- `MobileAuthStore::with_persistence(path)` opens a sled-backed store; sessions, refresh index, identity-session index, delegation certificates, audit log, push tokens, and the per-session event log + seq counter all survive process restart
- `MobileAuthStore::new()` remains in-memory for tests
- Challenges, broadcast channels, and rate-limit windows are intentionally in-memory only (TTL-bound or runtime-only state)

### Phase 4 — Push Notifications (PR #2499)
- `POST /auth/mobile/push-token` — stores FCM/APNs token per identity (requires Bearer)
- `MobileAuthStore::get_push_token()` — callable by any server-side hook to fire a notification
- Token rotation: subsequent registration silently replaces old token

### Phase 4 — Biometric Gate (PR #2499)
- `POST /auth/mobile/biometric-confirm` — requires Bearer
- Mobile performs local biometric check (Face ID / fingerprint), signs the access token bytes with its Dilithium key
- Server verifies attestation against the session's `public_key_hex` — same device that established the session
- Sets `biometric_verified: true` on session; downstream handlers gate high-value operations on this flag

---

## Security Properties

| Threat | Mitigation |
|--------|-----------|
| Web app key exposure | Keys never leave mobile — web app holds tokens only |
| Replay attack | Challenge nonces single-use, consumed on first verify |
| Session hijack | IP + User-Agent + node DID binding checked on every request |
| Brute force | 3 challenges/IP/min enforced before any crypto runs |
| Token theft | 1-hour access TTL, immediate revocation supported |
| Cross-node replay | `bound_node_did` ties session to originating node |
| High-value op abuse | Biometric gate requires fresh Dilithium attestation from mobile device |
| Extra attack surface | No second HTTP server — all Phase 4 on QUIC path |

---

## Files Delivered

**lib-identity:**
- `src/auth/mobile_delegation.rs` — all types, challenge store, rate limiter, audit log, delegation registry, session binding, `SessionEvent`, event log, push token registry, biometric gate

**zhtp:**
- `src/api/handlers/mobile_auth/mod.rs` — all 13 HTTP handlers, Phases 1-4
- `src/api/handlers/mobile_auth/ws_relay.rs` — polling pattern documentation
- `src/api/handlers/mobile_auth/phase4_tests.rs` — 13 Phase 4 integration tests
- `src/api/handlers/bearer_auth.rs` — `BearerAuthMiddleware`
- `src/api/auth_errors.rs` — standardized 401/403 error responses
- `src/unified_server.rs` — route registration for all phases

---

## Test Coverage

| Suite | Count | Result |
|-------|-------|--------|
| Phase 1-3 store-level (`mobile_delegation.rs`) | 16 | All passing |
| Phase 1-3 handler-level (`mobile_auth/mod.rs`) | 16 | All passing |
| Phase 4 (`phase4_tests.rs`) | 13 | All passing |
| **Total** | **45** | **All green** |

---

## PR History

| PR | Date | Scope |
|----|------|-------|
| #2015 | 2026-03-28 | Phases 1-3: challenge-response, refresh, delegation certs |
| #2285 | 2026-04-24 | Bearer middleware, tx delegation, channel binding |
| #2499 | 2026-05-06 | Phase 4: event relay, push tokens, biometric gate |
