# Demo — Issue #1877: Mobile + Web App Authentication Delegation
# All Four Phases

**PR History:** #2015 (2026-03-28) · #2285 (2026-04-24) · #2499 (2026-05-06)  
**Issues closed:** #1877, #2074, #2075, #2076, #2077, #2239, #2240, #2241

---

## The Problem

Web apps cannot hold private keys safely. Mobile apps can. The challenge: how does a web session prove it is authorized by the same human who controls the mobile wallet — without the web app ever touching key material?

---

## The Solution: A 4-Phase Delegation Chain

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
   |   (poll for events)        |                          |
   |-- GET /session/events ---->|                          |
   |<-- { session_approved } ---|                          |
   |                            |                          |
   |   (high-value operation)   |                          |
   |-- POST /biometric-confirm ->|<-- Face ID + sign ------|
   |<-- { biometric_verified } -|                          |
```

---

## Phase 1 — Challenge-Response Session

**What it does:** Establishes a Bearer session without the web app touching any key material.

**Flow:**
1. Web app posts to `/challenge` → node generates a 32-byte CSPRNG nonce, encodes it into a `zhtp://auth?d=<hex>` QR code
2. User scans QR with mobile app → mobile signs the nonce with its Dilithium post-quantum key
3. Mobile posts signature to `/verify` → node verifies, issues a Bearer token bound to IP + User-Agent
4. Web app uses Bearer token for all subsequent API calls

**Security:** Key material never leaves the mobile. The web app only ever sees an opaque hex token.

```bash
# Step 1 — web app requests a challenge
curl -X POST http://localhost:9334/api/v1/auth/mobile/challenge \
  -H "Content-Type: application/json" \
  -d '{"capabilities": [{"type": "read_balance"}, {"type": "submit_tx", "max_amount_tokens": 1000}]}'

# Response:
# {
#   "session_id": "a3f7...",
#   "challenge_nonce": "8b2c...",
#   "expires_at": 1746561234,
#   "qr_payload": "zhtp://auth?d=7b2273657373696f6e5f6964...",
#   "node_endpoint": "http://localhost:9334"
# }

SESSION_ID="a3f7..."

# Step 2 — mobile signs the nonce (happens on device, not shown here)

# Step 3 — web app submits mobile's signature
curl -X POST http://localhost:9334/api/v1/auth/mobile/verify \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "'$SESSION_ID'",
    "public_key_hex": "<dilithium_pk_hex>",
    "signature_hex": "<dilithium_sig_hex>",
    "identity_hex": "<identity_id_hex>"
  }'

# Response:
# {
#   "access_token": "9d4e...",
#   "refresh_token": "f1a2...",
#   "access_expires_at": 1746564834,
#   "refresh_expires_at": 1747166034,
#   "granted_capabilities": [{"type": "read_balance"}, {"type": "submit_tx", "max_amount_tokens": 1000}]
# }

ACCESS_TOKEN="9d4e..."

# Step 4 — use Bearer on any protected endpoint
curl http://localhost:9334/api/v1/wallet/balance \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

---

## Phase 2 — Enhanced Security

**What it does:** Hardens the session against brute force, replay, and session overflow.

| Control | Behaviour |
|---------|-----------|
| Refresh token rotation | One-time use — old token invalidated the moment it is rotated |
| Rate limiting | Max 3 challenge requests per IP per 60 seconds — applied before any crypto |
| Audit log | Every auth event written to an immutable in-memory ring buffer (10 000 entries) |
| Session cap | 10 concurrent sessions per identity — oldest evicted automatically on overflow |

```bash
# Rotate refresh token (web app calls this before the 1-hour access token expires)
curl -X POST http://localhost:9334/api/v1/auth/mobile/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "f1a2..."}'

# Response: new access_token + new refresh_token; old tokens immediately dead
```

---

## Phase 3 — Delegation Certificates

**What it does:** Grants the web session named, scoped, time-limited capabilities that can be independently revoked.

**Capabilities available:**

| Capability | Effect |
|------------|--------|
| `read_balance` | Read any on-chain balance |
| `submit_tx` (+ `max_amount_tokens`) | Submit transactions up to a token cap |
| `vote_governance` | Cast DAO governance votes |
| `web4_deploy` | Deploy / update Web4 content |
| `read_identity` | Read identity metadata |

```bash
# Create a delegation certificate
curl -X POST http://localhost:9334/api/v1/auth/delegate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "delegate_id": "did:zhtp:web-session-1",
    "capabilities": [{"type": "submit_tx", "max_amount_tokens": 500}],
    "expires_in_secs": 3600,
    "nonce": 1,
    "signature_hex": "<delegator_dilithium_sig>"
  }'

# Response: { "cert_id": "c9f2...", "expires_at": 1746564834 }

CERT_ID="c9f2..."

# Prepare a delegated transaction (requires SubmitTx capability)
curl -X POST http://localhost:9334/api/v1/tx/prepare \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tx_hex": "..."}'

# Mobile signs the prepared tx hash, web app submits:
curl -X POST http://localhost:9334/api/v1/tx/submit-delegated \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tx_hash": "...", "mobile_signature_hex": "..."}'

# Revoke the certificate (immediate — any in-flight use after this is rejected)
curl -X DELETE http://localhost:9334/api/v1/auth/delegate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cert_id": "'$CERT_ID'"}'
```

---

## Phase 4 — Real-Time Event Relay, Push Notifications, Biometric Gate

**Architecture note:** All Phase 4 endpoints run on the existing QUIC/ZHTP transport — no separate HTTP server. The HTTP-to-QUIC bridge remains edge-case only.

---

### 4A — Session Event Relay

**What it does:** The web app knows the instant the mobile scans and approves — without holding a persistent connection.

**How:** Client polls `GET /auth/session/events?since=N` every 1-2 seconds. The server returns all events with sequence ≥ N. Each event carries a `seq` number so the client advances its cursor and never misses or double-processes.

**Events:**

| Event | Fired when |
|-------|-----------|
| `challenge_issued` | Challenge created and QR is ready |
| `session_approved` | Mobile signed — session is live |
| `session_expired` | Access token TTL elapsed |
| `session_revoked` | Signout called |
| `biometric_verified` | Biometric gate passed |

```bash
# Web app starts polling as soon as it displays the QR
# since=0 to get everything from the beginning

curl "http://localhost:9334/api/v1/auth/session/events?session_id=$SESSION_ID&since=0" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Response immediately after challenge:
# {
#   "session_id": "a3f7...",
#   "events": [
#     { "event": "challenge_issued", "session_id": "a3f7...", "expires_at": 1746561234, "seq": 0 }
#   ],
#   "next_since": 1
# }

# After mobile scans and verifies (poll with next_since=1):
curl "http://localhost:9334/api/v1/auth/session/events?session_id=$SESSION_ID&since=1" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# {
#   "events": [
#     { "event": "session_approved", "session_id": "a3f7...", "identity_id": "8b2c...", "seq": 1 }
#   ],
#   "next_since": 2
# }
# → web app can now auto-redirect to the authenticated view
```

---

### 4B — Push Notifications

**What it does:** Mobile app registers its FCM/APNs device token once. Any server-side hook can then retrieve it to fire a notification (e.g. "Pending signing request on your web session").

```bash
# Mobile app registers its push token after session is established
curl -X POST http://localhost:9334/api/v1/auth/mobile/push-token \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"push_token": "fcm:APA91bHPRgkFLJu13CrTyF..."}'

# Response: { "registered": true }

# Token is now stored per identity — any node-side hook can call
# MobileAuthStore::get_push_token(identity_id) to retrieve and fire a push
```

---

### 4C — Biometric Gate

**What it does:** Before a high-value operation, the mobile app must perform a local biometric check (Face ID / fingerprint) and prove it with a fresh Dilithium signature. The server verifies this is the same device that established the session.

**Flow:**
1. Web app initiates a high-value operation
2. Server checks `session.biometric_verified` — if false, responds 403 with a prompt
3. Web app tells mobile to confirm biometrically
4. Mobile passes Face ID / fingerprint → signs the access token bytes with its Dilithium key
5. Web app posts the attestation to `/biometric-confirm`
6. Server verifies signature against the session's `public_key_hex` — sets `biometric_verified: true`
7. Operation proceeds

```bash
# Mobile signs the access token after local biometric check
# attestation_hex = Dilithium signature over the raw access_token bytes

ATTESTATION="<dilithium_sig_over_access_token_bytes>"

curl -X POST http://localhost:9334/api/v1/auth/mobile/biometric-confirm \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"attestation_hex": "'$ATTESTATION'"}'

# Response: { "biometric_verified": true }

# Poll to confirm the event fired:
curl "http://localhost:9334/api/v1/auth/session/events?session_id=$SESSION_ID&since=2" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# { "events": [{ "event": "biometric_verified", "session_id": "a3f7...", "seq": 2 }], "next_since": 3 }

# High-value operation now permitted on this session
```

---

### Full Phase 4 Sequence — End to End

```bash
# 1. Challenge + QR display
curl -X POST http://localhost:9334/api/v1/auth/mobile/challenge \
  -d '{"capabilities": [{"type": "submit_tx", "max_amount_tokens": 10000}]}'

# 2. Web app starts polling (seq 0)
curl "http://localhost:9334/api/v1/auth/session/events?session_id=$SESSION_ID&since=0" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# → challenge_issued (seq 0)

# 3. Mobile scans and verifies
# → session_approved (seq 1) appears on next poll

# 4. Register push token
curl -X POST http://localhost:9334/api/v1/auth/mobile/push-token \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"push_token": "fcm:..."}'

# 5. Biometric gate for high-value tx
curl -X POST http://localhost:9334/api/v1/auth/mobile/biometric-confirm \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"attestation_hex": "<sig>"}'
# → biometric_verified (seq 2)

# 6. Submit the high-value delegated transaction
curl -X POST http://localhost:9334/api/v1/tx/prepare \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"tx_hex": "..."}'
curl -X POST http://localhost:9334/api/v1/tx/submit-delegated \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"tx_hash": "...", "mobile_signature_hex": "..."}'

# 7. Sign out
curl -X POST http://localhost:9334/api/v1/auth/mobile/signout \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# → session_revoked (seq 3) appears on next poll
```

---

## Why It Is Secure

| Threat | Mitigation |
|--------|-----------|
| Web app key exposure | Keys never leave mobile — web app holds tokens only |
| Replay attack | Challenge nonces single-use, consumed on first verify |
| Session hijack | IP + User-Agent + node DID binding checked on every request |
| Brute force | 3 challenges/IP/min enforced before any crypto runs |
| Token theft | 1-hour access TTL, immediate revocation supported |
| Cross-node replay | `bound_node_did` ties session to originating node |
| High-value op abuse | Biometric gate requires fresh Dilithium attestation from the mobile device |
| Extra attack surface | No second HTTP server — all Phase 4 endpoints on QUIC |

---

## Test Coverage

| Suite | Tests | Result |
|-------|-------|--------|
| Phase 1-3 store-level (`mobile_delegation.rs`) | 16 | All passing |
| Phase 1-3 handler-level (`mobile_auth/mod.rs`) | 16 | All passing |
| Phase 4 (`phase4_tests.rs`) | 13 | All passing |
| **Total** | **45** | **All green** |
