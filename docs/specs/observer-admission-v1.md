# Observer Admission V1

Status: Draft

Scope: Observer node admission, sponsorship, rate limiting, anti-abuse controls, and bootstrap enforcement.

## Purpose

Define a production-safe admission model for observer nodes so that:

- anonymous nodes cannot join as observers
- every observer node is accountable to a sponsoring user DID
- validator and bootstrap nodes can authenticate and authorize observers deterministically
- abuse can be rate-limited, suspended, and revoked without treating observers as validators

This spec is intentionally incremental. It is designed to fit protocol upgrades and additive state changes rather than large refactors.

## Design Goals

- Require explicit observer admission.
- Separate node authentication from observer authorization.
- Bind every observer node DID to a sponsoring user DID.
- Enforce minimum proof requirements on the sponsoring user DID.
- Support automatic registration through an API-driven enrollment flow.
- Support per-observer and per-sponsor rate limits.
- Support suspension and revocation.
- Avoid validator stake semantics for ordinary observer access.

## Non-Goals

- Replacing validator registration.
- Making observer admission anonymous.
- Defining a token bond or slashing model in V1.
- Reworking consensus or validator economics.

## Core Model

An observer is a node identity sponsored by a user identity.

Two identities participate:

- `observer_node_did`
  - the machine/node identity used for QUIC peer authentication
- `sponsoring_user_did`
  - the user or operator identity that authorizes and is accountable for the observer

Observer access is granted only when:

1. the node proves ownership of `observer_node_did`
2. the sponsor proves ownership of `sponsoring_user_did`
3. the sponsor has sufficient proof level for observer operation
4. the observer admission record is `active`

## Invariants

1. Anonymous users cannot operate observers.
2. Authentication does not imply authorization.
3. An observer may connect only if its node DID is bound to an active sponsoring user DID.
4. Sponsoring user proof level determines whether observer access is allowed.
5. Rate limits apply both per observer and per sponsoring user.
6. Revoking a sponsor may revoke all sponsored observers.
7. Observer access is independent from validator consensus rights.

## Roles

- `validator`
  - consensus role
  - stake-backed
  - separate registration path
- `observer`
  - read/sync role
  - admission-backed
  - no proposing or voting rights

## Admission Record

Minimum persisted fields:

- `observer_node_did`
- `observer_public_key`
- `sponsoring_user_did`
- `sponsor_signature`
- `role = observer`
- `status = pending | active | suspended | revoked`
- `proof_level`
- `rate_limit_tier`
- `allowed_network`
- `trusted_sync_scope`
- `created_at`
- `updated_at`
- `expires_at` optional

Recommended optional fields:

- `display_name`
- `endpoints`
- `invite_id`
- `last_seen_at`
- `suspension_reason`
- `revocation_reason`

## Proof-Level Policy

Observer access is gated by sponsoring user proof level.

Example policy:

- `proof_level_0`
  - cannot sponsor observers
- `proof_level_1`
  - may sponsor 1 observer
- `proof_level_2`
  - may sponsor up to 3 observers
- `proof_level_3`
  - may sponsor higher limits or organizational observers

The exact tiers are governance-configurable, but the protocol rule is:

`proof_level < minimum_observer_proof_level => observer admission denied`

## Enrollment Flow

### 1. Node identity creation

The observer node generates or loads:

- node keypair
- `observer_node_did`

### 2. Sponsor authorization

The user wallet signs an enrollment statement authorizing the node:

`I, sponsoring_user_did, authorize observer_node_did to operate as observer on network X`

The signed statement must bind:

- sponsor DID
- observer node DID
- requested role
- network identifier
- issuance time
- expiry time or nonce

### 3. Admission API submission

The observer submits:

- `observer_node_did`
- `observer_public_key`
- `sponsoring_user_did`
- sponsor-signed enrollment statement
- optional endpoint metadata
- optional invite token

### 4. Server validation

The admission service verifies:

- observer DID/public key consistency
- sponsor DID validity
- sponsor signature over the enrollment statement
- sponsor proof level
- sponsor quota availability
- network match
- invite token or approval requirements if configured

### 5. Record creation

If valid, the system creates or updates the admission record as:

- `pending`, if approval is required
- `active`, if auto-approval is allowed

### 6. Bootstrap enforcement

Bootstrap and validator nodes accept observer sync only when the record is `active`.

## API

### `POST /api/v1/node-admission/challenge`

Purpose:
- establish freshness and anti-replay challenge

Request:

```json
{
  "observer_node_did": "did:zhtp:...",
  "observer_public_key": "base64..."
}
```

Response:

```json
{
  "challenge_id": "uuid-or-hash",
  "challenge_nonce": "base64...",
  "expires_at": 1760000000
}
```

### `POST /api/v1/node-admission/register`

Purpose:
- request observer admission

Request:

```json
{
  "observer_node_did": "did:zhtp:...",
  "observer_public_key": "base64...",
  "sponsoring_user_did": "did:zhtp:...",
  "requested_role": "observer",
  "challenge_id": "uuid-or-hash",
  "node_signature": "base64...",
  "sponsor_signature": "base64...",
  "endpoints": [
    "203.0.113.10:9334"
  ],
  "invite_token": "optional"
}
```

Response:

```json
{
  "status": "active",
  "observer_node_did": "did:zhtp:...",
  "sponsoring_user_did": "did:zhtp:...",
  "rate_limit_tier": "observer_basic",
  "trusted_sync_sources": [
    "77.42.37.161:9334",
    "77.42.74.80:9334"
  ]
}
```

### `GET /api/v1/node-admission/status/{observer_node_did}`

Purpose:
- allow observer and operators to inspect admission state

Response:

```json
{
  "status": "active",
  "role": "observer",
  "sponsoring_user_did": "did:zhtp:...",
  "proof_level": 2,
  "rate_limit_tier": "observer_basic",
  "expires_at": null
}
```

### `POST /api/v1/node-admission/revoke`

Purpose:
- sponsor or governance revokes observer access

Request:

```json
{
  "observer_node_did": "did:zhtp:...",
  "requested_by": "did:zhtp:...",
  "signature": "base64..."
}
```

## Authentication Rules

Two signatures are required during enrollment:

- `node_signature`
  - proves the node controls `observer_node_did`
- `sponsor_signature`
  - proves the user DID authorizes that node

This prevents:

- registering someone else’s node DID
- registering an observer without sponsor consent
- binding a valid sponsor DID to an unrelated machine

## Authorization Rules

An observer is authorized only if all are true:

- admission record exists
- role is `observer`
- status is `active`
- sponsor proof level meets minimum
- sponsor quota not exceeded
- record not expired
- network id matches

## Rate Limiting

Rate limits are enforced at three layers.

### Per observer DID

- max connection attempts per minute
- max concurrent sync sessions
- max block-range requests per minute
- max API requests per minute
- max bytes served per hour

### Per sponsoring user DID

- max active observers
- max aggregate bytes served across all sponsored observers
- max aggregate sync sessions
- max failed enrollments per time window

### Per source IP

Fallback only:

- protect against obvious floods before identity is established

IP rate limiting must not be the primary trust model.

## Anti-Abuse Controls

Each observer and sponsor accumulates abuse signals:

- repeated failed authentication
- repeated failed sponsorship verification
- excessive reconnect churn
- repeated oversized or invalid requests
- repeated sync retries without progress

Response ladder:

- warn
- temporary slow-down
- temporary suspension
- revocation

## Bootstrap And Sync Enforcement

Bootstrap peers must enforce:

- peer DID is registered
- role is `observer` or other sync-allowed role
- status is `active`
- network matches

Trusted sync sources should only serve state to admitted observers.

This check must happen before:

- bootstrap sync
- gap fill
- long-range block import

## Revocation

Revocation can be initiated by:

- sponsoring user DID
- governance/admin authority
- automated abuse controls

Revoking a sponsor may:

- immediately revoke all child observers
- suspend all child observers pending review

V1 should support at least full child revocation.

## State Machine

- `unregistered`
- `pending`
- `active`
- `rate_limited`
- `suspended`
- `revoked`

Rules:

- only `active` observers may sync
- `pending` observers may poll status but may not sync
- `suspended` observers are denied until reinstated
- `revoked` observers require a new enrollment

## Storage And Replication

V1 may start with validator-governed replicated registry state, but the target model is:

- deterministic registry state available to bootstrap peers
- replay-safe revocation and admission decisions

Implementation may begin as:

- config-backed authority API plus replicated registry storage

Later upgrade path:

- on-chain admission records
- governance-controlled updates

## Rollout Plan

### Phase 1

- Add observer admission record model
- Add sponsor binding
- Add challenge/register/status API
- Add bootstrap enforcement for `active` records

### Phase 2

- Add proof-level policy
- Add per-sponsor quotas
- Add rate-limit tiers

### Phase 3

- Add suspension and revocation workflows
- Add abuse scoring
- Add operator/admin approval paths

### Phase 4

- Consider optional observer bond if abuse pressure justifies economic friction

## Open Questions

1. Should first enrollment be auto-approved for qualifying sponsors, or always `pending`?
2. Should sponsorship be limited to one organization or namespace per user DID?
3. Should trusted sync sources be returned by the admission API or discovered from chain state?
4. Should revoking a sponsor instantly revoke all observers, or suspend them first?
5. When the identity registry is unavailable, should bootstrap peers fail closed or permit a temporary cache-based grace window?

## Acceptance Criteria

- An anonymous node cannot join as observer.
- A node DID without a sponsoring user DID cannot join.
- A sponsoring user DID below minimum proof level cannot sponsor an observer.
- A revoked observer cannot sync.
- A revoked sponsor disables sponsored observers.
- Bootstrap peers deny non-admitted observers before sync begins.
- Rate limits can be enforced both per observer and per sponsor.

