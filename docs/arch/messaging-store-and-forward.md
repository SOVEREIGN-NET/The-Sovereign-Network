# Messaging store-and-forward delivery model (BUBL)

**Epic:** #2896  
**Status:** Production target for node relay (`/api/v1/msg/*`)

## Model

1. **Deposit first** — every send path writes the sealed envelope to a durable deposit store before live push or mesh relay.
2. **Peek, never delete on poll** — `GET /api/v1/msg/receive` and `GET /api/v1/msg/inbound` return envelopes but leave them in the store.
3. **Delete only on client ack or TTL** — `POST /api/v1/msg/ack` removes ids addressed to the authenticated caller. Undelivered mail expires after 48 hours.
4. **Honest status** — `POST /api/v1/msg/send` returns `"queued"` (stored only) or `"pushed"` (stored + live inbound frame). Never `"delivered"`.
5. **E2E unchanged** — node stores opaque ciphertext; optional node at-rest encryption is a second layer over the same blob.

## Message id

```
message_id = hex(blake3(envelope_bytes))
```

Clients and nodes compute the same id. Duplicate deposits and mesh re-relays are idempotent. After ack, a short tombstone drops re-relays of the same bytes.

## Durability

Path: `{node_data_dir}/messaging_deposits.sled` (sled trees `deposits`, `tombstones`).

Restart reloads undelivered mail into memory indexes.

## Auth

- `send` / `deposit`: `sender_did` (and envelope `sender_did`) must match the authenticated key session (MSG-R8).
- Optional: `ZHTP_MSG_VERIFY_ENVELOPES=1` requires Dilithium envelope signature vs on-chain sender key (MSG-R9).
- `ack` / `receive` / `inbound` / `cancel`: recipient or sender is session-bound via shared DID resolver.

## Mesh

- Always deposit locally first.
- **Presence-directed relay (MSG-R14):** if the recipient is online on this node (inbound subscriber or presence), skip mesh flood.
- Otherwise fan-out `MessageRelay` to connected peers; peers deposit + optional push; dedupe by `message_id` / tombstones.

## Cancel

`POST /api/v1/msg/cancel` with `{ "recipient_did": "..." }` cancels the caller's undelivered mail to that recipient on this node.

## Operator knobs

| Env | Effect |
|-----|--------|
| `ZHTP_MSG_AT_REST_KEY` | 64 hex chars (32-byte key): encrypt deposit blobs on disk |
| `ZHTP_MSG_VERIFY_ENVELOPES` | `1` / `true`: require valid Dilithium envelope sig on send/deposit |

## Metrics

`GET /api/v1/msg/stats` — queue depth (`pending`) and counters (deposits, acks, mesh, verify rejects). Logs redact DIDs (MSG-R12).

## Client integration notes (#2489)

1. After receive/inbound, persist envelopes locally, then `POST /api/v1/msg/ack` with `message_ids`.
2. Treat send `status` as transport hint only; reliability is deposit + ack.
3. Use lib-client `message_id_for_envelope` / `ack_request_body` for id and ack JSON.
4. Deduplicate multi-node copies by `message_id` before display.
