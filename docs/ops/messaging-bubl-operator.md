# BUBL messaging — operator notes

## Data path

- Deposit DB: `$NODE_DATA_DIR/messaging_deposits.sled`
- Backup/restore: include this directory with other node state if undelivered mail must survive host moves.
- TTL: 48h undelivered; GC every 5 minutes in-process.

## Health

```
GET /api/v1/msg/stats
```

Key fields:

- `metrics.pending` — undelivered envelopes on this node
- `metrics.deposits_accepted` / `acks_removed` / `gc_expired`
- `metrics.mesh_relays_in` / `mesh_relays_out`
- `metrics.verify_rejects` / `auth_rejects` — spikes indicate misconfigured clients or attack

## Optional hardening

```bash
# 32-byte key as 64 hex chars (generate: openssl rand -hex 32)
export ZHTP_MSG_AT_REST_KEY="$(openssl rand -hex 32)"

# Require Dilithium envelope signatures on send/deposit
export ZHTP_MSG_VERIFY_ENVELOPES=1
```

**Warning:** changing or losing `ZHTP_MSG_AT_REST_KEY` makes existing encrypted blobs unreadable; rotate only with empty queue or accept loss of pending mail.

## Deploy notes

- Messaging Phase 2+ (durable store) is a **node** change; redeploy validators/gateways that accept `/api/v1/msg/*`.
- Mobile/lib-client must use peek + ack (not assume delete-on-poll) and treat send status as `queued`/`pushed`.
- Rolling restart: undelivered mail survives if `messaging_deposits.sled` is on persistent disk.

## Related

- Design: `docs/arch/messaging-store-and-forward.md`
- Epic: GitHub #2896
