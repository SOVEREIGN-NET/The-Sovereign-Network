# Observer Node Runbook

This runbook covers operator-facing expectations for ZHTP observer nodes.

An observer node is the canonical `FullNode` runtime path:

- It stores the full blockchain.
- It syncs from existing peers.
- It serves APIs and network data.
- It does not participate in consensus.
- It does not mine blocks.

## Content And Gateway Capability

Observer mode is layered:

- Base observer:
  stores full chain state, syncs, verifies, and exposes operator APIs.
- Content-serving observer:
  may serve read-only Web4 content and resolve domains from synced state.
- Gateway observer:
  may also answer host-based Web4 gateway requests for public content.

Supported observer Web4 behavior on this branch:

- `GET /api/v1/web4/resolve/{domain}`
- `POST /api/v1/web4/load`
- `GET /api/v1/web4/content/{domain}/{path}`
- host-header-based Web4 gateway serving for registered public content

Observer nodes do not become validators by serving content:

- they do not mint blocks
- they do not validate/vote in consensus
- they do not require validator-only startup paths to serve read-only Web4 content

Operationally, treat content serving as an optional observer capability, not the minimal observer contract. A base observer may run without public Web4/gateway exposure, while a gateway observer adds public-facing read-only content routes on top of the same non-validator full-state role.

## Required Startup Contract

Observer startup is only valid when all of the following are true:

- `node_type = "full"` or the runtime resolves to `NodeType::FullNode`
- `node_role = Observer`
- `consensus_config.validator_enabled = false`

In runtime terms, an observer must be able to report:

- `can_mine = false`
- `can_validate = false`
- `stores_full_blockchain = true`

If a full-node config still enables validator behavior, startup is rejected.

## Fresh Start Behavior

On a fresh observer with no local chain state:

- The node must not create genesis on its own.
- The node must discover an existing network first.
- Discovery should continue until peers are found and sync can begin.

Expected lifecycle progression:

1. `discovering`
2. `bootstrapping`
3. `serving`

Expected sync progression:

1. `waiting_for_peers`
2. `bootstrapping`
3. `connected`

If peers are temporarily unavailable after sync has already completed, the node may report:

- lifecycle: `degraded` or `caught_up`
- sync: `peer_unavailable` or `recovering`

## Restart Behavior

On restart with local chain state present:

- The observer may start from local committed data.
- The observer must not be forced back into continuous discovery before serving local state.
- The observer still reconnects to peers and continues catch-up if remote peers are ahead.

Expected restart states:

- `serving`: local chain present and mesh-connected
- `caught_up`: local chain present, not yet mesh-connected
- `recovering`: local chain present, reconnecting to peers

## Observer API Endpoints

Use these endpoints to confirm readiness:

- `GET /api/v1/observer/status`
- `GET /api/v1/observer/sync/current`
- `GET /api/v1/observer/network/health`
- `GET /api/v1/observer/lifecycle/current`

Recommended operator checks:

1. Confirm `node_role` is `Observer`.
2. Confirm `can_mine` is `false`.
3. Confirm `can_validate` is `false`.
4. Confirm `stores_full_blockchain` is `true`.
5. Confirm lifecycle is moving from `discovering` or `bootstrapping` to `serving`.
6. Confirm local height increases when joining an existing network.

## Minimal Config Checklist

Use `zhtp/configs/full-node.toml` or `zhtp/configs/mainnet-full-node.toml` as a base and verify:

- `consensus_config.validator_enabled = false`
- bootstrap peers are set for the target environment
- `data_directory` is persistent across restarts
- `protocols_config.api_port` is reachable by operators

Do not repurpose a validator config as an observer by only changing one field. The observer contract depends on the full-node runtime path and observer role resolution staying aligned.

## Failure Cases That Need Attention

Treat these as operator-actionable problems:

- startup rejection because the config resolves to validator behavior
- lifecycle stuck in `discovering` with zero peers
- lifecycle stuck in `bootstrapping` with peers but no height progress
- repeated `degraded` network health
- local height present but no recovery to `serving`

## Verification Commands

Targeted regression coverage for the observer runtime and operator surfaces:

```bash
cargo test -p zhtp runtime_orchestrator_tests -- --nocapture
cargo test -p zhtp observer -- --nocapture
```
