# Sovereign Asset — Unified DAO/Token Primitive

**Status:** Proposed (design — no implementation yet)  
**Supersedes (eventually):** fragmented `TokenContract` + `BondingCurveToken` + ad-hoc DAO registry wiring  
**Companion:** [`genesis-bootstrap-surface.md`](./genesis-bootstrap-surface.md), [`state-unification.md`](./state-unification.md)  
**Epic context:** [#2727 GENESIS](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2727)

---

## 1. Problem

Today BUBL, CBE, and future DAO tokens are **different species** in code:

| Today | Issue |
|-------|-------|
| `TokenContract` (ledger row) | Bare metadata; treasury recipient not stored; no shareable interface |
| `BondingCurveToken` (parallel struct) | Duplicates identity fields; curve is a token *class*, not a module |
| `DAOEntry` (separate registry) | Optional bolt-on; metadata hash disconnected from token launch |
| Rewards (BUBL) | Node env + hardcoded constants; not discoverable from chain |
| `TokenCreation` tx | Payload not persisted; clients must special-case tickers |

Users cannot share “a DAO token” uniformly. Wallets must hardcode BUBL vs CBE. After chain wipe, BUBL disappears until a script re-broadcasts `TokenCreation` — because launch state is not a first-class, replayable asset record with a published interface.

**Goal:** One on-chain primitive — **`SovereignAsset`** — with optional modules (curve, rewards, governance, …), mandatory shareability (manifest), and deploy-address identity.

---

## 2. Decision summary (locked)

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| D1 | **Asset identity** | `asset_id = BLAKE3(launch_tx_hash)` (deploy-address style) | Same mental model as `ContractDeployment`; unique per launch; no global name-hash collisions across creators |
| D2 | **Module model** | Optional facets on one `SovereignAsset` record | BUBL = fixed supply, no curve. CBE = same type + `curve` module. Not two token structs |
| D3 | **Module upgrades** | **Allowed** via `AssetModuleUpgrade` tx | DAOs can add curve/rewards/governance post-launch; gated by authority module |
| D4 | **Manifest authority** | **Governance module** (single-key or multisig) once enabled; creator until then | Manifest updates are privileged; governance is a module, not a separate registry step |
| D5 | **Rewards signing** | **Hot-wallet delegation** on-chain | Creator/governance delegates spend authority to an operational keystore; validators load delegate, not root creator key |
| D6 | **SOV** | Stays **native** L1 currency | Not a `SovereignAsset`; unchanged native shell at h=0 |
| D7 | **Shareability** | Mandatory **manifest** (DHT content, on-chain CID + hash) | Wallets interact from manifest `interface` — no ticker hardcoding |
| D8 | **Execution** | Protocol-native tx kinds + published schema | Non-EVM: no WASM per standard token; WASM reserved for custom DAO logic beyond standard modules |
| D9 | **Multisig defaults** | See [§4.4](#44-governance-defaults-multisig--authority-transfer) | Bounded N≤10; majority default M; CBE/BUBL recommendations |
| D10 | **Creator after governance** | **No privileged rights**; provenance + holder rights only | Authority fully transfers; creator may remain a multisig signer if governance config includes them |

---

## 3. Core type: `SovereignAsset`

Single sled-backed record. All DAO/token launches write exactly one row.

```rust
/// Consensus-persisted asset record (metadata + module headers).
/// Balances live in `asset_balances/`; heavy module state in sub-trees.
pub struct SovereignAsset {
    // ── Identity ──────────────────────────────────────────────────
    /// Deploy-address: hash of the AssetLaunch transaction (32 bytes).
    pub asset_id: [u8; 32],
    pub name: String,
    pub symbol: String,          // globally unique at launch
    pub decimals: u8,
    pub creator_key_id: [u8; 32],
    pub creator_did: Option<String>,
    pub treasury_key_id: [u8; 32],   // always persisted (not mint-only)
    pub launched_at_height: u64,
    pub launched_at_time: u64,

    // ── Supply ────────────────────────────────────────────────────
    pub supply_mode: SupplyMode,     // Fixed | Elastic
    pub max_supply: u128,
    pub total_supply: u128,

    // ── Shareability (mandatory) ────────────────────────────────
    pub manifest_cid: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub schema_version: u16,

    // ── Authority (who may upgrade modules / update manifest) ─────
    pub authority: AssetAuthority,

    // ── Enabled modules (None = disabled) ─────────────────────────
    pub curve: Option<CurveModuleHeader>,
    pub rewards: Option<RewardsModuleHeader>,
    pub governance: Option<GovernanceModuleHeader>,
    pub kernel: Option<KernelModuleHeader>,
    pub market: Option<MarketModuleHeader>,
}

pub enum SupplyMode {
    /// Initial mint at launch; further mints only via explicit policy/governance.
    Fixed,
    /// Supply changes via curve buy/sell (Elastic implies curve module present or planned).
    Elastic,
}

pub enum AssetAuthority {
    /// Launch creator may upgrade modules and rotate manifest until governance enabled.
    Creator { key_id: [u8; 32] },
    /// Governance module holds authority (single or multisig).
    Governance { module_ref: [u8; 32] },
}
```

### Module headers vs module state

Headers stay on `SovereignAsset` for cheap listing. Heavy state is keyed by `asset_id` in sub-trees:

| Sled tree | Contents |
|-----------|----------|
| `assets/` | `SovereignAsset` record |
| `asset_balances/` | `(asset_id, key_id) → u128` |
| `asset_curve/` | `CurveModuleState` (phase, reserves, threshold, …) |
| `asset_rewards/` | `RewardsModuleState` (delegate, policy refs, nonce) |
| `asset_governance/` | `GovernanceModuleState` (verifier type, signers, threshold) |

---

## 4. Optional modules

### 4.1 `CurveModule` (optional — CBE-style)

Bonding curve is **not** a token class. It is optional sub-state.

```
CurveModuleHeader { enabled: true, curve_type, threshold, sell_enabled }
CurveModuleState  { phase: Curve|Graduated|AMM, reserve_balance, treasury_balance, amm_pool_id }
```

- `AssetLaunch` may include `curve: Some(CurveLaunchConfig)` or omit it (BUBL-style).
- `AssetModuleUpgrade` may add curve to an existing `Fixed` asset (supply_mode flips to `Elastic`).

Tx kinds when enabled: `CurveBuy`, `CurveSell`, `CurveGraduate` (automatic), `AmmMigrate`.

### 4.2 `RewardsModule` (optional — BUBL-style)

Reward **policy** is manifest + module state, not validator env vars.

```
RewardsModuleHeader {
    /// On-chain delegate allowed to sign outbound reward transfers.
    spend_delegate_key_id: [u8; 32],
    policy_cid: [u8; 32],
    policy_hash: [u8; 32],
}
```

**Hot-wallet delegation (D5):**

1. At launch (or upgrade), creator sets `spend_delegate_key_id` — typically a dedicated operational keystore (`/opt/zhtp/keystores/bubl-rewards-hot`).
2. Delegate must hold spendable balance on the asset (funded from creator/treasury allocation).
3. Validators enable `/api/v1/rewards/*` when:
   - `rewards` module present on asset,
   - delegate has positive balance,
   - `ZHTP_REWARDS_ASSET_ID` (or manifest discovery) points at this asset.

Root creator key stays cold; compromise of hot wallet limits exposure to reward float, not full treasury.

Rotation: `AssetRewardsDelegateRotate` tx, signed by current `AssetAuthority`.

### 4.3 `GovernanceModule` (optional — manifest + upgrades)

Governance is the **authority module** for privileged operations:

| Operation | Before governance | After governance enabled |
|-----------|-------------------|--------------------------|
| Manifest update | Creator | Governance verifier |
| Module upgrade | Creator | Governance verifier |
| Delegate rotation | Creator | Governance verifier |
| Treasury parameter change | Creator | Governance verifier |

```
GovernanceModuleHeader {
    verifier: GovernanceVerifier,
}

pub enum GovernanceVerifier {
    /// Single authorized key (simple DAOs, early-stage assets).
    Single { signer_key_id: [u8; 32] },
    /// M-of-N multisig (reuses existing MultisigVerifier semantics).
    Multisig {
        signers: Vec<[u8; 32]>,   // bounded, e.g. max 10
        threshold: u8,            // M
    },
}
```

**Enabling governance** (`AssetModuleUpgrade`):

1. Launch with `authority: Creator`.
2. Later upgrade adds `governance: Some(...)`.
3. Same tx (or follow-up `AssetAuthorityTransfer`) sets `authority: Governance`.
4. Creator **loses all privileged rights** at authority transfer (see [§4.5](#45-creator-rights-after-governance-transfer)).

Manifest updates require `AssetManifestUpdate` tx with `GovernanceProof` (single sig or multisig bundle).

### 4.4 Governance defaults (multisig + authority transfer)

Protocol-enforced bounds and defaults for `GovernanceVerifier`. Aligns with
`MultisigConfig` (`max_signers: 10`) in `approval_verifier/multisig.rs`.

#### Signer set bounds

| Constant | Value | Rule |
|----------|-------|------|
| `GOVERNANCE_MIN_SIGNERS` | 1 | `Single` verifier only |
| `GOVERNANCE_MULTISIG_MIN_SIGNERS` | 2 | `Multisig` requires N ≥ 2 |
| `GOVERNANCE_MAX_SIGNERS` | 10 | N ≤ 10; duplicate key_ids rejected |
| `GOVERNANCE_MIN_THRESHOLD` | 1 | M ≥ 1 |
| `GOVERNANCE_MAX_THRESHOLD` | N | M ≤ N always |

Validation at launch/upgrade:

- `threshold == 0` → reject
- `threshold > signers.len()` → reject
- `signers.len() == 1` → must use `Single`, not `Multisig`
- `signers.len() > 10` → reject
- Creator `key_id` **may** be in signer set (recommended for continuity)

#### Default threshold when M omitted

If `AssetLaunch` or `AssetModuleUpgrade` supplies `Multisig { signers }` without
`threshold`, the executor applies **simple majority**:

```
default_threshold(N) = floor(N / 2) + 1
```

| N (signers) | Default M | Notes |
|-------------|-----------|-------|
| 2 | 2 | 2-of-2 (both required) |
| 3 | 2 | 2-of-3 |
| 4 | 3 | 3-of-4 |
| 5 | 3 | 3-of-5 |
| 6 | 4 | 4-of-6 |
| 7 | 4 | 4-of-7 |
| 8 | 5 | 5-of-8 |
| 9 | 5 | 5-of-9 |
| 10 | 6 | 6-of-10 |

Explicit `threshold` in payload always overrides the default.

#### Recommended profiles (non-enforced hints in manifest)

| Asset profile | Verifier | Signers | M | Notes |
|---------------|----------|---------|---|-------|
| **BUBL** (rewards treasury) | `Single` or `Multisig` | council hot + 2 cold | 2-of-3 | Operational: rewards delegate is separate from governance |
| **CBE** (public DAO) | `Multisig` | 5 council keys | 3-of-5 | Matches supermajority spirit of existing governance constants |
| **Solo launcher** | `Single` | creator `key_id` | 1 | Until DAO adds multisig via upgrade |
| **High-security DAO** | `Multisig` | 5–7 keys | `ceil(N × 0.67)` | Optional explicit M; no default override |

#### Authority transfer timelock

First transfer `Creator → Governance` on an asset that did **not** launch with
governance enabled:

| Parameter | Default |
|-----------|---------|
| `AUTHORITY_TRANSFER_TIMELOCK_BLOCKS` | 7_200 (~2 h at 1 s/block testnet; configurable per network) |
| Subsequent signer/threshold changes | No timelock (governance proof only) |
| Launch with `governance` + `transfer_authority: true` in same `AssetLaunch` | **No timelock** (explicit opt-in at birth) |

During timelock, `AssetAuthorityTransfer` is queued in `asset_governance/` with
`effective_height`. Creator may cancel the transfer with a creator-signed
`AssetAuthorityTransferCancel` before `effective_height`.

#### Privileged ops and required proof (after governance)

| Operation | Proof required | Default M applies? |
|-----------|----------------|------------------|
| `AssetManifestUpdate` | `GovernanceProof` | Yes |
| `AssetModuleUpgrade` | `GovernanceProof` | Yes |
| `AssetRewardsDelegateRotate` | `GovernanceProof` | Yes |
| `AssetAuthorityTransfer` (signer set / threshold change) | `GovernanceProof` | Yes |
| `AssetMint` (if policy allows) | `GovernanceProof` | Yes |
| `AssetTransfer` | Holder signature | No (not governance) |

`GovernanceProof` wire format: reuse `ApprovalProof` from
`lib-blockchain/src/contracts/approval_verifier/` (resolves open Q4).

### 4.5 Creator rights after governance transfer

**Decision D10:** Once `authority` becomes `Governance`, the launch creator has
**zero unilateral privileged rights**. No escape hatch, no shadow admin, no
retained manifest veto in v1.

#### What the creator **loses** (immediately at `effective_height`)

| Capability | After transfer |
|------------|----------------|
| `AssetManifestUpdate` | ❌ Creator sig alone insufficient |
| `AssetModuleUpgrade` | ❌ |
| `AssetRewardsDelegateRotate` | ❌ |
| `AssetAuthorityTransfer` | ❌ |
| `AssetMint` / treasury policy | ❌ |
| Cancel queued authority transfer | ❌ (only while still `Creator`) |

#### What the creator **keeps** (non-privileged, permanent)

| Right | Notes |
|-------|-------|
| **Provenance** | `creator_key_id` and `creator_did` on `SovereignAsset` are **immutable** historical fields — wallets show “launched by” |
| **Token holder** | `AssetTransfer`, `AssetBurn` own balance like any key |
| **Multisig signer** | **Only if** governance config lists creator in `signers` — then they have 1-of-M voice, not solo control |
| **Rewards delegate** | **Only if** governance assigns them `spend_delegate_key_id` — operational role, not creator authority |
| **Read access** | All public API / manifest / balance queries |

#### How creators stay involved (by design)

Creators who want ongoing influence after handing off authority should:

1. Include their `key_id` in the initial `Multisig` signer set (e.g. 2-of-3 with creator + two council keys).
2. Remain a funded holder of governance/reward tokens if voting weight is token-weighted later.
3. Use `AssetModuleUpgrade` under governance to rotate themselves **out** of signers when ready — that requires M-of-N consent.

There is **no** `CreatorRetain { emergency_pause: true }` or similar backdoor in v1.

#### Worked example: BUBL handoff

```
Launch:     authority=Creator, rewards.spend_delegate=hot_wallet
Upgrade:    governance=Multisig(3 council keys, 2-of-3), transfer_authority=true
After:      creator_key_id still on record; creator NOT in signers unless council adds them
Rewards:    hot_wallet still signs claims; rotation requires 2-of-3 governance
```

---

## 5. Shareability: manifest (mandatory)

Every `AssetLaunch` must include `manifest_cid` + `manifest_hash`. Launch tx is **rejected** if hash mismatch against DHT pin (validators perform best-effort pin check; strict mode configurable).

### `SovereignAssetManifest` (DHT content)

```json
{
  "schema": "zhtp/asset-manifest/v1",
  "asset_id": "<launch_tx_hash>",
  "name": "Bubble",
  "symbol": "BUBL",
  "decimals": 18,
  "description": "...",
  "links": { "website": "...", "docs": "..." },
  "media": { "icon_cid": "..." },

  "interface": {
    "version": "1.0.0",
    "tx_kinds": ["AssetTransfer", "RewardsClaim"],
    "methods": [],
    "events": ["RewardPaid", "ManifestUpdated"]
  },

  "modules": {
    "curve": null,
    "rewards": {
      "spend_delegate": "<key_id>",
      "policy": { "welcome_bubl": "100", "checkin_base": "10" }
    },
    "governance": null
  }
}
```

**Share link:** `zhtp://asset/<asset_id>` or API `GET /api/v1/assets/<asset_id>` (resolves manifest from CID).

Wallets **must not** hardcode tickers. Discovery flow:

1. `GET /api/v1/assets` or scan `AssetLaunched` events.
2. Fetch manifest from DHT by CID.
3. Verify `manifest_hash`.
4. Build UI and tx list from `interface.tx_kinds` + `modules`.

---

## 6. Transactions

### 6.1 `AssetLaunch` (replaces `TokenCreation`)

```
AssetLaunchPayloadV1 {
    name, symbol, decimals: u8,
    initial_supply: u128,
    treasury_key_id: [u8; 32],
    treasury_bps: u16,              // canonical 2000
    supply_mode: Fixed | Elastic,
    manifest_cid, manifest_hash,

    // optional module init (all None = minimal fixed token)
    curve: Option<CurveLaunchConfig>,
    rewards: Option<RewardsLaunchConfig>,   // includes spend_delegate_key_id
    governance: Option<GovernanceLaunchConfig>,
    dao_class: Option<NP | FP>,
}
```

**Executor:**

1. `asset_id = launch_tx_hash`
2. Validate symbol uniqueness, manifest hash, treasury != creator
3. Write `SovereignAsset`, mint allocations, init requested module substates
4. Emit `AssetLaunched { asset_id, module_bitmask }`

### 6.2 `AssetModuleUpgrade`

Adds or reconfigures a module. Requires `AuthorityProof` (creator or governance).

```
AssetModuleUpgradePayloadV1 {
    asset_id,
    module: Curve | Rewards | Governance | Kernel | Market,
    config: <module-specific>,
    transfer_authority: bool,          // if true and module=Governance → queue or immediate per launch rules
    governance: Option<GovernanceLaunchConfig>,  // verifier, signers, threshold (optional → default M)
}
```

Rules:

- Cannot disable a module with non-zero external obligations (e.g. curve with open positions) — must graduate or wind down first.
- Adding `governance` with `transfer_authority: true` queues `AssetAuthorityTransfer` (timelock unless same-tx launch).
- `threshold` omitted → `default_threshold(N)` from [§4.4](#44-governance-defaults-multisig--authority-transfer).

### 6.2b `AssetAuthorityTransfer`

```
AssetAuthorityTransferPayloadV1 {
    asset_id,
    new_verifier: GovernanceVerifier,   // Single or Multisig
    effective_height: Option<u64>,      // None = launch-time immediate; Some = timelock queue
    authority_proof: CreatorSig | GovernanceProof,
}
```

- While `authority: Creator`: only creator may initiate; timelock applies unless launch bundled governance.
- While `authority: Governance`: only `GovernanceProof` may change verifier (signer rotation, M change).

### 6.3 `AssetManifestUpdate`

```
AssetManifestUpdatePayloadV1 {
    asset_id,
    manifest_cid,
    manifest_hash,
    authority_proof: CreatorSig | GovernanceProof,
}
```

### 6.4 `AssetRewardsDelegateRotate`

```
AssetRewardsDelegateRotatePayloadV1 {
    asset_id,
    new_delegate_key_id: [u8; 32],
    authority_proof,
}
```

### 6.5 Standard asset operations

| Tx kind | When |
|---------|------|
| `AssetTransfer` | Always (if holder has balance) |
| `AssetMint` | Creator/policy only; fixed-supply assets reject |
| `AssetBurn` | Holder or policy |
| `CurveBuy` / `CurveSell` | `curve` module enabled |
| `RewardsClaim` | `rewards` module enabled; server builds transfer from delegate |

---

## 7. Discovery API

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/assets` | List all assets: id, symbol, module bitmask, manifest CID |
| `GET /api/v1/assets/{id}` | On-chain record + resolved manifest |
| `GET /api/v1/assets/{id}/interface` | Wallet shortcut: `interface` section only |
| `GET /api/v1/assets/{id}/balances/{did}` | Balance lookup |

Deprecate special-casing in `/api/v1/token/list` (projection shim during migration).

---

## 8. BUBL and CBE as configurations

| Field / module | BUBL | CBE |
|----------------|------|-----|
| `supply_mode` | `Fixed` | `Elastic` |
| `curve` | `None` | `Some` |
| `rewards` | `Some` + hot delegate | `None` (or added later) |
| `governance` | optional | `Some(Multisig…)` typical |
| `asset_id` | launch tx hash | launch tx hash |
| Share | same manifest + API | same manifest + API |

---

## 9. Migration plan (PR DAG)

| PR | GitHub | Scope | Notes |
|----|--------|-------|-------|
| **SA-1** | [#2781](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2781) | `SovereignAsset` types + sled tree layout + read projection | No new tx yet; project legacy `TokenContract` / `BondingCurveToken` → asset view |
| **SA-2** | [#2782](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2782) | `GET /api/v1/assets/*` backed by projection | Wallets can adopt discovery before write path |
| **SA-3** | [#2783](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2783) | `AssetLaunch` tx + executor write path | Deprecate `TokenCreation`; `seed_founding_dao` → `seed_asset_launch` |
| **SA-4** | [#2784](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2784) | `RewardsModule` + delegate rotation + validator handler | Replace `ZHTP_REWARDS_TREASURY_KEYSTORE` ticker hack |
| **SA-5** | [#2785](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2785) | `CurveModule` as sub-state of asset | Retire standalone `BondingCurveToken` writes |
| **SA-6** | [#2786](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2786) | `AssetModuleUpgrade` + `GovernanceModule` | Manifest updates; single + multisig |
| **SA-7** | [#2787](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2787) | `AssetManifestUpdate` + DHT pin validation | Full shareability gate |
| **SA-8** | [#2788](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2788) | Remove legacy read paths / deprecate `/api/v1/token/*` | After testnet re-launch |

**Epic:** [#2780](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2780)

**Testnet re-launch note:** After SA-3, BUBL/CBE must be re-launched via `AssetLaunch` (not `TokenCreation`). Document in reset runbook.

---

## 10. Invariants

1. `asset_id` is immutable and equals the launch transaction hash.
2. `symbol` is globally unique among active assets.
3. `manifest_hash` must verify against DHT content at launch and on every update.
4. Module-specific txs are rejected if module not enabled.
5. `treasury_key_id` is always stored on-chain.
6. Rewards outbound transfers only from `spend_delegate_key_id` with positive balance.
7. Once `authority: Governance`, creator has **no** unilateral privileged ops ([§4.5](#45-creator-rights-after-governance-transfer)); provenance fields stay immutable.
8. Multisig: `2 ≤ N ≤ 10`, `1 ≤ M ≤ N`; omitted M uses `floor(N/2)+1`.
9. First `Creator → Governance` transfer respects timelock unless governance launched in same `AssetLaunch`.
10. Replay wipe + re-apply blocks → identical `assets/` and module substates.

---

## 11. Resolved and open questions

### Resolved

| # | Question | Decision |
|---|----------|----------|
| Q4 | Multisig proof wire format | Reuse `ApprovalProof` from `approval_verifier` crate ([§4.4](#44-governance-defaults-multisig--authority-transfer)) |
| Q5 | Multisig threshold defaults | `M = floor(N/2) + 1` when omitted; bounds in [§4.4](#44-governance-defaults-multisig--authority-transfer) |
| Q6 | Creator rights after governance | None privileged; provenance + holder + optional signer seat ([§4.5](#45-creator-rights-after-governance-transfer)) |

### Open (non-blocking)

| # | Question | Lean |
|---|----------|------|
| Q1 | Symbol reservation after asset sunset? | Cooldown registry tree; 90-day tombstone |
| Q2 | Manifest pin failure on launch — hard reject or grace blocks? | Hard reject on validators; gateways may cache |
| Q3 | Max manifest size? | 64 KiB DHT object; hash on-chain only |
| Q7 | Token-weighted governance votes | Out of scope v1; `GovernanceModule` is key-based multisig only |

---

## 12. References

- Existing ABI schema: `lib-blockchain/src/contracts/abi/schema.rs` (`ContractAbi` → manifest `interface`)
- Multisig verifier: `lib-blockchain/src/contracts/approval_verifier/multisig.rs`
- Web4 manifest pattern: chain `manifest_cid` + DHT content (domains)
- Deprecated path: `TokenCreationPayloadV1`, `BondingCurveToken` as parallel identity