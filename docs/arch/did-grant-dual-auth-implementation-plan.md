# Implementation plan: DID + dual-auth grants

**Status:** Plan (investigation snapshot 2026-07-24)  
**Target ADR:** [did-grant-dual-auth-adr.md](./did-grant-dual-auth-adr.md)  
**Bootstrap context:** [authorization-bootstrap-adr.md](./authorization-bootstrap-adr.md) (#2935 Phases 1–3 shipped)

---

## 1. Executive fit summary

| Dual-auth ADR goal | Current development | Fit |
|--------------------|---------------------|-----|
| One subject DID per person/entity | Device QUIC key → canonical DID; multi-wallet under one DID | **Strong** |
| Personal baseline = DID auth only | Soft privacy + self gates for Citizen | **Strong** |
| Grants as meta-credentials | `ScopedGrant` domain/op/expiry evaluation | **Authz half only** |
| Dual-auth before elevation | Never; grants not attached on live path | **Missing** |
| Eligibility ≠ exercise | Council list / InfraAdmin env **are** full exercise | **Opposite** |
| Wallet stores DID keys only | True for grants (none exist); false for power (fat DID keystore) | **Accidental / weak** |
| Grant keys external, separate unlock, cold optional | No grant keys; keystore always-hot plaintext | **Missing** |
| Role purity (vote / ops / audit) | Fat Council + fat InfraAdmin (+ handler shortcuts) | **Bootstrap only** |

**One-liner:** Identity plumbing matches “one DID.” Elevation is still **prove the right DID keystore**. Grant evaluation is built but **dead in production**. Custody and dual-auth are greenfield.

```text
TODAY:   QUIC DID → Role(Council|InfraAdmin|Citizen) → fat exercise; grants=[]
TARGET:  prove(DID) → Citizen baseline
         prove(DID) ∧ prove(grant) → attach grant → scoped exercise
         wallet: DID keys hot; grant keys external / second unlock / cold
```

---

## 2. What already fits (reuse)

### 2.1 One DID + device binding

| Piece | Location | Role |
|-------|----------|------|
| Principal DID | `zhtp/src/api/principal.rs` | Subject on every request |
| Device → canonical DID | SessionManager + identity_registry | One person, many devices |
| Fail-closed Public | No requester / no spoof Node / no bare Bearer→Citizen | Baseline hygiene |
| Multi-wallet under one DID | `lib-identity` wallet types / HD | UX for “accounts,” not elevation |

### 2.2 Authorization half of grants

| Piece | Location | Role |
|-------|----------|------|
| `ScopedGrant` | `lib-access-control/src/grant.rs` | Coverage + expiry + sticky consumed |
| `grants_allow` / `grant_allows` | grant.rs / principal.rs | Hot-path evaluation |
| Policy early grant allow | `lib-access-control/src/policy.rs` | Works **if** grants attached |
| Soft grant hooks | `may_read_wallet_subject`, `is_ops_elevated` | Dead branches until attach |
| Cap grants-per-principal | `MAX_GRANTS_PER_PRINCIPAL` | DoS bound |

### 2.3 Custody / ceremony precedents (wrong layer, right idea)

| Precedent | Location | Reuse as |
|-----------|----------|----------|
| Alternate `--keystore` / delegate dirs | zhtp-cli | “Provide material for this action” UX |
| Per-wallet password after DID login | `wallet_password.rs` | Second unlock ceremony |
| Ops vault off validators | `docs/ops/testnet-credentials-vault.md` | Cold storage process |
| `op_key_binding_*` | lib-identity-core | Bind non-DID key to DID at issuance |
| Mobile holds keys; web session caps | `mobile_delegation.rs` | Session elevation redesign target |

---

## 3. Gaps (blocking dual-auth)

### 3.1 Protocol / server

| Gap | Severity | Detail |
|-----|----------|--------|
| Grants never attached | **Blocking** | `extract_principal_from_request` → `SecurityPrincipal::new` only |
| No `grant_auth` / proof types | **Blocking** | `ScopedGrant` has no crypto half |
| No dual-auth session API | **Blocking** | No “prove DID + prove grant → elevated session” |
| Eligibility = exercise | **Critical** | Council membership / `ZHTP_INFRA_ADMIN_DIDS` alone elevate |
| Fat Council in policy | **Critical** | Full domain access except private ZK |
| Handler role shortcuts | **Critical** | Bypass policy; InfraAdmin wallet-read contradicts policy matrix |
| Council write-as-other | **Critical** | send/stake/transfer allow `Role::Council` without self match |
| Shutdown ungated | **Critical** | `POST .../node/shutdown` ignores principal |
| No grant store / issue / revoke | **High** | Cannot re-issue or revoke in production |
| Use limits | Deferred | Correctly out of type until store exists |
| Elevated session TTL | **High** | Not modeled |
| QUIC requester encoding drift | **Medium** | `quic_handler` parse vs `router` blake3 of DID string |

### 3.2 Client / custody (ADR §4)

| Gap | Severity | Detail |
|-----|----------|--------|
| No grant key type | **Blocking** | Nothing to store externally |
| Keystore always-hot | **High** | `user_private_key.json` plaintext load, no unlock |
| No separate unlock API | **Blocking** | One load = all power of that DID |
| No cold-grant mode | **High** | Cannot refuse persist of grant sk |
| CLI always loads full DID keystore | **High** | Elevated commands = same key as personal |
| Mobile session caps | **High** | Elevation via same DID signature, not grant proof |

### 3.3 Drift inventory (must fix together)

| Surface | Today allow | Dual-auth target |
|---------|-------------|------------------|
| Halt / export / import / provision | Council \| InfraAdmin role | Ops **grant** + dual-auth |
| Cross-wallet soft read | Council \| InfraAdmin role | Audit **grant** + dual-auth |
| Unfiltered wallet enum | Several fat roles | Audit grant or self |
| DAO council admin APIs | `Role::Council` | Governance **grant** + dual-auth |
| Bootstrap vote | Council membership | Eligibility list + vote grant (or phased) |
| Council send/stake as other | Role bypass | **Remove** or spend-delegation grant |
| Node shutdown | **Open** | Ops grant (or remove endpoint) |
| Self wallet | DID match | Unchanged |

---

## 4. Target architecture (implementation view)

```text
┌─────────────────────────────────────────────────────────────┐
│ Client                                                       │
│  Hot wallet: DID Dilithium/Kyber only                        │
│  Grant vault: external / HSM / file — NOT co-unlocked        │
│  On elevated action: load grant key → proof → forget/lock    │
└───────────────────────────┬─────────────────────────────────┘
                            │ DID session + GrantExerciseProof
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Server                                                       │
│  1. Authenticate subject DID (existing QUIC / session)       │
│  2. Baseline principal: Citizen (+ eligibility labels)       │
│  3. Verify grant proof against GrantRecord (store)           │
│  4. Attach AttachedGrant[] to principal (short TTL session)  │
│  5. Policy / handlers: elevated only via grants_allow        │
└─────────────────────────────────────────────────────────────┘
```

### Types (sketch)

```text
GrantRecord (store / issuance)
  id, grantee_did, issuer_did, domains, ops, expires_at, revoked
  grant_pubkey / scheme
  issuer_attestation over binding

GrantExerciseProof (request)
  grant_id, challenge_or_session_binding, signature(grant_sk)

AttachedGrant (on principal — no secrets)
  id, domains, ops, expires_at  // only after verify
```

Eligibility directories (council list, optional ops allowlist) become **who may be issued grants**, not **who may exercise**.

---

## 5. Grant distribution: two issuance rails + claim

Grants are **preassigned** as offers against a subject DID. They are not “power because you are on a list.” Lifecycle is always:

```text
INTENT → OFFER (registered vs DID) → CLAIM (DID + grant key setup) → EXERCISE (dual-auth)
```

Two rails create offers; **one** claim/exercise machinery consumes them.

```text
                 ┌──────────────────────────┐
                 │     Grant registry        │
                 │  offers + active grants   │
                 └────────────┬─────────────┘
        Council vote          │          Protocol rule
        (human intent)        │          (machine intent)
                 │            │            │
                 ▼            ▼            ▼
              GrantOffer(grantee_did, class, scope, issuer_kind, exp)
                              │
                              ▼
                 Claim by DID (+ bind grant pubkey / cold key)
                              │
                              ▼
                 Active grant → exercise = DID auth ∧ grant auth
```

### 5.1 Lifecycle states

```text
Requested  →  (council vote | protocol accept)  →  Offered
Offered    →  Claimed/Active  →  Expired | Revoked
           ↘  Lapsed (unclaimed TTL) | Rejected
```

| State | Meaning |
|-------|---------|
| **Requested** | Protocol rail only: node/operator submitted a credential request (not yet a grant) |
| **Offered** | Registry row bound to `grantee_did`; **not exercisable** until claim |
| **Active** | Claimed; grant pubkey bound; dual-auth exercise allowed |
| **Revoked / Expired / Lapsed** | Dead; re-issue creates a **new** `grant_id` |

**Unclaimed offers expire.** Claim does not mint a new person DID.

### 5.2 Rail A — Council-granted (governance)

| Step | What happens |
|------|----------------|
| Propose | “Grant DID X: class/domains/ops, TTL, cold required?” |
| Vote | Council / governance passes |
| Register | Protocol writes **GrantOffer** (`issuer_kind=Council`), status=`Offered`, grantee=`X` |
| Claim | X authenticates as DID, **claims** offer → binds grant key (BYO pubkey preferred, or one-shot secret) |
| Exercise | Dual-auth for that grant’s domains only |

**Typical classes (council):**

| Class | Domains (sketch) | Notes |
|-------|------------------|--------|
| `VoteGovernance` | Governance vote/admin exercise | Eligibility list alone is not enough |
| `AuditRead` | WalletGraph Read/Enumerate (short TTL) | Investigation |
| `OpsHalt` / `OpsExport` / … | Halt, export, import, provision | Exceptional / maintenance; cold default |
| `DelegateSpend` (optional) | Explicit act-as for another subject | Replaces Council write-as-other |

Fits: humans and orgs receiving power after a **vote**.

### 5.3 Rail B — Protocol-granted (node / admission)

| Step | What happens |
|------|----------------|
| Request | Node (or operator tooling) at **startup** builds `NodeCredentialRequest`: node_id, desired class (validator/observer), operator subject DID, proof material (genesis allowlist, stake, PoP, admission artifact, …) |
| Submit | Request → chain or admission API (rate-limited; request ≠ grant) |
| Decide | **Protocol rule** (not a human vote each time): e.g. in genesis set, passed observer admission, stake ≥ N |
| Register | Protocol emits **GrantOffer** (`issuer_kind=Protocol`) to operator’s **subject DID**, scope includes `node_id` / cluster |
| Claim | Operator DID claims → activates **NodeOperate**-class grant (not automatic halt/export) |
| Exercise | Node process uses grant (or short-lived node session derived after claim) |

**Typical classes (protocol):**

| Class | Meaning | Not included |
|-------|---------|----------------|
| `NodeOperate` / participate | May run this node class / join mesh-consensus path | Halt, full chain export, cross-wallet audit |
| Future: stake-gated caps | Automated product rights | God-mode |

**Hard split:** protocol grants **admission to operate a node**. Catastrophic ops and audit stay **council-offered** (or rare break-glass), so a validator boot does not mint a fat ops god-credential.

**Subject model:** grantee is usually the **operator person/org DID**; `node_id` is a **scope parameter** on the grant, not a second personhood DID.

### 5.4 Claim ceremony (both rails)

Preferred (cold-friendly):

1. Grantee generates **grant keypair** offline / HSM.  
2. Claim request: DID proof + `grant_id` + **grant pubkey**.  
3. Registry binds pubkey → status=`Active`.  
4. **Secret never crosses the network.**

Bootstrap fallback: one-shot grant secret at claim → operator vault immediately → wallet never co-stores with DID key.

After claim, exercise is unchanged: `prove(DID) ∧ prove(grant)`.

### 5.5 Distribution of secrets (reminder)

| Material | Distribution |
|----------|----------------|
| Offer / Active record | Public to grantee (list-my-offers API); store holds pubkey + metadata |
| Grant secret | External only; BYO at claim or one-shot then vault; **not** DID keystore |
| Re-issue | Revoke old `grant_id` → new offer → claim again |

### 5.6 Types (extend §4 sketch)

```text
issuer_kind: Council | Protocol

GrantRequest          // protocol rail only (pre-offer)
  request_id, operator_did, node_id, class, proofs, created_at

GrantOffer
  grant_id, grantee_did, issuer_kind, class, domains, ops
  scope (e.g. node_id), expires_at, status=Offered, unclaimed_ttl

GrantRecord (Active)  // after claim
  + grant_pubkey, claimed_at, revoked=false

NodeCredentialRequest // concrete GrantRequest for node boot
  // generated at node startup; submitted; awaits Offer
```

### 5.7 Fit vs today

| Piece | Today | Target |
|-------|--------|--------|
| Council list | Exercise power | Eligibility + **who may receive council offers** / vote |
| `ZHTP_INFRA_ADMIN_DIDS` | Fat exercise | Migrate to council **Ops\*** offers or retire |
| Validator/observer boot | Keystore DID + config | `NodeCredentialRequest` → protocol offer → claim `NodeOperate` |
| Manual vault packs | Full DID keystores | Offer/claim + **grant** vault files |

---

## 6. Phased implementation plan

Principles: **never break personal self path**; **dual-path then cut-over**; **custody rules land with first real grant exercise**; **handlers and policy change together**; **offers before fat-role cut-over**.

### Phase A — Align and seal holes (1 PR, low risk)

**Goal:** Stop open holes; document dual path; no UX change for council yet.

1. Gate **node shutdown** with `is_ops_elevated` (or remove).  
2. Reconcile **InfraAdmin wallet read**: match policy (deny cross-wallet) **or** document intentional override — prefer **deny** (ops purity).  
3. Add matrix tests for dual-auth **placeholders** (grant attach elevates; role-only paths flagged).  
4. Fix/note QUIC `requester` encoding consistency.  
5. ADR + this plan linked from tracking epic.

**Exit:** No unauthenticated catastrophic endpoints; InfraAdmin ≠ audit by default.

---

### Phase B — Grant auth types + store + verify + **offer/claim skeleton**

**Goal:** Authentication half + registry lifecycle; still dual-path with fat roles.

1. Extend `lib-access-control`:
   - `GrantAuthDescriptor` / `GrantOffer` / `GrantRecord` / `AttachedGrant`
   - `issuer_kind: Council | Protocol`
   - `verify_grant_proof(record, proof, now, session_binding) -> Result`
   - `SecurityPrincipal::with_authenticated_grants` (only pre-verified)
2. Persistent **grant store** (sled/chain — product choice):
   - key = `grant_id`
   - states: Offered / Active / Revoked / Expired / Lapsed  
   - list-by-grantee (offers + active); no use-count until needed  
3. **Claim API:** DID auth + bind grant pubkey (or one-shot secret bootstrap) → Active.  
4. **Elevate session API:** DID session + `GrantExerciseProof[]` → attach Active grants (short TTL).  
5. Wire `extract_principal` (or middleware): elevated proofs → attach; else baseline.  
6. **Issuance stub (council):** admin/council path registers `GrantOffer` (vote wiring can be manual/genesis first).

**Exit:** Offer → claim → dual-auth exercise in integration test. Fat roles still work (dual path).

---

### Phase B2 — Issuance rails (distribution)

**Goal:** Real preassignment paths.

#### B2a — Council rail

1. Governance/council vote (or bootstrap multi-sig) **registers GrantOffer** vs target DID + class.  
2. Grantee **lists offers** and **claims**.  
3. First production classes: `OpsHalt` / `OpsExport` (cold), `AuditRead` (short TTL), then `VoteGovernance`.  
4. Runbook: vote → offer → claim → vault grant key → elevate.

#### B2b — Protocol rail (node operate)

1. Define `NodeCredentialRequest` + proof adapters (genesis allowlist / admission / stake — start with **allowlist + signature**).  
2. Node **startup** (or `zhtp-cli node request-credential`) submits request.  
3. Protocol acceptor mints **GrantOffer** (`issuer_kind=Protocol`, class=`NodeOperate`, scope=`node_id`) to operator DID.  
4. Operator claims once per deploy/rotation; node loads Active grant / derived session — **not** personal DID as god-mode.  
5. Explicitly **exclude** halt/export/audit from protocol-minted classes.

**Exit:** Council can offer ops/audit/vote; node boot can obtain `NodeOperate` without human vote each time.

---

### Phase C — Client custody (ADR §4 hard requirements)

**Goal:** Protocol + wallet enforce separate unlock / external grant keys.

1. **Wallet / lib-client / CLI:**  
   - Durable keystore remains DID (+ node identity material for mesh) only.  
   - Grant key APIs: `import_grant_key_ephemeral`, `sign_grant_proof`, `lock_grant_key` / drop.  
   - **Refuse** writing grant sk into `user_private_key.json` or always-hot keystore.  
2. **Cold-grant mode** flag: never write grant sk to disk; memory only for one proof.  
3. **Separate unlock:** even if user keeps grant file on same machine, providing it is a **second ceremony**.  
4. CLI: `grants list-offers`, `grants claim`, elevated commands require `--grant-key` / `--grant-file`.  
5. Mobile: grant material separate from DID item; web elevate via grant proof, not only DID cap list.  
6. Node: after protocol offer, claim tooling stores grant material **outside** default user keystore path.

**Exit:** §4 checklist testable; grant sk never in default keystore format.

---

### Phase D — Role purity cut-over (ops first, then audit, then vote)

**Goal:** Eligibility ≠ exercise in production. **Requires B2 offers already claimed** for operators who must keep working.

> **HARD ORDERING GATE (non-negotiable):** A real **Dilithium (or production) `GrantSignatureVerifier`** must land and be wired into elevate **before any Phase D fat-role cut-over**.
>
> - Today elevate accepts `DevAccept` for tests/dev and keeps `Signature` **fail-closed** (`RejectAllVerifier`).
> - Cutting Council / InfraAdmin fat exercise without a working grant crypto path makes ops either **DID-only again** (reverting dual-auth) or **unreachable** (grant proofs never verify).
> - Phase D PRs must depend on: production verifier + claimed Ops\* grants vaulted for break-glass operators + dual-path soak evidence.
>
> Suggested pre-D milestone: **Phase B3 — production grant signature verifier** (Dilithium verify over `grant_exercise_message`, plug into elevate).

| Step | Move to grant-only exercise | Keep during transition |
|------|-----------------------------|------------------------|
| D1 | **Ops:** halt, export, import, provision (+ shutdown) | role **or** claimed Ops\* grant → then grant-only |
| D2 | **Audit:** cross-wallet soft path; unfiltered enum | dual path → grant-only short TTL |
| D3 | **Remove Council write-as-other** | optional `DelegateSpend` grant |
| D4 | **Governance exercise** (council admin APIs) | membership = eligibility; `VoteGovernance` grant |
| D5 | Narrow policy Council branch | matrix rewrite |
| D6 | Retire fat `ZHTP_INFRA_ADMIN_DIDS` exercise | council Ops offers only |
| D7 | Node admission prefers **protocol `NodeOperate` grant** over “any keystore on disk” | dual path then grant-only for new nodes |

**Exit:** Council DID alone cannot halt/export/read-others; node operate is protocol-claimed; InfraAdmin env alone cannot elevate.

---

### Phase E — Product polish

1. Grant recovery / re-issue UX (revoke + new offer + claim).  
2. Elevated session TTL independent of personal session.  
3. Optional threshold grant keys (2-of-n for halt/export).  
4. Observability: audit log `grant_id`, `issuer_kind`, offer→claim events.  
5. Unclaimed offer TTL sweeper; request spam controls.  
6. Deprecate dual path flags; mark dual-auth ADR **Accepted**.

---

## 7. Suggested PR DAG

```text
A1  seal shutdown + InfraAdmin wallet purity + tests
     │
B1  grant types + verify API (lib-access-control)
     │
B2  grant store + Offer/Claim/Active + elevate attach
     │
B3  production Dilithium GrantSignatureVerifier (HARD GATE before D)
     │
B2a council register-offer API (+ bootstrap vote hook)
B2b NodeCredentialRequest + protocol offer (NodeOperate)
     │
C1  client grant key custody + claim CLI (after B1/B2)
     │
D1  ops dual-path → grant-only
D2  audit dual-path → grant-only
D3  remove council write-as-other
D4  governance grant exercise
D7  node admission via protocol grant
D5  policy matrix + ADR Accepted
```

Parallelizable: **B2a ∥ B2b** after **B2**; **C1** after **B2**; **D\*** only after **B2a/B2b + C1** and real claims in vault.

---

## 8. Test plan (by phase)

| Phase | Tests |
|-------|--------|
| A | Shutdown 403 without elevation; InfraAdmin cannot soft-read other wallet |
| B | Offer → claim → proof → attach → `grants_allow`; forged proof denied; unclaimed not exercisable |
| B2a | Council offer → claim → ops/audit exercise; non-grantee cannot claim |
| B2b | Node request → protocol offer → claim `NodeOperate`; request alone does not elevate halt |
| C | Keystore has no grant sk; elevate without `--grant-key` fails; second unlock required |
| D | Council DID without grant: halt 403; with claimed ops grant: allow; node without NodeOperate denied (post cut-over) |
| E | Revoke + re-offer + reclaim; elevated TTL; offer lapse |

---

## 9. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Lock ops out of testnet | Dual-path D1; **pre-offer + claim** ops grants to vault before cut-over |
| Protocol mints fat ops | **Forbid** halt/export/audit classes on `issuer_kind=Protocol` |
| Request spam | Rate-limit; proof required before Offer; Request ≠ Active |
| UX friction | Cold grants for ops/audit; personal path unchanged; NodeOperate claim once per deploy |
| Handler vs policy drift | Single helper: `require_elevated(domain, op)` using policy only |
| Grant attach without proof | Production only `with_authenticated_grants` |
| Same machine co-storage | Spec + client refuse co-unlock; cold mode default for Ops\* |
| Unclaimed offers pile up | Unclaimed TTL + lapse sweeper |
| Bootstrap docs conflict | Bootstrap ADR historical; dual-auth ADR + this plan are target |

---

## 10. What not to do

- Do **not** add grant private keys to `user_private_key.json`.  
- Do **not** mint a second person DID per job as the primary model.  
- Do **not** reintroduce `max_uses` without a store.  
- Do **not** cut fat Council before ops grants are **offered, claimed, and vaulted**.  
- Do **not** start Phase D cut-over before a **production Dilithium grant verifier** is live on elevate (see Phase D hard gate).  
- Do **not** ship production elevate that only accepts `DevAccept`.  
- Do **not** fix only `AccessPolicy` while leaving handler role shortcuts.  
- Do **not** treat a protocol node request as an Active grant without claim.  
- Do **not** let protocol `NodeOperate` imply halt/export/audit.  
- Do **not** skip claim (vote alone must not enable exercise).

---

## 11. Immediate next action

1. **Land shutdown gate on `development` immediately** (surgical PR; do not wait on docs stack).  
2. Land dual-auth stack A → B1 → B2 (docs + types + elevate skeleton).  
3. **Phase B3:** production Dilithium `GrantSignatureVerifier` on elevate (hard gate before D).  
4. Phase C custody + B2a/B2b issuance rails; claim + vault Ops\* for operators.  
5. Only then Phase D fat-role cut-over.

No production dual-auth until B+B2+B3+C; bootstrap fat roles remain intentional until D cut-over.
**Ordering:** B3 (real verifier) **before** D, always.
