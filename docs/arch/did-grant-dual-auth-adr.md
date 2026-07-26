# ADR: One DID, dual-auth grants (identity vs elevation)

**Status:** Proposed  
**Date:** 2026-07-24  
**Epic:** [#2935](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2935)  
**Related:** [authorization-bootstrap-adr.md](./authorization-bootstrap-adr.md)  
**Supersedes (concept):** “multiple job DIDs for one human” as the primary blast-radius strategy

---

## Context

Bootstrap auth (#2935 Phases 1–3) assigns standing roles from a DID (Citizen / Council / InfraAdmin) and evaluates optional `ScopedGrant` records on the principal. That leaves a structural problem:

- **One long-lived DID credential** can accumulate or imply too much power (vote + ops + audit).
- Splitting into **many DIDs per human** shrinks blast radius but breaks “one identity” (legal/natural person).
- Telling operators “don’t put Council keys on a laptop” is **ops advice**, not protocol security.

We need a model where **identity is one DID**, and **elevated power is a separate credential class** with its own secrets, unlock policy, and recovery.

---

## Decision

### 1. One operative DID per subject

- A **natural person** or **legal person** (org/DAO subject) has **one primary subject DID**.
- Subject kind may extend (`NaturalPerson` / `LegalPerson` / Device / …) without minting a second “personhood” DID for each job.
- **Personal baseline** (self wallet, self graph, ordinary app use) requires only **DID authentication**.

Standing **eligibility** (e.g. “listed as council member”) may still be DID-linked in a directory.  
**Exercise of elevated power** must not follow from DID auth alone (see §3).

### 2. Grants are meta-credentials (not second identities)

A **grant** is a first-class capability credential:

| Field (conceptual) | Meaning |
|--------------------|---------|
| `grant_id` | Stable id (store key, audit, revoke) |
| `grantee_did` | Subject DID that may hold it |
| `issuer` | Who issued (council, governance, ops authority) |
| `issuer_kind` | `Council` (vote) or `Protocol` (rule/admission) |
| `domains` / `operations` | What it authorizes |
| `expires_at` / revoke flags | Time and sticky death |
| `grant_auth` | How exercise is proven (key material **not** the personal DID key) |

`ScopedGrant` evaluation (domain, op, expiry, consumed-when-loaded) remains the **authorization** half.  
This ADR adds the **authentication** half: the grant does not elevate a session until **grant auth succeeds**.

#### 2.1 Issuance rails (preassign → claim → exercise)

Grants are **preassigned as offers** against a DID; they are not live power until **claimed**.

| Rail | Intent | Flow |
|------|--------|------|
| **Council** | Human governance | Vote registers **GrantOffer** vs DID → grantee **claims** → dual-auth exercise |
| **Protocol** | Machine admission | Node/operator **requests** (e.g. startup proof) → protocol rule mints **Offer** → DID **claims** → exercise |

Shared lifecycle: `Requested? → Offered → Active (claimed) → Expired|Revoked`.  
Unclaimed offers lapse. **Request ≠ grant.**

**Class split (normative intent):**

- Protocol may mint **node operate / admission** classes (e.g. run validator/observer for `node_id`).
- Protocol must **not** auto-mint halt, full chain export, or cross-wallet audit.
- Council (or rare break-glass) mints **vote / audit / catastrophic ops** classes.

Subject is usually the **operator person/org DID**; `node_id` is grant **scope**, not a second person DID.

Claim prefers **grantee-generated grant pubkey** (secret never on wire); bootstrap may one-shot a secret into external vault only.

Full distribution + phased delivery: [did-grant-dual-auth-implementation-plan.md](./did-grant-dual-auth-implementation-plan.md) §5–§6.

### 3. Dual authentication (hard requirement)

Elevated session establishment:

```text
prove_control(subject_DID)  AND  prove_control(grant)
        →  principal with that grant attached for this session
```

Baseline session:

```text
prove_control(subject_DID)
        →  Citizen (self-only) principal; no elevated grants
```

**Rules:**

1. **Eligibility ≠ exercise.** Being on a Council list (or any role directory) does **not** by itself authorize halt, export, cross-identity wallet read, or other elevated domains.
2. **Elevated domain/op** requires an **authenticated grant** covering that domain/op (and still active).
3. **Role purity target:**
   - **Council eligibility** → pure governance/voting *when* paired with a vote grant (or equivalent), not a god DID.
   - **Ops** → ops grants only (no blanket wallet-other).
   - **Audit** → audit grants only, preferably short TTL.
4. Personal DID remains usable if grant keys are lost; elevated paths fail until recovery/re-issue.

### 4. Key custody: DID keys vs grant keys (non-negotiable)

#### 4.1 Wallet storage policy

| Material | Wallet may persist? | Unlock |
|----------|---------------------|--------|
| **DID-related keys** (identity, device bindings for login) | **Yes** — primary wallet storage | Normal wallet unlock / session |
| **Grant keys** (meta-credential secrets) | **No** as always-hot co-residents of the DID key store | **Separate unlock**, on demand |

**Requirement — separate unlock even on the same machine:**  
If an implementation temporarily holds both materials on one host, **unlocking the wallet for personal DID use must not unlock grant keys**. Grant use requires an **explicit second unlock** (or external provision) per exercise or per elevated session.

**Requirement — cold / external grant credentials (default product posture):**

1. The **wallet only accepts durable storage of DID-related keys**.
2. **Grant secrets are not stored in the hot wallet keystore.** They live on **external storage** (hardware token, air-gapped file, HSM, sealed operator vault, offline backup medium, etc.).
3. To exercise a grant, the user (or operator tooling) **provides the grant key on demand** for that action or elevated session; the wallet/client uses it to produce a **grant proof**, then **must not** leave the grant key unlocked in the same manner as the DID key.
4. Implementations **may** support a strict “cold grant” mode where the binary **refuses** to persist grant private keys at all (only accept one-shot import / sign-then-forget).

Rationale: same machine is not the trust boundary; **same unlock ceremony** is. Co-storage without separate unlock recreates the single super-credential failure mode.

#### 4.2 Session attachment

- Server attaches grants to `SecurityPrincipal` **only after** dual proof for that grant id.
- Grant proofs are **server-time checked** (not client-declared role).
- Prefer short elevated session TTL independent of personal session TTL.

### 5. Loss and recovery

| Lost | Effect | Recovery |
|------|--------|----------|
| **DID key** | Identity control compromised / locked out | Existing identity recovery (social, guardian, re-bind device) — out of scope detail here |
| **Grant key** | Personal DID still works; elevation impossible | **Re-issue** by issuer (council/governance); optional threshold re-share; revoke old `grant_id` |
| **Both** | Full account + elevation recovery | Identity recovery first, then grant re-issue |

**Requirement:** losing a grant key must **not** require minting a new person DID. Recovery is **grant lifecycle**, not identity death.

### 6. Natural vs legal person (optional axis, same machinery)

- **Natural person** DID and **legal person** DID are subject kinds, not extra job DIDs.
- Humans may receive **delegation grants** to act for a legal person on scoped domains (still dual-auth on that grant).
- Same custody rules apply: org grant keys stay cold/external relative to personal hot wallet.

### 7. Relationship to multi-account wallets

Other products isolate power with multiple accounts.  
We isolate power with **one identity + many grants**, each grant a meta-credential with its own secret and unlock path. UX can still show “Council vote”, “Ops”, “Audit” as **capability unlocks**, not as separate people.

---

## Non-goals

- Replacing `lib-access-control` domains/ops.
- Implementing use-count limits without a persistent grant store (see bootstrap ADR).
- Forcing every citizen grant to be hardware-only on day one (product may phase cold-grant for **ops/audit/council exercise** first).
- Multi-DID-as-primary-identity model (explicitly rejected as the main design).

---

## Consequences

### Positive

- Blast radius of a leaked **personal** key is baseline identity, not halt/export/full audit by default.
- Blast radius of a leaked **grant** key is that grant’s domain/op/TTL only.
- Protocol encodes separation; not “please don’t put Council on a laptop.”
- Aligns with one legal/natural identity while supporting multi-capability UX.

### Costs

- UX: elevated actions need **on-demand grant key** (friction is intentional for high power).
- Issuance, revoke, re-issue, and dual-auth session APIs required.
- Clients must **refuse** hot co-unlock of DID + grant keys.
- Bootstrap transition: today’s “Council DID alone can halt/export/read” must be **narrowed** as grants + dual-auth land.

### Migration sketch (not a schedule)

1. Keep DID → Citizen baseline; soft privacy stays.  
2. Stop treating Council/InfraAdmin DID alone as full exercise of ops/audit (eligibility only or temporary dual path).  
3. Issue grants for vote / ops / audit with external grant keys.  
4. Dual-auth session attach; wallet enforces §4 storage rules.  
5. Deprecate fat-role exercise paths.

---

## Implementation hooks (existing code)

| Piece | Today | Target |
|-------|--------|--------|
| `SecurityPrincipal.did` | Subject | Unchanged (one subject) |
| `Role` | Standing assignment from DID lists/env | Eligibility / coarse label; not sole elevated authz |
| `ScopedGrant` | Domain/op/expiry on principal | Plus **grant auth proof** before attach |
| `grants_allow` / policy early grant check | Evaluates attached grants | Only attached after dual-auth |
| Wallet keystore | DID/device material | **DID only** durable; grants external/on-demand |
| `ZHTP_INFRA_ADMIN_DIDS` | Fat InfraAdmin | Migrate to ops **grants** + dual-auth |

---

## Explicit requirements checklist (acceptance criteria for this ADR)

- [ ] One primary subject DID per natural/legal person (job power is not a second person DID).
- [ ] Elevated domain/op requires authenticated grant, not DID-only role.
- [ ] Wallet **durable store = DID-related keys only**.
- [ ] Grant keys: **external / on-demand**; not auto-unlocked with wallet unlock.
- [ ] Same machine still requires **separate unlock** for grant material.
- [ ] Optional **cold-grant mode**: refuse to persist grant private keys.
- [ ] Grant key loss → re-issue/recovery; personal DID remains operative.
- [ ] Server never trusts client-declared elevation without grant proof.
- [ ] Council rail: vote/register **Offer** vs DID → **claim** before exercise (vote alone is not live power).
- [ ] Protocol rail: node **request** → rule mints **Offer** → DID **claim** (request alone is not a grant).
- [ ] Protocol must not mint halt/export/cross-wallet-audit classes; those are council (or break-glass) only.
- [ ] Unclaimed offers lapse; revoke + re-offer for rotation.

---

## References

- `docs/arch/authorization-bootstrap-adr.md` — bootstrap phases, role purity notes  
- `docs/arch/did-grant-dual-auth-implementation-plan.md` — gap analysis, **§5 distribution rails**, phased PR plan  
- `lib-access-control` — `ScopedGrant`, `SecurityPrincipal`, policy engine  
- `zhtp/src/api/principal.rs` — principal extraction (DID path today)

---

## Store consistency (decision)

**Ops / audit / vote grants** that authorize cluster-wide actions (halt, export, cross-wallet audit, governance exercise) **must** use a **chain-backed or gossip-replicated** grant store so claim and **revocation** are consistent across validators.

**Process-local / sled-only** storage is acceptable only for **node-scoped protocol grants** (`NodeOperate`) whose enforcement is intentionally local to that node, and must never be used as the sole source of truth for ops/audit/vote elevation.

Revocation of an ops-class grant must propagate so that every validator stops honoring it within one agreed gossip/block interval (runbook at issuance rail B2a).

