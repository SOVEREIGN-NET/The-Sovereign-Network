# Crypto Signing Cutover Runbook

**Status:** Draft — promote to **Approved** after validator ops review.
**Owner:** Protocol + operations.
**Audience:** Validator operators deploying PR #2745 signing fixes.

PR #2745 corrects broken transaction and identity signing paths and patches
the KyberSlash advisory (`RUSTSEC-2023-0079`). This is a **coordinated
binary deploy**, not a chain restart. Signing semantics change at the moment
validators run the new build.

## What changes

| Area | Before | After |
|------|--------|-------|
| `sign_transaction` | Generated a fresh random keypair per call | Signs with the caller's `PrivateKey` via `KeyPair::from_private_key` |
| `IdentityManager::sign_with_identity` | Returned a Blake3 hash as "signature" | Real Dilithium5 signature with domain prefix `ZHTP-identity-sig-v1\0` |
| Domain updates (`lib-network`) | Structural hex-length check only | Dilithium5 verify when `owner_dilithium_pk` is stored on the record |
| Kyber KEM | `pqc_kyber` (vulnerable) | `pqc_kyber_edit` community fork |

## Why coordinated deploy is required

1. **Transaction signatures** — Any code path that called the old
   `sign_transaction` produced signatures from random keys. After deploy,
   signatures bind to the caller keystore. Mempool txs built with the old
   binary may fail verification on new nodes (and vice versa).

2. **Identity attestations** — New attestations use real Dilithium5 bytes
   with domain separation. Verifiers must run the new `verify_identity_attestation`
   helper (or equivalent) to validate them.

3. **Domain updates** — Records registered after this deploy store
   `owner_dilithium_pk`. Updates to those domains require a valid Dilithium5
   signature over:

   ```
   domain|expected_previous_manifest_cid|new_manifest_cid|timestamp
   ```

   Legacy records without `owner_dilithium_pk` still accept structural-only
   validation during the grace window documented below.

## Pre-deploy checklist

- [ ] PR #2745 merged to `development` and release binaries built from tip.
- [ ] `cargo test -p lib-crypto from_private_key` passes.
- [ ] `cargo test -p lib-blockchain --lib sign_transaction_binds` passes.
- [ ] `cargo test -p lib-network --lib test_domain_update_persists` passes.
- [ ] `cargo test -p lib-identity --lib sign_with_identity_roundtrips` passes.
- [ ] Validator keystores confirmed: Dilithium sk/pk pairs match (no corrupted
      `PrivateKey` structs with mismatched halves).
- [ ] Operators notified ≥24h before cutover window.

## Cutover window

```
Deploy branch:  development @ <merge-sha>
Validators:     g1, g2, g3 (testnet)
Grace end:      T+7 days after deploy (structural-only domain updates disabled)
```

Record the actual merge SHA and datetime here when scheduled:

```
merge_sha:     <pending>
cutover_utc:   <pending>
```

## Deploy sequence

Run on **all validators** in the same maintenance window (rolling is OK
if mempool is paused first).

### 1. Pause mempool ingress

```bash
# On each validator — stop accepting new txs during binary swap
zhtp-cli admin mempool-pause
```

### 2. Drain in-flight work

Wait until each node's mempool is empty or quiescent:

```bash
zhtp-cli admin mempool-status
```

Reject or drop txs signed with pre-cutover semantics if they remain after
5 minutes (they will not verify on new binaries).

### 3. Build and install

```bash
git fetch origin
git checkout development
git pull
cargo build --release --features validator
# Install binary per node playbook (systemd unit restart)
sudo systemctl restart zhtp-validator
```

### 4. Verify health

```bash
zhtp-cli node status
zhtp-cli consensus peers
```

Confirm all three validators report the same `development` tip hash.

### 5. Resume mempool

```bash
zhtp-cli admin mempool-resume
```

### 6. Smoke-test signing paths

```bash
# Transaction signing — must verify on-chain
zhtp-cli wallet transfer --dry-run ...

# Domain update — must produce 9190-char hex signature
zhtp-cli domain update --domain <test>.zhtp ...

# Identity attestation roundtrip (API)
curl -X POST /api/v1/identity/sign ...
```

## Domain registry migration

New registrations automatically persist `owner_dilithium_pk` from the
owner's `ZhtpIdentity.public_key`.

**Legacy records** (registered before cutover, `owner_dilithium_pk` all
zeros):

- Updates continue to work with structural signature validation only.
- Operators SHOULD re-register or run `DomainRegistry::migrate_domains`
  after an owner-initiated update that includes a valid signature, so the
  pubkey is captured on the next registration path.

**After grace window (T+7 days):** plan follow-up issue to reject domain
updates on records without `owner_dilithium_pk`.

## Rollback

If cutover fails:

1. Pause mempool on all validators.
2. Reinstall previous binary (record pre-cutover SHA before deploy).
3. Flush mempool (`zhtp-cli admin mempool-flush`).
4. Resume with old binary.

Do **not** roll back only one validator — mixed signing semantics across
the quorum will cause validation divergence.

## Follow-up work (tracked as GitHub issues)

- Enforce `owner_dilithium_pk` on all domain updates (disable structural-only grace).
- Add `ZHTP-domain-update-v1\0` domain prefix to domain signing (breaking; coordinate with clients).
- On-chain `OnChainDomainRecord` owner pubkey for validator-side domain tx verify.
- Kyber fork audit / upstream tracking for `pqc_kyber_edit`.

## References

- PR #2745: `fix/crypto-signing-kyber-domain`
- RUSTSEC-2023-0079 (KyberSlash)
- Client domain update wire format: `lib-client/src/token_tx.rs::build_domain_update_request`