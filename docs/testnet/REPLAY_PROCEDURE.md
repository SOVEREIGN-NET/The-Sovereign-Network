# Testnet Chain Replay Procedure

**Last executed**: 2026-04-18
**Chain height at replay**: ~1600

---

## Prerequisites

- CLI binary: `cargo build --profile dev-release -p zhtp-cli`
- Snapshot files in `docs/testnet/`:
  - `testnet_snapshot_2026-04-14.json` — 16 identities, 409 wallets
  - `cbe_transactions_original_payroll_2026-04-13.json` — 15 CBE payroll transfers
- Council member keystore (see below)
- Chain running on g1 (77.42.37.161:9334)

---

## 1. Council Member Keystore

The only council member with signing authority is `did:zhtp:94563acff1be7506bde97263611d03d53c5f1a78ba3712eb986e275a1592c821`.

### Location

Backup file exported from the mobile app:
```
~/Downloads/sov-identity-backup-94563acff1bcze-1776150773219.zkdid.json
```

### Extraction

The `.zkdid.json` file contains a `keystore_base64` field which is a **base64-encoded tar archive** with two files:
- `keystore/user_identity.json` — public identity (DID, public keys)
- `keystore/user_private_key.json` — private keys (dilithium_sk, kyber_sk, master_seed)

```python
import json, base64, tarfile, io, os

d = json.load(open("path/to/backup.zkdid.json"))
raw = base64.b64decode(d["keystore_base64"])
tar = tarfile.open(fileobj=io.BytesIO(raw))

outdir = "/tmp/council_keystore"
os.makedirs(outdir, exist_ok=True)
for member in tar.getmembers():
    f = tar.extractfile(member)
    if f:
        with open(os.path.join(outdir, os.path.basename(member.name)), "wb") as out:
            out.write(f.read())
```

### Format Conversion

The mobile app exports keys as **byte arrays**. The CLI expects:
- `user_identity.json` — **leave as arrays** (serde deserializes arrays natively)
- `user_private_key.json` — **convert arrays to hex strings**, pad `master_seed` to 64 bytes

```python
import json

pk = json.load(open("/tmp/council_keystore/user_private_key.json"))

# Convert byte arrays → hex strings
for k in pk:
    if isinstance(pk[k], list):
        pk[k] = bytes(pk[k]).hex()

# Pad master_seed from 32 bytes (64 hex) to 64 bytes (128 hex)
if len(pk["master_seed"]) < 128:
    pk["master_seed"] = pk["master_seed"] + "0" * (128 - len(pk["master_seed"]))

with open("/tmp/council_keystore/user_private_key.json", "w") as f:
    json.dump(pk, f)
```

**Do NOT convert `user_identity.json`** — it must stay as arrays or the CLI crashes with "expected a sequence".

---

## 2. Wallet Provisioning

All wallets from the snapshot are in `genesis.toml` and get created at node startup. Provisioning is only needed for wallets added AFTER the genesis snapshot was taken.

### Command

```bash
./target/dev-release/zhtp-cli -s 77.42.37.161:9334 wallet provision \
  --wallet-id <32-byte-hex> \
  --owner <32-byte-hex-identity-id> \
  --wallet-type Primary \
  --welcome-bonus \
  --public-key <dilithium-pk-hex-5184-chars>
```

- `--welcome-bonus` only on Primary wallets (mints 5000 SOV)
- `--public-key` required if the identity is not already registered on-chain
- The endpoint auto-creates an IdentityRegistration system tx if the owner doesn't exist
- Already-existing wallets return 400 "already exists" — safe to retry

### Run from local machine

The CLI connects over QUIC to g1. Do NOT run from g1 itself — the keystore on g1 has a broken handshake.

---

## 3. CBE Payroll Replay

### Decimal Systems

| Token | Old system | New system | Conversion factor |
|-------|-----------|------------|-------------------|
| CBE   | 8 decimals | 18 decimals | × 10^10 |
| SOV   | 8 decimals | 18 decimals | × 10^10 |

**CRITICAL**: The snapshot amounts are in **8-decimal atoms**. The payroll `--amount-cbe` field expects **18-decimal atoms**. Multiply by `10^10`.

Example: snapshot amount `87,671,600,000,000` = 876,716 CBE at 8 decimals
→ `87,671,600,000,000 × 10,000,000,000` = `876,716,000,000,000,000,000,000` (18-decimal atoms)

### Verification

`5,930,842 CBE` total was distributed across 15 transfers (per RESET_CHECKLIST.md).
`593,084,200,000,000` total atoms in snapshot ÷ `10^8` = `5,930,842 CBE` ✓

### Payroll Command

```bash
./target/dev-release/zhtp-cli -s 77.42.37.161:9334 cbe payroll \
  --contract-id <32-byte-hex> \
  --amount-cbe <18-decimal-atoms> \
  --collaborator <32-byte-hex-wallet-id> \
  --deliverable-hash <32-byte-hex> \
  --keystore /tmp/council_keystore
```

- `--contract-id`: unique per transfer (use deterministic hash)
- `--amount-cbe`: collaborator receives exactly this amount (48% of gross)
- Gross mint = amount × 25/12 ≈ 2.083× (split: 20% treasury, 32% reserve, 48% collaborator)
- `--deliverable-hash`: unique per transfer (use deterministic hash)
- Signer must be a Bootstrap Council member

### Generating Commands

```python
import json, hashlib

cbe = json.load(open("docs/testnet/cbe_transactions_original_payroll_2026-04-13.json"))

for i, t in enumerate(cbe):
    amount_8dec = int(t["amount"])
    amount_18dec = amount_8dec * 10_000_000_000  # 8-dec → 18-dec
    to = t["to"]
    contract_id = hashlib.sha256(f"replay_correct_{i}_{to}".encode()).hexdigest()
    deliverable = hashlib.sha256(f"replay_correct_deliv_{i}_{to}".encode()).hexdigest()
    print(f"{to}|{amount_18dec}|{contract_id}|{deliverable}")
```

### Execution

```bash
while IFS='|' read -r collaborator amount contract_id deliverable; do
  ./target/dev-release/zhtp-cli -s 77.42.37.161:9334 cbe payroll \
    --contract-id "$contract_id" \
    --amount-cbe "$amount" \
    --collaborator "$collaborator" \
    --deliverable-hash "$deliverable" \
    --keystore /tmp/council_keystore
  sleep 2
done < /tmp/payroll_correct.txt
```

---

## 4. Domain Replay

Use `scripts/replay-domains.sh`:
```bash
./scripts/replay-domains.sh 77.42.37.161:9334 docs/testnet/domain_snapshot_2026-04-15.json
```

---

## 5. What NOT To Do

- **NEVER wipe sled on all nodes simultaneously** — destroys all chain state with no recovery
- **Do NOT multiply CBE amounts by 10^6** — that's SOV 12-dec→18-dec, CBE is 8-dec→18-dec (× 10^10)
- **Do NOT convert `user_identity.json` arrays to hex** — the serde deserializer expects arrays
- **Do NOT run CLI from g1** — the keystore on g1 has a broken keypair, run from local machine

---

## Files Reference

| File | Purpose |
|------|---------|
| `docs/testnet/testnet_snapshot_2026-04-14.json` | Full snapshot: identities, wallets |
| `docs/testnet/cbe_transactions_original_payroll_2026-04-13.json` | Original 15 CBE payroll transfers (8-decimal atoms) |
| `docs/testnet/domain_snapshot_2026-04-15.json` | Domain registrations |
| `genesis.toml` | Genesis allocations (validators, council, wallets) |
| `scripts/replay-chain.sh` | Automated replay script (wallet provisioning) |
| `scripts/replay-domains.sh` | Domain recovery script |
| `tools/replay_wallets.rs` | Wallet replay JSON generator (not a submitter) |
