# Testnet credentials vault

**Purpose:** Single offline place for every private key that must survive a chain wipe.  
**Never commit this tree** — keep it on an encrypted volume or password manager + local folder only.

Default location (operator machine):

```
~/zhtp-testnet-vault/
```

Add to your personal backup (not git). Repo `.gitignore` already blocks `keystore*`, `keys/`, `.zhtp/`.

---

## Should we reset council / validator wallets?

| Layer | Reset on chain wipe? | Action |
|-------|----------------------|--------|
| **On-chain balances & registry** | Yes — rebuilt from `genesis.toml` at h=0 | Automatic (151 SOV rows, council wallet `bb12668e…`, ~426 wallet metadata) |
| **Private keys (keystores)** | **No** — not in sled | **Backup before reset; restore only if a node disk is lost** |
| **Council signing keys** | **No** — must match genesis `bootstrap_council` DID | Keep same keystore; rotating requires genesis + config ceremony |
| **Validator node keystores (g1–g3)** | **No** — live under `/opt/zhtp/.zhtp/keystore/` | Backup; wipe does **not** delete keystore |
| **g4 / g5 / gateway keystores** | N/A — hosts retired | Archive once for forensics, then ignore |
| **Wallets created only on-chain** (post-genesis) | Yes — history gone | Need new `WalletRegistration` txs; save keys if you want same holders |

**Recommendation:** Do **not** rotate council or validator keys during this reset. Wipe sled only. After restart, validators self-register using existing node keystores; council signs with the same DID/wallet pair embedded in genesis.

---

## Folder layout

```
~/zhtp-testnet-vault/
├── MANIFEST.md                 # Human index (fill after backup)
├── inventory.json              # Machine-readable (from backup script)
│
├── council/
│   └── bootstrap-council/
│       ├── user_identity.json      # DID did:zhtp:94563ac…
│       ├── user_private_key.json   # Signs halt, DAO, payroll, domain fees
│       ├── node_identity.json      # If council pack includes node DID
│       ├── node_private_key.json
│       └── wallet_data.json
│
├── validators/
│   ├── g1-77.42.37.161/
│   │   ├── keystore/               # Full tar from node
│   │   └── meta.env                # DID, wallet_id, IP (no secrets)
│   ├── g2-77.42.74.80/
│   └── g3-178.105.9.247/
│
├── retired/                      # Optional — one-time archive before decommission
│   ├── g4-148.113.140.176/
│   ├── g5-51.75.62.133/
│   ├── gateway-91.98.113.188/
│   └── gateway2-57.128.30.74/
│
├── tls/                          # QUIC / mesh certs if rotated separately
│   ├── g1-spki-pin.txt
│   ├── g2-spki-pin.txt
│   └── g3-spki-pin.txt
│
└── ops/
    ├── deploy-binary.sha256      # Binary used at reset
    └── reset-2026-07-01.log      # Operator notes
```

---

## What each key file does

Standard keystore files (see `zhtp/src/keyfile_names.rs`):

| File | Holds | Used for |
|------|--------|----------|
| `user_identity.json` | User/citizen DID, metadata | CLI identity, DAO votes, wallet ops |
| `user_private_key.json` | Dilithium + Kyber + master seed | **Signs transactions** |
| `node_identity.json` | Node/validator DID | P2P identity, `ValidatorRegistration` |
| `node_private_key.json` | Node signing material | Consensus votes, mesh auth |
| `wallet_data.json` | Local wallet name, address, balance cache | Node startup; not authoritative vs chain |

**Config-only (public, in repo):** `tools/node-configs/shared.toml` `consensus_key` = Dilithium **public** key for each validator bootstrap entry — must match the node keystore’s public half.

---

## Known DIDs (development genesis)

| Role | DID (hex after `did:zhtp:`) | Wallet ID | Where keys live |
|------|-----------------------------|-----------|-----------------|
| Bootstrap council | `94563acff1be7506bde97263611d03d53c5f1a78ba3712eb986e275a1592c821` | `bb12668e4a979ac4f9bf97203cd95394b51ca9bf6da445f474a82823a541b57e` | Operator `council/` pack (not on validator nodes unless you put it there) |
| Validator g1 | `59e07e17556e2955581443538839d576974e4f8a9af424c0a2cc7df79c995c9d` | (node wallet in keystore) | `g1-…/keystore/` on server |
| Validator g2 | `f37a307761b863130adb6129f16c269af4e395eb3d4b14b070a756bef282c07b` | — | `g2-…/keystore/` |
| Validator g3 | `bf409db91ad276fa35e8af9c78a48facdfba99eb95fcbf01719310e91c558a9c` | — | `g3-…/keystore/` |
| Retired g4 | `14225182b8140220c2adf3e61471ba5f0117f863408ee6b2b86cff4d0f679cef` | — | `retired/g4-…/` archive only |
| Retired g5 | `3218b9025f1b7c678e115c094a73d3e077801f60501452babd43c7a32ecdf284` | — | `retired/g5-…/` archive only |

After wipe, on-chain SOV for council wallet returns from genesis (~9780.3 SOV). **Signing** still requires the council `user_private_key.json` that matches `94563ac…`.

---

## Backup procedure (before reset)

```bash
# From dev machine with SSH to g1–g3
./scripts/backup-testnet-keystores.sh ~/zhtp-testnet-vault

# Council keystore (wherever you keep it — laptop, g1, password manager export)
mkdir -p ~/zhtp-testnet-vault/council/bootstrap-council
cp -a /path/to/council/keystore/* ~/zhtp-testnet-vault/council/bootstrap-council/

# Optional: retired nodes once
./scripts/backup-testnet-keystores.sh ~/zhtp-testnet-vault --include-retired
```

Encrypt the vault:

```bash
tar czf - -C ~ zhtp-testnet-vault | gpg -c -o zhtp-testnet-vault-$(date +%Y%m%d).tar.gz.gpg
```

---

## Restore (only if a node lost its keystore)

```bash
# On target validator (g1 example) — service must be stopped
ssh zhtp-g1 'sudo systemctl stop zhtp'
scp -r ~/zhtp-testnet-vault/validators/g1-77.42.37.161/keystore/* \
  zhtp-g1:/opt/zhtp/.zhtp/keystore/
ssh zhtp-g1 'sudo chown -R zhtp:zhtp /opt/zhtp/.zhtp/keystore && sudo systemctl start zhtp'
```

Council CLI (halt, DAO, payroll):

```bash
export ZHTP_KEYSTORE=~/zhtp-testnet-vault/council/bootstrap-council
./target/release/zhtp-cli -s 77.42.37.161:9334 node halt-consensus --reason upgrade
# or: --keystore $ZHTP_KEYSTORE on subcommands that accept it
```

---

## MANIFEST.md template

Copy into `~/zhtp-testnet-vault/MANIFEST.md` and fill after backup:

```markdown
# Vault manifest — testnet reset YYYY-MM-DD

| Pack | Host | DID | Wallet ID | Backed up | Notes |
|------|------|-----|-----------|-----------|-------|
| council/bootstrap-council | ops laptop | 94563ac… | bb12668e… | yes | halt + DAO |
| validators/g1 | 77.42.37.161 | 59e07e17… | (from wallet_data) | yes | bootstrap leader |
| validators/g2 | 77.42.74.80 | f37a3077… | | yes | |
| validators/g3 | 178.105.9.247 | bf409db9… | | yes | |
| retired/g4 | 148.113.140.176 | 14225182… | | optional | decommissioned |
| retired/g5 | 51.75.62.133 | 3218b902… | | optional | decommissioned |

Binary at reset: sha256=…
Council threshold: 1 (genesis bootstrap_council)
```

---

## Related

- [`docs/protocol/genesis-3-testnet-reset.md`](../protocol/genesis-3-testnet-reset.md) — wipe phases (sled only)
- [`docs/arch/genesis-bootstrap-surface.md`](../arch/genesis-bootstrap-surface.md) — genesis vs on-chain vs node-local