# Observer Node Onboarding

This guide covers installing and running a ZHTP observer node.

---

## Prerequisites

- A sponsor user DID with `Basic` or higher proof level on-chain
- The observer node binary (`zhtp-observer`) for your platform
- 1000 nSOV in the sponsor account (registration fee)

---

## Installation

### Linux

Download the latest `zhtp-observer-linux-x86_64.tar.gz` from the releases page,
extract, and run directly:

```sh
tar -xzf zhtp-observer-linux-x86_64.tar.gz
./zhtp-observer --config observer.toml
```

### Windows

Download `zhtp-observer-windows-x86_64.zip`, extract, and run:

```powershell
.\zhtp-observer.exe --config observer.toml
```

### macOS

Download the latest `zhtp-observer-macos-x86_64.tar.gz` (Intel) or
`zhtp-observer-macos-aarch64.tar.gz` (Apple Silicon), then extract:

```sh
tar -xzf zhtp-observer-macos-*.tar.gz
```

**Important — macOS Gatekeeper quarantine**

macOS marks binaries downloaded from the internet with a quarantine flag.
Until the release is signed with an Apple Developer ID, Gatekeeper will
block the binary with a security prompt.

Remove the quarantine flag before running:

```sh
xattr -d com.apple.quarantine ./zhtp-observer
```

Then run normally:

```sh
./zhtp-observer --config observer.toml
```

> This is a one-time step per downloaded binary. It does not affect the
> security of the node itself — it only tells macOS you are intentionally
> running this binary.

---

## Registration

Observer registration is a two-step process:

### Step 1 — Get canonical signing bytes

```sh
POST /api/v1/observer/admission/prepare
```

Provide your observer DID, Dilithium public key, endpoints, and your
sponsor DID. The server returns 32 bytes to sign and the current nonce.

See [DEMO-2524.md](demos/DEMO-2524.md) for a full request/response example.

### Step 2 — Submit signed registration

Sign the bytes returned in step 1 with the sponsor's Dilithium key, then:

```sh
POST /api/v1/observer/admission/register
```

On success the transaction enters the mempool. Once included in a block
the observer record is active and the node may begin syncing.

---

## Configuration reference

```toml
# observer.toml
[node]
did      = "did:zhtp:your-observer-node-did"
network  = "mainnet"          # or "testnet"

[sponsor]
did      = "did:zhtp:your-sponsor-did"

[endpoints]
listen   = ["0.0.0.0:9000"]
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| macOS blocks binary on launch | Gatekeeper quarantine | Run `xattr -d com.apple.quarantine ./zhtp-observer` |
| 403 on /admission/prepare | Sponsor DID not found on chain | Ensure sponsor identity is registered |
| 403 on /admission/register | Sponsor proof level too low | Sponsor must have `Basic` or higher |
| Registration tx never confirms | Insufficient nSOV balance | Fund sponsor with at least 1000 nSOV |
