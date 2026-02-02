# Domain Management

This document defines how `.sov` domains are created, inspected, updated, and renewed on the Sovereign Network.

This document covers **domain lifecycle only**. It does not include build steps, CI configuration, or deployment workflows.

---

## Authority Model

- A domain is bound to **one identity (DID)**
- That identity has full authority over the domain
- There are no delegated roles or secondary identities

If you control the keystore, you control the domain.

---

## Prerequisites

You must have:

- `zhtp-cli` installed
- An existing identity keystore

---

## Create Identity (if not already created)

```bash
zhtp-cli identity create --keystore ~/.zhtp/keystore
zhtp-cli identity show --keystore ~/.zhtp/keystore
```

Result:
- Keystore file exists
- Output includes `did:sov:`

---

## Register Domain

```bash
zhtp-cli domain register your-site.sov --keystore ~/.zhtp/keystore
```

Result:
- Command completes without error

---

## View Domain Information

```bash
zhtp-cli domain info your-site.sov --keystore ~/.zhtp/keystore
```

Result:
- Domain ownership and metadata displayed

---

## Renew Domain

```bash
zhtp-cli domain renew your-site.sov --keystore ~/.zhtp/keystore
```

Result:
- Domain expiration extended

---

## Update Domain Records

```bash
zhtp-cli domain update your-site.sov \
  --content-hash <CID> \
  --keystore ~/.zhtp/keystore
```

Result:
- Domain record updated

---

## Backup and Recovery

- Back up your keystore immediately
- Loss of keystore = permanent loss of domain control

---

## Security Notes

- Keystore equals full authority
- Base64 encoding is not encryption
- Protect the keystore like a private key

