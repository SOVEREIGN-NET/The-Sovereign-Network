# Client Bootstrap Specification v1

## Overview

How clients discover and connect to the ZHTP network without hardcoded validator lists.

## Bootstrap Flow

```
1. App starts
2. Try ZDNS: query network.sov via UDP 53 to bootstrap IPs
3. Get validator IP list (multiple A records)
4. Optionally: GET /api/v1/network/directory for rich metadata
5. Latency probe: QUIC ping to top 3 candidates
6. Connect to fastest validator via QUIC + UHP v2
```

## Step 1: Hardcoded Bootstrap

App ships with 3 bootstrap IPs (current validators):

```
77.42.37.161    (g1 — Helsinki)
77.42.74.80     (g2 — Helsinki)
178.105.9.247   (g3 — Zurich)
```

These are ZDNS server addresses (port 53) AND validator addresses (port 9334).

## Step 2: ZDNS Query

Query `network.sov` via standard DNS (UDP port 53):

```
DNS Query:
  Type: A
  Name: network.sov
  Server: <any bootstrap IP>:53
```

Response:
```
;; ANSWER SECTION:
network.sov.    3600    IN    A    77.42.37.161
network.sov.    3600    IN    A    77.42.74.80
network.sov.    3600    IN    A    178.105.9.247
```

Multiple A records — all active validators. Round-robin ordered.

### DNS query format

Standard RFC 1035 DNS over UDP. Any DNS client library works (iOS: `dnssd`, Android: `DnsResolver`, React Native: native module wrapping system DNS).

### Reserved domains

| Domain | Returns |
|--------|---------|
| `network.sov` | All active validator IPs |
| `directory.sov` | All ZDNS server IPs (for bootstrap refresh) |
| `*.sov` | Gateway IP for Web4 content (existing) |

## Step 3: Rich Directory (Optional)

For more metadata than DNS provides:

```
GET /api/v1/network/directory
Host: <any validator IP>:9334
Transport: QUIC (public mode, no auth required)
```

Response:
```json
{
  "validators": [
    {
      "did": "did:zhtp:59e07e17...",
      "endpoint": "77.42.37.161:9334",
      "stake": 1000,
      "status": "active",
      "last_activity": 28046,
      "healthy": true
    },
    {
      "did": "did:zhtp:f37a3077...",
      "endpoint": "77.42.74.80:9334",
      "stake": 1000,
      "status": "active",
      "last_activity": 28045,
      "healthy": true
    },
    {
      "did": "did:zhtp:bf409db9...",
      "endpoint": "178.105.9.247:9334",
      "stake": 1000,
      "status": "active",
      "last_activity": 28046,
      "healthy": true
    }
  ],
  "zdns_servers": [
    "77.42.37.161:53",
    "77.42.74.80:53",
    "178.105.9.247:53"
  ],
  "network_id": "development",
  "chain_height": 28046,
  "validator_count": 3
}
```

Use this for intelligent routing: pick lowest latency, highest stake, most recent block.

## Step 4: Latency Probe

QUIC connect + close to top 3 candidates. Measure RTT. Pick fastest.

```pseudocode
candidates = dns_response.addresses  // or directory.validators
for each candidate in candidates[0..3]:
    start = now()
    quic_connect(candidate, port=9334, timeout=2s)
    quic_close()
    candidate.latency = now() - start

best = candidates.sort_by(latency).first()
```

## Step 5: Connect

Standard QUIC connection to the selected validator:

```
Transport: QUIC (port 9334)
ALPN: zhtp-uhp/2 (authenticated) or zhtp-public/1 (read-only)
Auth: UHP v2 handshake (Dilithium5 + Kyber1024)
```

## Fallback

If ZDNS fails (port 53 blocked by network):

1. Try the directory API directly on port 9334 (QUIC, public mode)
2. If that also fails, connect to bootstrap IPs directly (hardcoded list)

## Bootstrap Refresh

After connecting, periodically query `directory.sov` to update the bootstrap list. Cache locally so the app doesn't depend on hardcoded IPs after first successful connection.

## Config

The app's network config:

```typescript
const BOOTSTRAP_IPS = [
  "77.42.37.161",
  "77.42.74.80",
  "178.105.9.247",
];

const ZDNS_PORT = 53;
const QUIC_PORT = 9334;
const NETWORK_DOMAIN = "network.sov";
const DIRECTORY_DOMAIN = "directory.sov";
const DIRECTORY_API = "/api/v1/network/directory";
```
