# @zhtp/sdk - TypeScript SDK for ZHTP/Web4

Production-ready TypeScript SDK for the ZHTP/Web4 API. Register domains, deploy dApps, and manage wallets from Node.js or browser environments.

## Features

- ✅ **Domain Management** - Register, lookup, transfer, and renew domains
- ✅ **Content Storage** - Upload blobs and manifests to IPFS-like storage
- ✅ **dApp Deployment** - One-command deployment of SPAs and static sites
- ✅ **Wallet Operations** - Send tokens, stake, check balances
- ✅ **Type-Safe API** - Full TypeScript support with IntelliSense
- ✅ **Automatic Retry** - Exponential backoff on network errors
- ✅ **Progress Tracking** - Callbacks for upload and deployment progress

## Installation

```bash
npm install @zhtp/sdk
```

## Quick Start

```typescript
import { createClient } from '@zhtp/sdk';

// Create client with your public key
const client = createClient('your-public-key-hex', 'http://localhost:8080');

// Register a domain
const result = await client.domains.register('myapp.zhtp', {
  contentCid: 'QmXxxx...',
  fee: 1080,
});

console.log(`Registered: ${result.domain}`);
console.log(`Expires: ${new Date(result.expiresAt)}`);
```

## Usage Examples

### Domain Management

```typescript
import { IdentityManager, createZhtpClient } from '@zhtp/sdk';

// Create identity from public key
const identity = IdentityManager.fromPublicKey('public-key-hex');
const client = createZhtpClient(identity, 'http://localhost:8080');

// Check domain availability
const available = await client.domains.check('myapp.zhtp');

// Register domain
const domain = await client.domains.register('myapp.zhtp', {
  contentCid: 'QmXxxx...',
  metadata: {
    description: 'My awesome dApp',
    author: 'me@example.com',
  },
});

// Get domain info
const info = await client.domains.getInfo('myapp.zhtp');

// Renew domain
const renewed = await client.domains.renew('myapp.zhtp', 2);

// Get domain history
const history = await client.domains.getHistory('myapp.zhtp', 10);
```

### Content Management

```typescript
import fs from 'fs';

// Upload a blob (file)
const fileData = fs.readFileSync('index.html');
const cid = await client.content.uploadBlob(
  fileData,
  'text/html'
);

console.log(`Uploaded to: ${cid}`);

// Fetch blob
const content = await client.content.fetchBlob(cid);

// Upload manifest
const manifest = {
  version: 1,
  created: Date.now(),
  updated: Date.now(),
  files: {
    'index.html': {
      cid: 'QmXxxx...',
      size: 1234,
      mimeType: 'text/html',
      path: 'index.html',
    },
  },
};

const manifestCid = await client.content.uploadManifest(manifest);
```

### dApp Deployment

```typescript
// Deploy a website to a domain
const deployment = await client.deploy.deploySite(
  'myapp.zhtp',
  './dist',
  'spa',
  (progress) => {
    console.log(`${progress.percentage.toFixed(0)}% - ${progress.status}`);
  }
);

console.log(`Deployed to: ${deployment.url}`);
console.log(`Files: ${deployment.filesDeployed}`);
console.log(`Size: ${deployment.totalSize} bytes`);

// Update existing deployment
const updated = await client.deploy.update('myapp.zhtp', './dist');

// Get deployment history
const deployments = await client.deploy.getDeployments('myapp.zhtp');

// Rollback to previous version
await client.deploy.rollback('myapp.zhtp', 2);
```

### Wallet Operations

```typescript
// Get wallet balance
const balance = await client.wallet.getBalance();

console.log(`Balance: ${balance.balance} ZHTP`);
console.log(`Staked: ${balance.stakedAmount || 0} ZHTP`);

// List all wallets
const wallets = await client.wallet.listWallets();

// Send tokens
const txHash = await client.wallet.send(
  'recipient-address',
  1000, // amount in ZHTP
  {
    memo: 'Payment for service',
  }
);

console.log(`Transaction: ${txHash}`);

// Stake tokens
const stakeTx = await client.wallet.stake(5000);

// Unstake tokens
const unstakeTx = await client.wallet.unstake(2000);

// Get transaction history
const transactions = await client.wallet.getTransactions(undefined, 20);

// Get single transaction
const tx = await client.wallet.getTransaction(txHash);
```

## API Reference

### ZhtpClient

Main client for interacting with ZHTP/Web4 API.

```typescript
const client = new ZhtpClient(identity, {
  baseUrl: 'http://localhost:8080',
  timeout: 30000,
  retryAttempts: 3,
  retryDelay: 100,
});

// Properties
client.domains   // DomainManager
client.content   // ContentManager
client.deploy    // DeployManager
client.wallet    // WalletManager

// Methods
await client.healthCheck()           // Check server connectivity
await client.getServerInfo()         // Get server version info
client.setHeader(name, value)        // Set default header
client.removeHeader(name)            // Remove default header
client.getIdentity()                 // Get identity
client.getTransport()                // Get transport layer
```

### DomainManager

```typescript
// Register domain
await client.domains.register(domain, options)

// Check availability
await client.domains.check(domain)

// Get info
await client.domains.getInfo(domain)

// Transfer ownership
await client.domains.transfer(domain, newOwner, proof)

// Release domain
await client.domains.release(domain)

// Get status
await client.domains.getStatus(domain)

// Get history
await client.domains.getHistory(domain, limit)

// Renew domain
await client.domains.renew(domain, years, fee)

// Batch operations
await client.domains.checkBatch(domains)
await client.domains.getInfoBatch(domains)
```

### ContentManager

```typescript
// Upload blob
await client.content.uploadBlob(data, contentType, onProgress)

// Upload chunked (automatic for >5MB)
// Large files are automatically split into 5MB chunks

// Fetch blob
await client.content.fetchBlob(cid)

// Upload manifest
await client.content.uploadManifest(manifest)

// Fetch manifest
await client.content.fetchManifest(cid)

// Check existence
await client.content.contentExists(cid)

// Get info
await client.content.getContentInfo(cid)

// Publish content
await client.content.publishContent(cid, metadata)

// Delete content
await client.content.deleteContent(cid)
```

### DeployManager

```typescript
// Deploy site
await client.deploy.deploySite(
  domain,
  buildDir,
  'spa' | 'static',
  onProgress,
  metadata
)

// Update deployment
await client.deploy.update(domain, buildDir, onProgress, metadata)

// Get deployments
await client.deploy.getDeployments(domain)

// Rollback
await client.deploy.rollback(domain, version)

// Delete
await client.deploy.delete(domain)
```

### WalletManager

```typescript
// List wallets
await client.wallet.listWallets(identityId)

// Get balance
await client.wallet.getBalance(address, walletType)

// Send tokens
await client.wallet.send(to, amount, from, options)

// Stake
await client.wallet.stake(amount, options, identityId)

// Unstake
await client.wallet.unstake(amount, options, identityId)

// Get transactions
await client.wallet.getTransactions(address, limit, offset)

// Get single transaction
await client.wallet.getTransaction(txHash)

// Estimate fee
await client.wallet.estimateFee(amount, walletType)

// Check address exists
await client.wallet.addressExists(address)

// Batch get wallets
await client.wallet.getWalletsBatch(addresses)
```

### IdentityManager

```typescript
// Create from public key
const identity = IdentityManager.fromPublicKey('public-key-hex');

// Create from config
const identity = IdentityManager.from({
  id: 'identity-id',
  publicKey: 'public-key-hex',
  privateKey: 'private-key-hex', // optional
});

// Get properties
identity.getIdentity()           // Full identity object
identity.getId()                 // Identity ID
identity.getDid()                // DID (did:zhtp:...)
identity.getPublicKey()          // Hex-encoded public key
identity.getPublicKeyBytes()     // Uint8Array
identity.hasPrivateKey()         // Check if private key available
identity.getPrivateKey()         // Get private key if available
identity.setPrivateKey(key)      // Set private key
identity.serialize()             // Export for storage
```

## Crypto Utilities

```typescript
import {
  blake3Hash,
  calculateContentHash,
  bytesToHex,
  hexToBytes,
  base64Encode,
  base64Decode,
  stringToBytes,
  bytesToString,
  calculateDomainFee,
  validateDomain,
  generateDid,
  extractPublicKeyFromDid,
} from '@zhtp/sdk';

// Hash content
const hash = blake3Hash(data);
const hashHex = calculateContentHash(data);

// Encoding
const hex = bytesToHex(bytes);
const bytes = hexToBytes(hex);
const b64 = base64Encode(data);
const decoded = base64Decode(b64);

// Domain operations
const isValid = validateDomain('myapp.zhtp');
const fee = calculateDomainFee('myapp.zhtp', 1);

// Identity
const did = generateDid('public-key-hex');
const key = extractPublicKeyFromDid('did:zhtp:xxx');
```

## Configuration

### Client Options

```typescript
interface ClientOptions {
  baseUrl: string;           // API server URL
  timeout?: number;          // Request timeout (ms), default: 30000
  retryAttempts?: number;    // Max retry attempts, default: 3
  retryDelay?: number;       // Initial retry delay (ms), default: 100
  debug?: boolean;           // Enable debug logging, default: false
}
```

### Register Options

```typescript
interface RegisterOptions {
  contentCid?: string;       // Content to link
  fee?: number;              // Registration fee (auto-calculated if not provided)
  years?: number;            // Registration period, default: 1
  metadata?: Record<string, string>;
  governance?: {
    config?: {
      contractAddress?: string;
      did?: string;
    };
    delegate?: {
      delegate: string;
      expiration?: number;
    };
  };
}
```

## Error Handling

```typescript
import { HttpError } from '@zhtp/sdk';

try {
  await client.domains.register('invalid domain!');
} catch (error) {
  if (error instanceof HttpError) {
    console.error(`HTTP ${error.status}: ${error.statusText}`);
    console.error(error.body);
  } else {
    console.error(error.message);
  }
}
```

## Progress Callbacks

```typescript
interface ProgressCallback {
  (progress: {
    loaded: number;      // Bytes loaded
    total: number;       // Total bytes
    percentage: number;  // 0-100
    status: string;      // Current status
  }): void;
}

// Use in uploads and deployments
await client.deploy.deploySite(
  'myapp.zhtp',
  './dist',
  'spa',
  (progress) => {
    console.log(`${progress.percentage.toFixed(0)}% - ${progress.status}`);
  }
);
```

## Comparison with zhtp-cli

| Feature | SDK | CLI |
|---------|-----|-----|
| Domain registration | ✅ | ✅ |
| Deploy websites | ✅ | ✅ |
| Wallet operations | ✅ | ✅ |
| Programmatic access | ✅ | ❌ |
| JavaScript/TypeScript | ✅ | ❌ |
| Scripting | ✅ | ✅ |
| Browser support | Planned | ❌ |

## Roadmap

### v1.0.0 (Current)
- ✅ HTTP/REST transport
- ✅ Domain management
- ✅ Content uploads
- ✅ dApp deployment
- ✅ Wallet operations
- ✅ Type-safe API

### v2.0.0 (Planned)
- 🚀 Native QUIC transport
- 🚀 Dilithium2 signatures via WASM
- 🚀 Browser support
- 🚀 React hooks
- 🚀 GitHub Actions

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT - See [LICENSE](LICENSE) file for details

## Support

- GitHub Issues: [Report bugs](https://github.com/zhtp-community/sdk-ts/issues)
- Documentation: [Full API docs](https://docs.zhtp.io/sdk)
- Community: [Discord](https://discord.gg/zhtp)

---

**Built for ZHTP** - The next generation of decentralized internet infrastructure
