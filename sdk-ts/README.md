# @zhtp/sdk - TypeScript SDK for ZHTP/Web4 Protocol

**QUIC-native TypeScript SDK for the ZHTP network** - Built following [zhtp-cli](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/development/zhtp-cli) architectural patterns.

**Platform:** Node.js only (v18+). This SDK is designed for Node.js environments such as CI/CD pipelines and server-side applications. Browser support is not available due to filesystem and QUIC transport requirements.

## Architecture Overview

This SDK follows zhtp-cli's **three-layer initialization pattern** and **operation enum** architecture:

```
Layer 1: Load Identity
   loadIdentityFromKeystore() → LoadedIdentity

Layer 2: Build Trust Configuration
   buildTrustConfig() → TrustConfig

Layer 3: Create Authenticated Client
   connectClient() → ZhtpClient (with UHP v2 authentication)

Use Client:
   client.domains.register()
   client.wallet.send()
   client.deploy.site()
```

### Design Principles

1. **QUIC-First** - No HTTP. All communication over QUIC with UHP v2 handshake
2. **Pure Functions** - Validation functions return results without side effects
3. **Operation Enums** - Polymorphic routing via enum → config lookup
4. **Dependency Injection** - Output trait pattern for testability
5. **Error Context** - Errors carry domain-specific context for debugging
6. **Signed Requests** - All mutations signed with Dilithium5 keypairs
7. **Type Safety** - Full TypeScript with strict mode

## Project Structure

```
src/
├── error.ts              # Domain-specific error types
├── output.ts             # Output abstraction (console/mock/silent)
├── identity.ts           # Identity loading + DID management
├── validation.ts         # Pure validation functions
├── types.ts              # Operation enums + core types
├── managers/             # [TODO] Domain/Wallet/Deploy managers
│   ├── domain.ts
│   ├── wallet.ts
│   └── deploy.ts
├── quic/                 # [TODO] QUIC transport + UHP handshake
│   ├── client.ts
│   ├── handshake.ts
│   └── wire.ts
└── index.ts              # Main exports

tests/
├── unit/                 # [TODO] Unit tests for validation
└── integration/          # [TODO] Integration tests with local node

examples/
├── register-domain.ts    # [TODO] Domain registration example
├── send-tokens.ts        # [TODO] Wallet transfer example
└── deploy-spa.ts         # [TODO] dApp deployment example
```

## Implementation Roadmap

### ✅ Phase 1: Foundation (Current)
- [x] Error types with context
- [x] Output abstraction (Console/Mock/Silent)
- [x] Identity loading interface
- [x] Pure validation functions
- [x] Operation enum definitions
- [x] Core type definitions

### 🔄 Phase 2: QUIC Transport (Next)
- [ ] QUIC client wrapper
- [ ] UHP v2 handshake orchestration (transport-only QUIC)
- [ ] Dilithium5 signature verification
- [ ] CBOR wire protocol encoding
- [ ] Request MAC computation

### 🔄 Phase 3: Managers
- [ ] DomainManager (register, lookup, transfer, etc.)
- [ ] WalletManager (send, stake, history, etc.)
- [ ] DeployManager (deploy site, rollback, etc.)

### 🔄 Phase 4: Examples & Testing
- [ ] Domain registration example
- [ ] Token transfer example
- [ ] dApp deployment example
- [ ] Unit tests
- [ ] Integration tests

## Phase 1: Available Now

### Validation Functions (Pure Functions)

```typescript
import { validateDomain, validateWalletAddress, validateDid } from '@zhtp/sdk';

// Validation returns result object, doesn't throw
const domainResult = validateDomain('my-app.zhtp');
if (!domainResult.valid) {
  console.log('Errors:', domainResult.errors);
}

// Validation errors accumulate
const walletResult = validateWalletAddress('invalid');
// {
//   valid: false,
//   errors: [
//     { field: 'address', message: 'must start with "z"' }
//   ]
// }

// DID validation
const didResult = validateDid('did:zhtp:abc123');
if (didResult.valid) {
  console.log('Valid DID');
}
```

### Fee Calculation

```typescript
import { calculateDomainRegistrationFee, calculateTransactionFee } from '@zhtp/sdk';

// Domain registration fees based on length (in SOV)
const fee1 = calculateDomainRegistrationFee('a.zhtp');           // 5000 SOV (1 char)
const fee2 = calculateDomainRegistrationFee('ab.zhtp');          // 1000 SOV (2 chars)
const fee3 = calculateDomainRegistrationFee('abc.zhtp');         // 100 SOV (3+ chars)

// Transaction fees (base + per-byte)
const txFee = calculateTransactionFee(1000);  // 1000 base + (size * 10)
```

### Dependency Injection for Testing

```typescript
import { ConsoleOutput, MockOutput, SilentOutput } from '@zhtp/sdk';

// Mock output for unit tests
const mockOutput = new MockOutput();
console.log(mockOutput.getAll()); // View all recorded output

// Silent output for production
const silent = new SilentOutput(); // No I/O

// Console output for CLI
const console = new ConsoleOutput(); // Real console with emoji prefixes
```

### Types and Constants

```typescript
import { DomainOp, WalletOp, getDomainOpConfig, VERSION } from '@zhtp/sdk';

// Operation enums for Phase 2+ managers
const domainRegisterOp = getDomainOpConfig(DomainOp.Register);
// { endpointPath: '/api/v1/web4/domains/register', method: 'POST', title: 'Register Domain' }

const walletTransferOp = getDomainOpConfig(WalletOp.Transfer);
// { endpointPath: '/api/v1/wallet/send', method: 'POST', title: 'Transfer' }

console.log(VERSION); // '1.0.0-alpha'
```

## Usage (When Complete - Phase 2+)

### Initialize Client (Phase 2)

```typescript
import {
  loadIdentityFromKeystore,
  buildTrustConfig,
  connectClient,
} from '@zhtp/sdk';

// Layer 1: Load identity
const loaded = await loadIdentityFromKeystore('~/.zhtp/keystore');

// Layer 2: Build trust config
const trustConfig = buildTrustConfig({
  mode: 'bootstrap',  // Bootstrap mode
  nodeDidExpectation: 'did:zhtp:...',  // Optional: expect specific node
});

// Layer 3: Create authenticated QUIC client
const client = await connectClient(loaded.identity, trustConfig, 'quic://node.zhtp:5555');

// Ready to use (Phase 3)
await client.domains.register('myapp.zhtp', {
  contentCid: 'QmXxxx...',
  fee: 100n,
});
```

## Architecture Compared to zhtp-cli

| Aspect | zhtp-cli | SDK |
|--------|----------|-----|
| **Language** | Rust | TypeScript |
| **Transport** | QUIC + UHP | QUIC + UHP |
| **Auth** | UHP v2 (Dilithium5 + Kyber1024) | UHP v2 (Dilithium5 + Kyber1024) |
| **Wire Format** | CBOR (4-byte framed) | CBOR (4-byte framed) |
| **Validation** | Pure functions in logic/ | Pure functions in validation.ts |
| **Output** | Output trait | Output interface |
| **Operations** | Enum + config | Enum + config |
| **Error Types** | Domain-specific | Domain-specific |
| **Client Init** | 3-layer pattern | 3-layer pattern |

## Key Files (Reference Implementation)

From zhtp-cli that this SDK mirrors:

- `lib-network/src/client/zhtp_client.rs` - QUIC client pattern
- `lib-network/src/protocols/quic_handshake.rs` - QUIC transport adapter for UHP v2
- `lib-protocols/src/wire/mod.rs` - CBOR wire protocol (4-byte framing)
- `zhtp-cli/src/commands/web4_utils.rs` - Client initialization pattern
- `zhtp-cli/src/logic/*.rs` - Pure validation functions

## Development Guide (Phase 2+)

### Architecture Pattern: Operation Enums + Config Maps

This SDK follows zhtp-cli's design pattern for adding new operations. When implementing Phase 2 (QUIC transport) and Phase 3 (managers), follow this pattern:

#### 1. Define Operation Enum (types.ts)

```typescript
export enum DomainOp {
  // ... existing operations
  MyNewOp = 'my-new-op',
}
```

#### 2. Add Operation Configuration (types.ts)

Map operations to HTTP endpoint metadata (for Phase 2 QUIC client to use):

```typescript
const DOMAIN_OPS: Record<DomainOp, DomainOpConfig> = {
  // ... existing
  [DomainOp.MyNewOp]: {
    endpointPath: '/api/v1/web4/domains/my-op',
    method: 'POST',
    title: 'My New Operation',
  },
};
```

#### 3. Add Validation Function (validation.ts)

Pure validation functions (no side effects, fully testable):

```typescript
export function validateMyNewOp(param: string): ValidationResult {
  const errors: ValidationIssue[] = [];

  if (!param) {
    errors.push({ field: 'param', message: 'required' });
  }

  return { valid: errors.length === 0, errors };
}
```

#### 4. Implement in Manager (managers/domain.ts - Phase 3)

```typescript
async myNewOp(params: MyNewOpParams, output: Output): Promise<Result> {
  // 1. Validate
  const validation = validateMyNewOp(params.field);
  if (!validation.valid) {
    throw new ValidationError('Validation failed', validation.errors);
  }

  // 2. Get operation config
  const config = getDomainOpConfig(DomainOp.MyNewOp);

  // 3. Build request body
  const body = { /* ... */ };

  // 4. Send via QUIC client
  return await this.client.request(
    config.method,
    config.endpointPath,
    { body },
  );
}
```

### Testing Pattern (Phase 2+)

Use MockOutput for unit tests:

```typescript
import { MockOutput } from '@zhtp/sdk';

it('should register domain', async () => {
  const output = new MockOutput();

  // When Phase 3 managers are implemented:
  // await client.domains.register('test.zhtp', {}, output);

  // Then verify output
  expect(output.successes.length).toBe(1);
  expect(output.successes[0]).toContain('registered');
});
```

## Security Considerations

- ✅ **Post-Quantum Ready**: UHP v2 (Kyber1024 + Dilithium5)
- ✅ **Signed Requests**: All mutations require Dilithium5 signature
- ✅ **Session MAC**: Every request includes BLAKE3-HMAC with session key
- ✅ **Replay Protection**: Sequence numbers prevent replay attacks
- ✅ **TLS 1.3**: QUIC transport layer uses TLS 1.3

## Status

**Alpha (v1.0.0-alpha)** - Foundation layer complete, QUIC transport and managers in progress.

## License

MIT - See LICENSE file

## Contributing

See CONTRIBUTING.md for guidelines

## Resources

- [ZHTP Network](https://github.com/SOVEREIGN-NET/The-Sovereign-Network)
- [zhtp-cli](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/development/zhtp-cli)
- [lib-network](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/development/lib-network)
- [lib-protocols](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/development/lib-protocols)
