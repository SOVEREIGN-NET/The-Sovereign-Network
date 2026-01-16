# @zhtp/sdk - TypeScript SDK for ZHTP/Web4 Protocol

**QUIC-native TypeScript SDK for the ZHTP network** - Built following [zhtp-cli](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/development/zhtp-cli) architectural patterns.

## Architecture Overview

This SDK follows zhtp-cli's **three-layer initialization pattern** and **operation enum** architecture:

```
Layer 1: Load Identity
   loadIdentityFromKeystore() → LoadedIdentity

Layer 2: Build Trust Configuration
   buildTrustConfig() → TrustConfig

Layer 3: Create Authenticated Client
   connectClient() → ZhtpClient (with UHP + Kyber authentication)

Use Client:
   client.domains.register()
   client.wallet.send()
   client.deploy.site()
```

### Design Principles

1. **QUIC-First** - No HTTP. All communication over QUIC with UHP handshake
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
- [ ] UHP handshake orchestration
- [ ] Kyber512 key encapsulation
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

## Usage (When Complete)

### Initialize Client

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
  trustNode: true,  // Bootstrap mode
  nodeDid: 'did:zhtp:...',  // Optional: expect specific node
});

// Layer 3: Create authenticated QUIC client
const client = await connectClient(loaded.identity, trustConfig, 'quic://node.zhtp:5555');

// Ready to use
await client.domains.register('myapp.zhtp', {
  contentCid: 'QmXxxx...',
  fee: 100n,
});
```

### Validation (Pure Functions)

```typescript
import { validateDomain, validateWalletAddress } from '@zhtp/sdk';

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
```

### Dependency Injection for Testing

```typescript
import { MockOutput } from '@zhtp/sdk';

// Use real output
const realOutput = new ConsoleOutput();
await client.domains.register('test.zhtp', {}, realOutput);

// Use mock for testing
const mockOutput = new MockOutput();
await client.domains.register('test.zhtp', {}, mockOutput);
console.log(mockOutput.successes); // ['Domain registered']
```

## Architecture Compared to zhtp-cli

| Aspect | zhtp-cli | SDK |
|--------|----------|-----|
| **Language** | Rust | TypeScript |
| **Transport** | QUIC + UHP | QUIC + UHP |
| **Auth** | Dilithium5 + Kyber512 | Dilithium5 + Kyber512 |
| **Wire Format** | CBOR (4-byte framed) | CBOR (4-byte framed) |
| **Validation** | Pure functions in logic/ | Pure functions in validation.ts |
| **Output** | Output trait | Output interface |
| **Operations** | Enum + config | Enum + config |
| **Error Types** | Domain-specific | Domain-specific |
| **Client Init** | 3-layer pattern | 3-layer pattern |

## Key Files (Reference Implementation)

From zhtp-cli that this SDK mirrors:

- `lib-network/src/client/zhtp_client.rs` - QUIC client pattern
- `lib-network/src/protocols/quic_handshake.rs` - UHP + Kyber handshake
- `lib-protocols/src/wire/mod.rs` - CBOR wire protocol (4-byte framing)
- `zhtp-cli/src/commands/web4_utils.rs` - Client initialization pattern
- `zhtp-cli/src/logic/*.rs` - Pure validation functions

## Development Guide

### Adding a New Operation

1. Add operation enum variant to `types.ts`:
```typescript
export enum DomainOp {
  // ... existing
  MyNewOp = 'my-new-op',
}
```

2. Add configuration to ops map:
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

3. Add validation function to `validation.ts`:
```typescript
export function validateMyNewOp(param: string): ValidationResult {
  const errors = [];
  // validation logic
  return { valid: errors.length === 0, errors };
}
```

4. Implement in manager:
```typescript
// In managers/domain.ts
async myNewOp(params: MyNewOpParams, output: Output): Promise<Result> {
  // Validate
  const validation = validateMyNewOp(params.field);
  if (!validation.valid) {
    throw new ValidationError('Validation failed', validation.errors);
  }

  // Build request
  const config = getDomainOpConfig(DomainOp.MyNewOp);
  const body = { /* ... */ };

  // Send (via QUIC client)
  return await this.client.request(
    config.method,
    config.endpointPath,
    { body },
  );
}
```

### Testing

Use MockOutput for unit tests:

```typescript
import { MockOutput } from '@zhtp/sdk';

it('should register domain', async () => {
  const output = new MockOutput();
  await client.domains.register('test.zhtp', {}, output);

  expect(output.successes.length).toBe(1);
  expect(output.successes[0]).toContain('registered');
});
```

## Security Considerations

- ✅ **Post-Quantum Ready**: Kyber512 KEM + Dilithium5 signatures
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
