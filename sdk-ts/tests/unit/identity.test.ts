import { describe, it, expect } from 'vitest';
import {
  generateDid,
  extractPublicKeyFromDid,
  createIdentity,
  validateIdentity,
  serializeIdentity,
} from '../../src/identity.js';

describe('Identity Management', () => {
  // Must be valid hex for DID format: did:zhtp:{hex_key}
  const testPublicKey = '0123456789abcdef0123456789abcdef';
  const testPrivateKeyMaterial = {
    dilithiumSk: 'base64_dilithium_sk',
    kyberSk: 'base64_kyber_sk',
    masterSeed: 'base64_master_seed',
  };

  describe('generateDid', () => {
    it('generates DID from public key', () => {
      const did = generateDid(testPublicKey);
      expect(did).toBe(`did:zhtp:${testPublicKey}`);
    });

    it('handles different public key formats', () => {
      const keys = [
        '0123456789abcdef',
        'ABCDEF0123456789',
        'a' + 'b'.repeat(100),
      ];

      keys.forEach(key => {
        const did = generateDid(key);
        expect(did).toBe(`did:zhtp:${key}`);
      });
    });

    it('handles empty public key (note: result fails validation)', () => {
      const did = generateDid('');
      // generateDid itself doesn't validate - it just concatenates
      // but 'did:zhtp:' would fail validateDid() since it requires hex characters
      expect(did).toBe('did:zhtp:');
    });
  });

  describe('extractPublicKeyFromDid', () => {
    it('extracts public key from valid DID', () => {
      const did = 'did:zhtp:abc123def456';
      const publicKey = extractPublicKeyFromDid(did);
      expect(publicKey).toBe('abc123def456');
    });

    it('throws SdkError for invalid DID format', () => {
      expect(() => extractPublicKeyFromDid('invalid-did')).toThrow();
      expect(() => extractPublicKeyFromDid('did:other:abc123')).toThrow();
      expect(() => extractPublicKeyFromDid('')).toThrow();
    });

    it('handles long public keys', () => {
      const longKey = 'a'.repeat(256);
      const did = `did:zhtp:${longKey}`;
      const extracted = extractPublicKeyFromDid(did);
      expect(extracted).toBe(longKey);
    });
  });

  describe('createIdentity', () => {
    it('creates valid identity from components', () => {
      const identity = createIdentity('test-id', testPublicKey, testPrivateKeyMaterial);

      expect(identity.identity.id).toBe('test-id');
      expect(identity.identity.publicKey).toBe(testPublicKey);
      expect(identity.identity.did).toBe(`did:zhtp:${testPublicKey}`);
      expect(identity.identity.isActive).toBe(true);
      expect(identity.identity.createdAt).toBeDefined();
      expect(identity.keypair.publicKey).toBe(testPublicKey);
      expect(identity.keypair.privateKey).toEqual(testPrivateKeyMaterial);
    });

    it('sets isActive to true by default', () => {
      const identity = createIdentity('test', testPublicKey, testPrivateKeyMaterial);
      expect(identity.identity.isActive).toBe(true);
    });

    it('sets createdAt timestamp', () => {
      const before = Math.floor(Date.now() / 1000);
      const identity = createIdentity('test', testPublicKey, testPrivateKeyMaterial);
      const after = Math.floor(Date.now() / 1000);

      expect(identity.identity.createdAt).toBeGreaterThanOrEqual(before);
      expect(identity.identity.createdAt).toBeLessThanOrEqual(after);
    });

    it('throws error for invalid DID', () => {
      // Create invalid public key that would fail validation
      const invalidKey = 'INVALID_NOT_HEX'; // Non-hex key makes invalid DID
      expect(() => createIdentity('test', invalidKey, testPrivateKeyMaterial)).toThrow();
    });

    it('preserves private key material exactly', () => {
      const custom = {
        dilithiumSk: 'custom_dilithium',
        kyberSk: 'custom_kyber',
        masterSeed: 'custom_seed',
      };
      const identity = createIdentity('test', testPublicKey, custom);
      expect(identity.keypair.privateKey).toEqual(custom);
    });
  });

  describe('validateIdentity', () => {
    it('validates correct identity', () => {
      const loaded = createIdentity('test-id', testPublicKey, testPrivateKeyMaterial);
      const error = validateIdentity(loaded);
      expect(error).toBeNull();
    });

    it('detects invalid DID', () => {
      const loaded = createIdentity('test-id', testPublicKey, testPrivateKeyMaterial);
      // Manually corrupt the DID
      loaded.identity.did = 'invalid:format:xyz';

      const error = validateIdentity(loaded);
      expect(error).not.toBeNull();
      expect(error).toBeInstanceOf(Error);
      expect(error?.message).toContain('validation');
    });

    it('detects public key mismatch between identity and DID', () => {
      const loaded = createIdentity('test-id', testPublicKey, testPrivateKeyMaterial);
      // Manually change identity public key - note: must still be valid hex
      loaded.identity.publicKey = 'fedcba9876543210fedcba9876543210';

      const error = validateIdentity(loaded);
      expect(error).not.toBeNull();
      expect(error?.message).toContain('mismatch');
    });

    it('detects keypair public key mismatch', () => {
      const loaded = createIdentity('test-id', testPublicKey, testPrivateKeyMaterial);
      // Manually change keypair public key - note: must still be valid hex
      loaded.keypair.publicKey = 'fedcba9876543210fedcba9876543210';

      const error = validateIdentity(loaded);
      expect(error).not.toBeNull();
      expect(error?.message).toContain('match');
    });

    it('validates all components together', () => {
      const loaded = createIdentity('test', testPublicKey, testPrivateKeyMaterial);
      const error = validateIdentity(loaded);
      expect(error).toBeNull();

      // All three should match
      expect(loaded.identity.publicKey).toBe(loaded.keypair.publicKey);
      expect(loaded.identity.publicKey).toBe(extractPublicKeyFromDid(loaded.identity.did));
    });
  });

  describe('serializeIdentity', () => {
    it('serializes identity for storage', () => {
      const loaded = createIdentity('test-id', testPublicKey, testPrivateKeyMaterial);
      const serialized = serializeIdentity(loaded);

      expect(serialized.identity.id).toBe('test-id');
      expect(serialized.identity.did).toBe(`did:zhtp:${testPublicKey}`);
      expect(serialized.identity.publicKey).toBe(testPublicKey);
      expect(serialized.identity.isActive).toBe(true);
      expect(serialized.identity.createdAt).toBeDefined();

      expect(serialized.privateKey.dilithiumSk).toBe('base64_dilithium_sk');
      expect(serialized.privateKey.kyberSk).toBe('base64_kyber_sk');
      expect(serialized.privateKey.masterSeed).toBe('base64_master_seed');
    });

    it('preserves all identity properties', () => {
      const loaded = createIdentity('custom-id', testPublicKey, testPrivateKeyMaterial);
      const serialized = serializeIdentity(loaded);

      expect(serialized.identity.id).toBe(loaded.identity.id);
      expect(serialized.identity.did).toBe(loaded.identity.did);
      expect(serialized.identity.publicKey).toBe(loaded.identity.publicKey);
      expect(serialized.identity.isActive).toBe(loaded.identity.isActive);
      expect(serialized.identity.createdAt).toBe(loaded.identity.createdAt);
    });

    it('preserves all private key material', () => {
      const custom = {
        dilithiumSk: 'custom_dilithium_base64',
        kyberSk: 'custom_kyber_base64',
        masterSeed: 'custom_master_seed_base64',
      };
      const loaded = createIdentity('test', testPublicKey, custom);
      const serialized = serializeIdentity(loaded);

      expect(serialized.privateKey).toEqual(custom);
    });

    it('can round-trip through serialization', () => {
      const loaded = createIdentity('id', testPublicKey, testPrivateKeyMaterial);
      const serialized = serializeIdentity(loaded);

      // Should be able to reconstruct from serialized data
      expect(serialized.identity.id).toBe(loaded.identity.id);
      expect(serialized.identity.publicKey).toBe(loaded.identity.publicKey);
      expect(serialized.privateKey.dilithiumSk).toBe(loaded.keypair.privateKey.dilithiumSk);
    });
  });
});
