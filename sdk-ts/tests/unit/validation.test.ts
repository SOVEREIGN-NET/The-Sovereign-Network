import { describe, it, expect } from 'vitest';
import {
  validateDomain,
  validateWalletAddress,
  validateTransactionAmount,
  validateWalletName,
  validateSufficientBalance,
  validateDid,
  validateMetadata,
  calculateDomainRegistrationFee,
  calculateTransactionFee,
} from '../../src/validation.js';

describe('Validation Functions', () => {
  describe('validateDomain', () => {
    it('accepts valid domains with .zhtp suffix', () => {
      expect(validateDomain('example.zhtp').valid).toBe(true);
      expect(validateDomain('my-app.zhtp').valid).toBe(true);
      expect(validateDomain('a.zhtp').valid).toBe(true);
      expect(validateDomain('verylongdomainname.zhtp').valid).toBe(true);
    });

    it('accepts valid domains without .zhtp suffix', () => {
      expect(validateDomain('example').valid).toBe(true);
      expect(validateDomain('my-app').valid).toBe(true);
      expect(validateDomain('a').valid).toBe(true);
    });

    it('rejects empty domain', () => {
      const result = validateDomain('');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('rejects domain exceeding 64 characters', () => {
      const longDomain = 'a'.repeat(65) + '.zhtp';
      const result = validateDomain(longDomain);
      expect(result.valid).toBe(false);
    });

    it('rejects domain with leading hyphen', () => {
      const result = validateDomain('-invalid.zhtp');
      expect(result.valid).toBe(false);
    });

    it('rejects domain with trailing hyphen', () => {
      const result = validateDomain('invalid-.zhtp');
      expect(result.valid).toBe(false);
    });

    it('rejects domain with consecutive hyphens', () => {
      const result = validateDomain('in--valid.zhtp');
      expect(result.valid).toBe(false);
    });

    it('rejects domain with invalid characters', () => {
      expect(validateDomain('invalid@.zhtp').valid).toBe(false);
      expect(validateDomain('invalid .zhtp').valid).toBe(false);
      expect(validateDomain('invalid_.zhtp').valid).toBe(false);
    });

    it('accepts domains with numbers', () => {
      expect(validateDomain('abc123.zhtp').valid).toBe(true);
      expect(validateDomain('123abc.zhtp').valid).toBe(true);
    });
  });

  describe('validateWalletAddress', () => {
    it('accepts valid wallet addresses', () => {
      // Must be 34-42 chars and start with 'z'
      expect(validateWalletAddress('z1234567890123456789012345678901234').valid).toBe(true);
      expect(validateWalletAddress('zabcdefghijklmnopqrstuvwxyz012345ab').valid).toBe(true);
    });

    it('rejects addresses not starting with z', () => {
      const result = validateWalletAddress('a12345678901234567890123456789012345');
      expect(result.valid).toBe(false);
    });

    it('rejects addresses that are too short', () => {
      const result = validateWalletAddress('zabc');
      expect(result.valid).toBe(false);
    });

    it('rejects addresses that are too long', () => {
      const longAddr = 'z' + 'a'.repeat(42);
      const result = validateWalletAddress(longAddr);
      expect(result.valid).toBe(false);
    });

    it('rejects empty address', () => {
      const result = validateWalletAddress('');
      expect(result.valid).toBe(false);
    });
  });

  describe('validateTransactionAmount', () => {
    it('accepts positive amounts', () => {
      expect(validateTransactionAmount(100n).valid).toBe(true);
      expect(validateTransactionAmount(1000000n).valid).toBe(true);
    });

    it('rejects zero amount', () => {
      const result = validateTransactionAmount(0n);
      expect(result.valid).toBe(false);
    });

    it('rejects negative amounts', () => {
      const result = validateTransactionAmount(-100n);
      expect(result.valid).toBe(false);
    });

    it('rejects amounts exceeding max supply', () => {
      const result = validateTransactionAmount(21000001n * 100000000n);
      expect(result.valid).toBe(false);
    });

    it('accepts amounts at max supply boundary', () => {
      expect(validateTransactionAmount(21000000n * 100000000n).valid).toBe(true);
    });
  });

  describe('validateWalletName', () => {
    it('accepts valid wallet names', () => {
      expect(validateWalletName('my-wallet').valid).toBe(true);
      expect(validateWalletName('wallet_2024').valid).toBe(true);
      expect(validateWalletName('MyWallet').valid).toBe(true);
    });

    it('rejects names that are too short', () => {
      const result = validateWalletName('ab');
      expect(result.valid).toBe(false);
    });

    it('rejects names that are too long', () => {
      const longName = 'a'.repeat(65);
      const result = validateWalletName(longName);
      expect(result.valid).toBe(false);
    });

    it('rejects names starting with special characters', () => {
      expect(validateWalletName('-wallet').valid).toBe(false);
      expect(validateWalletName('_wallet').valid).toBe(false);
    });

    it('rejects names with invalid characters', () => {
      expect(validateWalletName('wallet@home').valid).toBe(false);
      expect(validateWalletName('wallet space').valid).toBe(false);
    });
  });

  describe('validateSufficientBalance', () => {
    it('accepts when balance >= amount + fee', () => {
      const result = validateSufficientBalance(1000n, 500n, 100n);
      expect(result.valid).toBe(true);
    });

    it('rejects when balance < amount + fee', () => {
      const result = validateSufficientBalance(100n, 500n, 100n);
      expect(result.valid).toBe(false);
    });

    it('accepts exact match', () => {
      const result = validateSufficientBalance(600n, 500n, 100n);
      expect(result.valid).toBe(true);
    });

    it('handles large numbers correctly', () => {
      const result = validateSufficientBalance(
        BigInt(21000000) * BigInt(100000000),
        BigInt(10000000) * BigInt(100000000),
        BigInt(1000000),
      );
      expect(result.valid).toBe(true);
    });
  });

  describe('validateDid', () => {
    it('accepts valid DIDs', () => {
      expect(validateDid('did:zhtp:abc123').valid).toBe(true);
      expect(validateDid('did:zhtp:0123456789abcdef').valid).toBe(true);
    });

    it('rejects DIDs without zhtp method', () => {
      const result = validateDid('did:other:abc123');
      expect(result.valid).toBe(false);
    });

    it('rejects malformed DIDs', () => {
      expect(validateDid('abc123').valid).toBe(false);
      expect(validateDid('did:abc123').valid).toBe(false);
      expect(validateDid('did:zhtp:').valid).toBe(false);
    });

    it('rejects uppercase hexadecimal in DID', () => {
      expect(validateDid('did:zhtp:ABCDEF').valid).toBe(false);
      expect(validateDid('did:zhtp:0123ABCD').valid).toBe(false);
    });

    it('rejects empty DID', () => {
      const result = validateDid('');
      expect(result.valid).toBe(false);
    });
  });

  describe('validateMetadata', () => {
    it('accepts valid JSON objects', () => {
      expect(validateMetadata(JSON.stringify({ key: 'value' })).valid).toBe(true);
      expect(validateMetadata(JSON.stringify({ nested: { key: 'value' } })).valid).toBe(true);
      expect(validateMetadata(JSON.stringify({})).valid).toBe(true);
    });

    it('accepts undefined metadata', () => {
      expect(validateMetadata(undefined).valid).toBe(true);
    });

    it('accepts empty string metadata (treated as no metadata)', () => {
      // Empty strings bypass JSON.parse due to falsy check - this is intentional
      expect(validateMetadata('').valid).toBe(true);
    });

    it('rejects invalid JSON', () => {
      const result = validateMetadata('{ invalid json }');
      expect(result.valid).toBe(false);
    });
  });
});

describe('Fee Calculation', () => {
  describe('calculateDomainRegistrationFee', () => {
    it('returns fee in smallest unit (8 decimals) for 1-char domains', () => {
      // 5000 ZHTP * 100_000_000 (8 decimals) = 500_000_000_000
      expect(calculateDomainRegistrationFee('a.zhtp')).toBe(500_000_000_000n);
      expect(calculateDomainRegistrationFee('z.zhtp')).toBe(500_000_000_000n);
    });

    it('returns fee for 2-char domains', () => {
      // 5000 ZHTP * 100_000_000 = 500_000_000_000
      expect(calculateDomainRegistrationFee('ab.zhtp')).toBe(500_000_000_000n);
      expect(calculateDomainRegistrationFee('xy.zhtp')).toBe(500_000_000_000n);
    });

    it('returns fee for 3–4 and 5+ char domains', () => {
      // 3–4 char domains: 1000 ZHTP * 100_000_000 = 100_000_000_000
      expect(calculateDomainRegistrationFee('abc.zhtp')).toBe(100_000_000_000n);
      // 3–4 char domains: 1000 ZHTP * 100_000_000 = 100_000_000_000
      expect(calculateDomainRegistrationFee('abcd.zhtp')).toBe(100_000_000_000n);
      // 5+ char domains: 100 ZHTP * 100_000_000 = 10_000_000_000
      expect(calculateDomainRegistrationFee('verylongdomainname.zhtp')).toBe(10_000_000_000n);
    });

    it('respects years parameter', () => {
      const oneYear = calculateDomainRegistrationFee('a.zhtp', 1);
      const twoYears = calculateDomainRegistrationFee('a.zhtp', 2);
      expect(twoYears).toBe(oneYear * 2n);
    });
  });

  describe('calculateTransactionFee', () => {
    it('returns base fee for 0 bytes', () => {
      expect(calculateTransactionFee(0)).toBe(1000n);
    });

    it('adds per-byte fee correctly', () => {
      // base (1000) + size * per_byte (10)
      expect(calculateTransactionFee(1)).toBe(1010n);
      expect(calculateTransactionFee(100)).toBe(2000n);
      expect(calculateTransactionFee(500)).toBe(6000n);
    });

    it('handles large transactions', () => {
      expect(calculateTransactionFee(1000000)).toBe(10_001_000n);
    });
  });
});
