/**
 * Unit tests for crypto utilities
 */

import { describe, it, expect } from 'vitest';
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
} from '../../src/crypto/utils.js';

describe('Crypto Utils', () => {
  describe('Hash functions', () => {
    it('should hash data with blake3', () => {
      const data = stringToBytes('hello world');
      const hash = blake3Hash(data);
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32); // blake3 produces 32-byte hashes
    });

    it('should produce consistent hashes', () => {
      const data = stringToBytes('test data');
      const hash1 = blake3Hash(data);
      const hash2 = blake3Hash(data);
      expect(bytesToHex(hash1)).toEqual(bytesToHex(hash2));
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = blake3Hash(stringToBytes('data1'));
      const hash2 = blake3Hash(stringToBytes('data2'));
      expect(bytesToHex(hash1)).not.toEqual(bytesToHex(hash2));
    });

    it('should calculate content hash as hex string', () => {
      const data = stringToBytes('content');
      const hash = calculateContentHash(data);
      expect(typeof hash).toBe('string');
      expect(/^[0-9a-f]{64}$/i.test(hash)).toBe(true);
    });
  });

  describe('Encoding functions', () => {
    it('should convert bytes to hex', () => {
      const bytes = new Uint8Array([0xff, 0x00, 0xab, 0xcd]);
      const hex = bytesToHex(bytes);
      expect(hex).toBe('ff00abcd');
    });

    it('should convert hex to bytes', () => {
      const hex = 'ff00abcd';
      const bytes = hexToBytes(hex);
      expect(bytes).toEqual(new Uint8Array([0xff, 0x00, 0xab, 0xcd]));
    });

    it('should roundtrip bytes to hex and back', () => {
      const original = new Uint8Array([1, 2, 3, 255, 254, 253]);
      const hex = bytesToHex(original);
      const recovered = hexToBytes(hex);
      expect(recovered).toEqual(original);
    });

    it('should base64 encode bytes', () => {
      const data = stringToBytes('hello');
      const encoded = base64Encode(data);
      expect(encoded).toBe('aGVsbG8=');
    });

    it('should base64 encode string', () => {
      const encoded = base64Encode('hello');
      expect(encoded).toBe('aGVsbG8=');
    });

    it('should base64 decode', () => {
      const decoded = base64Decode('aGVsbG8=');
      expect(bytesToString(decoded)).toBe('hello');
    });

    it('should roundtrip base64 encode/decode', () => {
      const original = 'test data with special chars: !@#$%';
      const encoded = base64Encode(original);
      const decoded = bytesToString(base64Decode(encoded));
      expect(decoded).toBe(original);
    });

    it('should convert string to bytes', () => {
      const bytes = stringToBytes('test');
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytesToString(bytes)).toBe('test');
    });
  });

  describe('Domain fee calculation', () => {
    it('should calculate premium fee for 1-2 char domains', () => {
      const fee1 = calculateDomainFee('x.zhtp');
      const fee2 = calculateDomainFee('ab.zhtp');
      expect(fee1).toBeGreaterThanOrEqual(5000);
      expect(fee2).toBeGreaterThanOrEqual(5000);
    });

    it('should calculate high fee for 3-4 char domains', () => {
      const fee3 = calculateDomainFee('abc.zhtp');
      const fee4 = calculateDomainFee('abcd.zhtp');
      expect(fee3).toBeGreaterThanOrEqual(1000);
      expect(fee3).toBeLessThan(5000);
      expect(fee4).toBeGreaterThanOrEqual(1000);
      expect(fee4).toBeLessThan(5000);
    });

    it('should calculate standard fee for 5+ char domains', () => {
      const fee5 = calculateDomainFee('abcde.zhtp');
      const fee10 = calculateDomainFee('abcdefghij.zhtp');
      expect(fee5).toBeGreaterThanOrEqual(100);
      expect(fee5).toBeLessThan(1000);
      expect(fee10).toBeGreaterThanOrEqual(100);
      expect(fee10).toBeLessThan(1000);
    });

    it('should multiply fee by years', () => {
      const fee1 = calculateDomainFee('example.zhtp', 1);
      const fee2 = calculateDomainFee('example.zhtp', 2);
      expect(fee2).toBe(fee1 * 2);
    });
  });

  describe('Domain validation', () => {
    it('should accept valid domains', () => {
      expect(validateDomain('example.zhtp')).toBe(true);
      expect(validateDomain('my-app.zhtp')).toBe(true);
      expect(validateDomain('a.zhtp')).toBe(true);
      expect(validateDomain('test123.zhtp')).toBe(true);
    });

    it('should reject invalid domain names', () => {
      expect(validateDomain('-example.zhtp')).toBe(false); // starts with hyphen
      expect(validateDomain('example-.zhtp')).toBe(false); // ends with hyphen
      expect(validateDomain('ex--ample.zhtp')).toBe(false); // consecutive hyphens
      expect(validateDomain('ex ample.zhtp')).toBe(false); // contains space
      expect(validateDomain('ex_ample.zhtp')).toBe(false); // contains underscore
      expect(validateDomain('ex@ample.zhtp')).toBe(false); // special character
    });

    it('should reject domain names that are too long', () => {
      const longDomain = 'a'.repeat(65) + '.zhtp';
      expect(validateDomain(longDomain)).toBe(false);
    });

    it('should reject empty domain names', () => {
      expect(validateDomain('.zhtp')).toBe(false);
    });

    it('should accept domains without .zhtp suffix', () => {
      expect(validateDomain('example')).toBe(true);
      expect(validateDomain('my-app')).toBe(true);
    });
  });

  describe('DID functions', () => {
    it('should generate DID from public key', () => {
      const pubKey = 'abcd1234ef5678';
      const did = generateDid(pubKey);
      expect(did).toBe('did:zhtp:abcd1234ef5678');
    });

    it('should generate DID from bytes', () => {
      const bytes = new Uint8Array([0xab, 0xcd, 0x12, 0x34]);
      const did = generateDid(bytes);
      expect(did).toBe('did:zhtp:abcd1234');
    });

    it('should extract public key from DID', () => {
      const original = 'abcd1234ef5678';
      const did = generateDid(original);
      const extracted = extractPublicKeyFromDid(did);
      expect(extracted).toBe(original);
    });

    it('should reject invalid DIDs', () => {
      expect(() => extractPublicKeyFromDid('invalid:format')).toThrow();
      expect(() => extractPublicKeyFromDid('did:other:key')).toThrow();
    });
  });

  describe('Edge cases', () => {
    it('should handle empty byte arrays', () => {
      const empty = new Uint8Array();
      const hash = blake3Hash(empty);
      expect(hash.length).toBe(32);
    });

    it('should handle large byte arrays', () => {
      const large = new Uint8Array(1024 * 1024); // 1MB
      const hash = blake3Hash(large);
      expect(hash.length).toBe(32);
    });

    it('should handle hex with leading zeros', () => {
      const bytes = hexToBytes('0001000f');
      expect(bytes[0]).toBe(0x00);
      expect(bytes[1]).toBe(0x01);
      expect(bytes[2]).toBe(0x00);
      expect(bytes[3]).toBe(0x0f);
    });

    it('should handle UTF-8 strings', () => {
      const utf8String = '你好世界 🌍';
      const bytes = stringToBytes(utf8String);
      const recovered = bytesToString(bytes);
      expect(recovered).toBe(utf8String);
    });
  });
});
