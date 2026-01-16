/**
 * Cryptographic utilities for the SDK
 */

import { blake3 } from '@noble/hashes/blake3';

export function blake3Hash(data: Uint8Array): Uint8Array {
  return blake3(data);
}

export function calculateContentHash(data: Uint8Array): string {
  const hash = blake3Hash(data);
  return bytesToHex(hash);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => `0${byte.toString(16)}`.slice(-2)).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function base64Encode(data: Uint8Array | string): string {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  return globalThis.btoa(String.fromCharCode(...data));
}

export function base64Decode(encoded: string): Uint8Array {
  const string = globalThis.atob(encoded);
  const bytes = new Uint8Array(string.length);
  for (let i = 0; i < string.length; i++) {
    bytes[i] = string.charCodeAt(i);
  }
  return bytes;
}

export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Calculate domain registration fee based on domain length
 * Follows ZHTP economic model:
 * - 1-2 chars: Premium (5000+ ZHTP)
 * - 3-4 chars: High (1000-5000 ZHTP)
 * - 5+ chars: Standard (100-1000 ZHTP)
 */
export function calculateDomainFee(domain: string, years: number = 1): number {
  const baseName = domain.replace(/\.zhtp$/, '');
  const length = baseName.length;

  let basePrice: number;
  if (length <= 2) {
    basePrice = 5000;
  } else if (length <= 4) {
    basePrice = 1000;
  } else {
    basePrice = 100;
  }

  // Apply yearly multiplier (simplified model)
  return basePrice * years;
}

/**
 * Validate domain name format
 * Rules:
 * - 1-64 characters
 * - Alphanumeric and hyphens only
 * - Cannot start or end with hyphen
 * - Cannot contain consecutive hyphens
 */
export function validateDomain(domain: string): boolean {
  const baseName = domain.replace(/\.zhtp$/, '');

  // Length check
  if (baseName.length < 1 || baseName.length > 64) {
    return false;
  }

  // Character check (alphanumeric and hyphens)
  if (!/^[a-z0-9-]+$/i.test(baseName)) {
    return false;
  }

  // Cannot start or end with hyphen
  if (baseName.startsWith('-') || baseName.endsWith('-')) {
    return false;
  }

  // Cannot contain consecutive hyphens
  if (baseName.includes('--')) {
    return false;
  }

  return true;
}

/**
 * Generate a DID from a public key
 * Format: did:zhtp:{hex_encoded_public_key}
 */
export function generateDid(publicKey: string | Uint8Array): string {
  let keyHex: string;
  if (typeof publicKey === 'string') {
    keyHex = publicKey;
  } else {
    keyHex = bytesToHex(publicKey);
  }
  return `did:zhtp:${keyHex}`;
}

/**
 * Extract public key from DID
 */
export function extractPublicKeyFromDid(did: string): string {
  const match = did.match(/^did:zhtp:(.+)$/);
  if (!match) {
    throw new Error('Invalid DID format');
  }
  return match[1];
}
