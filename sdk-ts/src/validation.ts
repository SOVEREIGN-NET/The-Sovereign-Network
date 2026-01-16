/**
 * Pure validation functions following zhtp-cli patterns
 * No side effects, fully testable, return ValidationResult
 */

import { ValidationResult, ValidationIssue } from './error.js';

/**
 * Validate domain name format
 * Rules: 1-64 chars, alphanumeric + hyphens, no leading/trailing hyphen, no consecutive hyphens
 */
export function validateDomain(domain: string): ValidationResult {
  const errors: ValidationIssue[] = [];

  // Remove .zhtp suffix if present for validation
  const baseName = domain.replace(/\.zhtp$/, '');

  if (!baseName || baseName.length === 0) {
    errors.push({ field: 'domain', message: 'Domain name cannot be empty' });
  }

  if (baseName.length > 64) {
    errors.push({
      field: 'domain',
      message: 'Domain name must not exceed 64 characters',
      value: baseName.length,
    });
  }

  if (!/^[a-z0-9-]+$/i.test(baseName)) {
    errors.push({
      field: 'domain',
      message: 'Domain can only contain alphanumeric characters and hyphens',
    });
  }

  if (baseName.startsWith('-') || baseName.endsWith('-')) {
    errors.push({
      field: 'domain',
      message: 'Domain cannot start or end with a hyphen',
    });
  }

  if (baseName.includes('--')) {
    errors.push({
      field: 'domain',
      message: 'Domain cannot contain consecutive hyphens',
    });
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validate wallet address format
 * Rules: starts with 'z', 34-42 characters
 */
export function validateWalletAddress(address: string): ValidationResult {
  const errors: ValidationIssue[] = [];

  if (!address || address.length === 0) {
    errors.push({ field: 'address', message: 'Wallet address cannot be empty' });
    return { valid: false, errors };
  }

  if (!address.startsWith('z')) {
    errors.push({
      field: 'address',
      message: 'Wallet address must start with "z"',
      value: address[0],
    });
  }

  if (address.length < 34 || address.length > 42) {
    errors.push({
      field: 'address',
      message: 'Wallet address must be 34-42 characters',
      value: address.length,
    });
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validate transaction amount
 * Rules: > 0, <= max supply
 */
export function validateTransactionAmount(amount: bigint): ValidationResult {
  const errors: ValidationIssue[] = [];
  const MAX_AMOUNT = 21_000_000_00_000_000n; // 21 million with 8 decimals

  if (amount <= 0n) {
    errors.push({
      field: 'amount',
      message: 'Transaction amount must be greater than 0',
      value: amount.toString(),
    });
  }

  if (amount > MAX_AMOUNT) {
    errors.push({
      field: 'amount',
      message: `Transaction amount exceeds maximum of ${MAX_AMOUNT.toString()}`,
      value: amount.toString(),
    });
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validate wallet name
 * Rules: 3-64 chars, alphanumeric + underscore + hyphen, starts with alphanumeric
 */
export function validateWalletName(name: string): ValidationResult {
  const errors: ValidationIssue[] = [];

  if (!name || name.length === 0) {
    errors.push({ field: 'name', message: 'Wallet name cannot be empty' });
    return { valid: false, errors };
  }

  if (name.length < 3) {
    errors.push({
      field: 'name',
      message: 'Wallet name must be at least 3 characters',
      value: name.length,
    });
  }

  if (name.length > 64) {
    errors.push({
      field: 'name',
      message: 'Wallet name must not exceed 64 characters',
      value: name.length,
    });
  }

  const first = name[0];
  if (!first.match(/[a-zA-Z0-9]/)) {
    errors.push({
      field: 'name',
      message: 'Wallet name must start with alphanumeric character',
      value: first,
    });
  }

  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(name)) {
    errors.push({
      field: 'name',
      message: 'Wallet name can only contain alphanumeric, underscore, and hyphen',
    });
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validate balance is sufficient for transaction
 */
export function validateSufficientBalance(
  balance: bigint,
  amount: bigint,
  fee: bigint,
): ValidationResult {
  const errors: ValidationIssue[] = [];
  const required = amount + fee;

  if (balance < required) {
    errors.push({
      field: 'balance',
      message: `Insufficient balance: need ${required.toString()}, have ${balance.toString()}`,
      value: {
        required: required.toString(),
        available: balance.toString(),
        shortfall: (required - balance).toString(),
      },
    });
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validate DID format
 * Format: did:zhtp:{hex_key}
 */
export function validateDid(did: string): ValidationResult {
  const errors: ValidationIssue[] = [];

  if (!did || !did.startsWith('did:zhtp:')) {
    errors.push({
      field: 'did',
      message: 'DID must start with "did:zhtp:"',
      value: did,
    });
  }

  const parts = did.split(':');
  if (parts.length !== 3) {
    errors.push({
      field: 'did',
      message: 'DID must have format "did:zhtp:{hex_key}"',
      value: did,
    });
  }

  const keyPart = parts[2] || '';
  if (!/^[0-9a-f]+$/.test(keyPart)) {
    errors.push({
      field: 'did',
      message: 'DID key part must be hexadecimal',
      value: keyPart,
    });
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validate metadata is valid JSON
 */
export function validateMetadata(metadata: string | undefined): ValidationResult {
  const errors: ValidationIssue[] = [];

  if (!metadata) {
    return { valid: true, errors };
  }

  try {
    JSON.parse(metadata);
  } catch (e) {
    errors.push({
      field: 'metadata',
      message: `Invalid JSON metadata: ${e instanceof Error ? e.message : 'unknown error'}`,
      value: metadata,
    });
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Calculate minimum registration fee for domain
 * Based on domain length:
 * - 1-2 chars: 5000 ZHTP
 * - 3-4 chars: 1000 ZHTP
 * - 5+ chars: 100 ZHTP
 */
export function calculateDomainRegistrationFee(domain: string, years: number = 1): bigint {
  const baseName = domain.replace(/\.zhtp$/, '');
  const length = baseName.length;

  let basePrice: bigint;
  if (length <= 2) {
    basePrice = 5000n;
  } else if (length <= 4) {
    basePrice = 1000n;
  } else {
    basePrice = 100n;
  }

  // Convert to smallest unit (8 decimals)
  return basePrice * 100_000_000n * BigInt(years);
}

/**
 * Calculate minimum transaction fee
 * Formula: base_fee + (tx_size_bytes * per_byte_fee)
 */
export function calculateTransactionFee(transactionSize: number): bigint {
  const baseFee = 1000n;
  const perByteFee = 10n;
  return baseFee + BigInt(transactionSize) * perByteFee;
}
