/**
 * Identity management - first layer of client initialization
 * Load identity from keystore, manage keypairs, generate DIDs
 */

import { IdentityError, ValidationError } from './error.js';
import { validateDid } from './validation.js';

/**
 * Loaded identity with both public and private keys
 */
export interface LoadedIdentity {
  identity: ZhtpIdentity;
  keypair: KeyPair;
}

/**
 * ZHTP Identity - public information
 */
export interface ZhtpIdentity {
  id: string; // Identity ID (unique identifier)
  did: string; // DID format: did:zhtp:{hex_public_key}
  publicKey: string; // Hex-encoded public key
  createdAt: number; // Unix timestamp
  isActive: boolean;
}

/**
 * Private key material
 */
export interface PrivateKeyMaterial {
  dilithiumSk: string; // Dilithium5 secret key (base64)
  kyberSk: string; // Kyber512 secret key (base64)
  masterSeed: string; // Master seed (base64)
}

/**
 * KeyPair - both public and private keys
 */
export interface KeyPair {
  publicKey: string; // Hex-encoded
  privateKey: PrivateKeyMaterial;
}

/**
 * Keystore file format (JSON)
 */
interface KeystoreFile {
  id: string;
  did: string;
  publicKey: string;
  createdAt: number;
  isActive: boolean;
}

interface PrivateKeyFile {
  dilithiumSk: string;
  kyberSk: string;
  masterSeed: string;
}

/**
 * Load identity from keystore
 * Mirrors zhtp-cli pattern: load_identity_from_keystore
 * Files needed:
 * - ~/.zhtp/keystore/identity.json
 * - ~/.zhtp/keystore/private_key.json
 */
export async function loadIdentityFromKeystore(
  keystorePath: string,
): Promise<LoadedIdentity> {
  try {
    // This is a placeholder - actual implementation would:
    // 1. Read identity.json from keystore_path/identity.json
    // 2. Read private_key.json from keystore_path/private_key.json
    // 3. Decrypt private keys with user password (if encrypted)
    // 4. Validate DID format
    // 5. Return LoadedIdentity

    // For now, throw to indicate not yet implemented
    throw new IdentityError('Keystore loading not yet implemented', {
      keystorePath,
    });
  } catch (e) {
    throw new IdentityError(
      `Failed to load identity from keystore: ${e instanceof Error ? e.message : 'unknown error'}`,
      { keystorePath },
    );
  }
}

/**
 * Generate a DID from public key
 * Format: did:zhtp:{hex_public_key}
 */
export function generateDid(publicKey: string): string {
  return `did:zhtp:${publicKey}`;
}

/**
 * Extract public key from DID
 */
export function extractPublicKeyFromDid(did: string): string {
  const validation = validateDid(did);
  if (!validation.valid) {
    throw new IdentityError('Invalid DID format', {
      did,
      errors: validation.errors,
    });
  }

  const parts = did.split(':');
  return parts[2];
}

/**
 * Create identity from components
 * Used when constructing identity programmatically (for testing or manual setup)
 */
export function createIdentity(
  id: string,
  publicKey: string,
  privateKey: PrivateKeyMaterial,
): LoadedIdentity {
  const did = generateDid(publicKey);

  const validation = validateDid(did);
  if (!validation.valid) {
    throw new ValidationError('Failed to create identity with invalid DID', validation.errors, {
      id,
      publicKey,
    });
  }

  return {
    identity: {
      id,
      did,
      publicKey,
      createdAt: Math.floor(Date.now() / 1000),
      isActive: true,
    },
    keypair: {
      publicKey,
      privateKey,
    },
  };
}

/**
 * Validate loaded identity
 */
export function validateIdentity(loaded: LoadedIdentity): ValidationError | null {
  const didValidation = validateDid(loaded.identity.did);
  if (!didValidation.valid) {
    return new ValidationError('Identity validation failed', didValidation.errors, {
      id: loaded.identity.id,
      did: loaded.identity.did,
    });
  }

  // Verify public key matches DID
  const didPublicKey = extractPublicKeyFromDid(loaded.identity.did);
  if (didPublicKey !== loaded.identity.publicKey) {
    return new ValidationError('Identity public key mismatch', [], {
      didPublicKey,
      identityPublicKey: loaded.identity.publicKey,
    });
  }

  // Verify keypair public key matches identity
  if (loaded.keypair.publicKey !== loaded.identity.publicKey) {
    return new ValidationError('Keypair public key does not match identity', [], {
      keypairPublicKey: loaded.keypair.publicKey,
      identityPublicKey: loaded.identity.publicKey,
    });
  }

  return null;
}

/**
 * Serialize identity for storage
 */
export function serializeIdentity(loaded: LoadedIdentity): {
  identity: KeystoreFile;
  privateKey: PrivateKeyFile;
} {
  return {
    identity: {
      id: loaded.identity.id,
      did: loaded.identity.did,
      publicKey: loaded.identity.publicKey,
      createdAt: loaded.identity.createdAt,
      isActive: loaded.identity.isActive,
    },
    privateKey: {
      dilithiumSk: loaded.keypair.privateKey.dilithiumSk,
      kyberSk: loaded.keypair.privateKey.kyberSk,
      masterSeed: loaded.keypair.privateKey.masterSeed,
    },
  };
}
